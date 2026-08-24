"""
Scope / authorization gate.

This module is the single choke point every scan request must pass
through. No scanner, wrapper, or subprocess call anywhere in the
codebase should run against a target that hasn't cleared
`is_authorized()` first.

Design intent: fail closed. If the scope file is missing, malformed,
unreadable, or the target simply isn't listed -> deny.
"""

from __future__ import annotations

import ipaddress
import fnmatch
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Optional

import yaml

SCOPE_FILE = Path(__file__).parent / "scope.yaml"


@dataclass
class ScopeDecision:
    authorized: bool
    reason: str
    owner: Optional[str] = None
    authorized_until: Optional[str] = None


def _load_scope() -> list[dict]:
    if not SCOPE_FILE.exists():
        return []
    try:
        with open(SCOPE_FILE, "r") as f:
            data = yaml.safe_load(f) or {}
        return data.get("targets", [])
    except yaml.YAMLError:
        return []


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _matches_domain(target: str, patterns: list[str]) -> bool:
    target = target.lower().strip()
    for pattern in patterns:
        if fnmatch.fnmatch(target, pattern.lower()):
            return True
    return False


def _matches_ip_range(target: str, ranges: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return False
    for cidr in ranges:
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def is_authorized(target: str) -> ScopeDecision:
    """
    Check a target (hostname or IP) against the scope file.
    Callers MUST check `.authorized` and refuse to proceed if False.
    """
    entries = _load_scope()
    if not entries:
        return ScopeDecision(
            authorized=False,
            reason="Scope file is empty, missing, or unreadable. Nothing is authorized by default.",
        )

    for entry in entries:
        domains = entry.get("domains", []) or []
        ip_ranges = entry.get("ip_ranges", []) or []

        matched = _matches_ip_range(target, ip_ranges) if _is_ip(target) else _matches_domain(target, domains)

        if not matched:
            continue

        until_str = entry.get("authorized_until")
        if until_str:
            try:
                until = datetime.strptime(until_str, "%Y-%m-%d").date()
                if date.today() > until:
                    return ScopeDecision(
                        authorized=False,
                        reason=f"Authorization for '{target}' expired on {until_str}.",
                        owner=entry.get("owner"),
                        authorized_until=until_str,
                    )
            except ValueError:
                return ScopeDecision(
                    authorized=False,
                    reason=f"Scope entry for '{target}' has an invalid authorized_until date.",
                )

        return ScopeDecision(
            authorized=True,
            reason="Target matched an active scope entry.",
            owner=entry.get("owner"),
            authorized_until=until_str,
        )

    return ScopeDecision(
        authorized=False,
        reason=f"'{target}' does not match any entry in scope.yaml. Add it there first.",
    )
