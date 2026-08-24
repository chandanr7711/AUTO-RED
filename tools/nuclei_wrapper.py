"""
Nuclei wrapper.

Runs Nuclei against a single, already-authorized target and returns
structured vulnerability findings. Does NOT check scope itself.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import dataclass, field


class NucleiNotFoundError(RuntimeError):
    pass


@dataclass
class NucleiFinding:
    template_id: str
    name: str
    severity: str
    matched_at: str
    description: str = ""
    tags: list[str] = field(default_factory=list)
    reference: list[str] = field(default_factory=list)


@dataclass
class NucleiResult:
    target: str
    findings: list[NucleiFinding] = field(default_factory=list)

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


def _require_nuclei() -> str:
    path = shutil.which("nuclei")
    if not path:
        raise NucleiNotFoundError(
            "nuclei is not installed or not on PATH. Install it with 'sudo apt install nuclei', "
            "then run 'nuclei -update-templates' once."
        )
    return path


def _parse_jsonl(raw: str, target: str) -> NucleiResult:
    findings: list[NucleiFinding] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = obj.get("info", {})
        findings.append(
            NucleiFinding(
                template_id=obj.get("template-id", "unknown"),
                name=info.get("name", "unknown"),
                severity=info.get("severity", "unknown"),
                matched_at=obj.get("matched-at", target),
                description=info.get("description", ""),
                tags=info.get("tags", []) or [],
                reference=info.get("reference", []) or [],
            )
        )

    return NucleiResult(target=target, findings=findings)


async def run_scan(target: str, *, severity: str | None = None, timeout_seconds: int = 600) -> NucleiResult:
    """
    Raises NucleiNotFoundError if nuclei isn't installed, and
    asyncio.TimeoutError if the scan exceeds timeout_seconds.
    """
    nuclei_path = _require_nuclei()

    args = [nuclei_path, "-u", target, "-jsonl", "-silent", "-no-color"]
    if severity:
        args += ["-severity", severity]

    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise

    if proc.returncode != 0 and not stdout.strip():
        raise RuntimeError(f"nuclei exited with code {proc.returncode}: {stderr.decode(errors='replace')}")

    return _parse_jsonl(stdout.decode(errors="replace"), target)
