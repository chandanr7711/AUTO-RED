"""
Nmap wrapper.

Runs nmap against a single, already-authorized target and returns
structured findings. Does NOT check scope itself - callers
(scan_runner.py) are responsible for that, keeping one enforcement point.
"""

from __future__ import annotations

import asyncio
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


class NmapNotFoundError(RuntimeError):
    pass


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str
    product: str = ""
    version: str = ""


@dataclass
class NmapResult:
    target: str
    host_status: str
    open_ports: list[PortResult] = field(default_factory=list)
    raw_xml: str = ""


def _require_nmap() -> str:
    path = shutil.which("nmap")
    if not path:
        raise NmapNotFoundError(
            "nmap is not installed or not on PATH. Install it with 'sudo apt install nmap' (present on Kali by default)."
        )
    return path


def _parse_xml(xml_text: str, target: str) -> NmapResult:
    root = ET.fromstring(xml_text)
    host = root.find("host")

    if host is None:
        return NmapResult(target=target, host_status="down", raw_xml=xml_text)

    status_el = host.find("status")
    host_status = status_el.get("state", "unknown") if status_el is not None else "unknown"

    ports: list[PortResult] = []
    ports_el = host.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            state = state_el.get("state") if state_el is not None else "unknown"
            if state != "open":
                continue

            service_el = port_el.find("service")
            service = service_el.get("name", "") if service_el is not None else ""
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""

            ports.append(
                PortResult(
                    port=int(port_el.get("portid")),
                    protocol=port_el.get("protocol", "tcp"),
                    state=state,
                    service=service,
                    product=product,
                    version=version,
                )
            )

    return NmapResult(target=target, host_status=host_status, open_ports=ports, raw_xml=xml_text)


async def run_scan(target: str, *, fast: bool = True, timeout_seconds: int = 300) -> NmapResult:
    """
    Raises NmapNotFoundError if nmap isn't installed, and
    asyncio.TimeoutError if the scan exceeds timeout_seconds.
    """
    nmap_path = _require_nmap()

    args = [nmap_path, "-sV", "--open", "-oX", "-"]
    args.append("-F" if fast else "-p-")
    args.append(target)

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

    if proc.returncode != 0:
        raise RuntimeError(f"nmap exited with code {proc.returncode}: {stderr.decode(errors='replace')}")

    return _parse_xml(stdout.decode(errors="replace"), target)
