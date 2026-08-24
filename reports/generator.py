"""
Report generation.

Turns a completed ScanJob's stored data (nmap/nuclei results + AI
summary, if present) into a polished HTML or PDF report. Pure
presentation layer - it doesn't touch scope, scanning, or the AI
layer directly; it just reads what's already on the ScanJob row.
"""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

TEMPLATE_DIR = Path(__file__).parent / "templates"
OUTPUT_DIR = Path(__file__).parent / "generated"

_env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))


def render_html(job) -> str:
    """
    Renders the report template for a given ScanJob ORM object (or any
    object with the same attributes: id, target, scan_type, status,
    started_at, finished_at, results_json, ai_summary).
    Returns the rendered HTML as a string.
    """
    results = json.loads(job.results_json) if getattr(job, "results_json", None) else {}
    nmap = results.get("nmap")
    nuclei = results.get("nuclei")

    template = _env.get_template("report.html")

    # job.status may be a ScanStatus enum (when passed the raw ORM object)
    # or already a plain string. Normalize so the template never shows
    # "ScanStatus.COMPLETED" instead of "completed".
    status_value = getattr(job.status, "value", job.status)

    return template.render(
        job=job,
        status=status_value,
        nmap=nmap,
        nuclei=nuclei,
        open_port_count=len(nmap.get("open_ports", [])) if nmap else 0,
        finding_count=len(nuclei.get("findings", [])) if nuclei else 0,
    )


def render_pdf(job) -> bytes:
    """Renders the report as a PDF and returns the raw PDF bytes."""
    html_str = render_html(job)
    return HTML(string=html_str).write_pdf()


def save_pdf(job, filename: str | None = None) -> Path:
    """
    Renders and saves a PDF to reports/generated/, returning the path.
    Useful for CLI/manual use; the API endpoint streams bytes directly
    instead of writing to disk.
    """
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    filename = filename or f"autored_report_{job.id}.pdf"
    out_path = OUTPUT_DIR / filename
    out_path.write_bytes(render_pdf(job))
    return out_path
