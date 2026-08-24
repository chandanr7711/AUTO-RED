"""
Scan orchestration.

Called from a FastAPI BackgroundTask so the API can return immediately
with a job id while the scan runs. Every path - success, failure, or
denial - writes an audit record and updates the job row.
"""

from __future__ import annotations

import json
import dataclasses
from datetime import datetime, timezone

from backend.core.audit import record_event
from backend.core.scope import is_authorized
from backend.models.database import ScanJob, ScanStatus, SessionLocal
from tools.nmap_wrapper import NmapNotFoundError, run_scan as run_nmap_scan
from tools.nuclei_wrapper import NucleiNotFoundError, run_scan as run_nuclei_scan

# Which tools run for each requested scan_type. "full" runs everything.
TOOLS_BY_SCAN_TYPE = {
    "recon": ["nmap"],
    "vuln": ["nuclei"],
    "full": ["nmap", "nuclei"],
}


async def execute_scan_job(job_id: str, requested_by: str = "unknown") -> None:
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if job is None:
            return

        target = job.target

        # --- Authorization gate: the one place every scan must pass through ---
        decision = is_authorized(target)
        record_event(
            db, target=target, action="scan_requested",
            authorized=decision.authorized, reason=decision.reason,
            requested_by=requested_by,
        )

        if not decision.authorized:
            job.status = ScanStatus.DENIED
            job.error = decision.reason
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
            return

        job.status = ScanStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)
        db.commit()

        tools_to_run = TOOLS_BY_SCAN_TYPE.get(job.scan_type, ["nmap"])
        results: dict[str, dict] = {}
        errors: dict[str, str] = {}

        if "nmap" in tools_to_run:
            try:
                nmap_result = await run_nmap_scan(target, fast=True)
                results["nmap"] = dataclasses.asdict(nmap_result)
                record_event(
                    db, target=target, action="nmap_completed", authorized=True,
                    reason=f"Found {len(nmap_result.open_ports)} open port(s).",
                    requested_by=requested_by,
                )
            except NmapNotFoundError as e:
                errors["nmap"] = str(e)
            except Exception as e:  # noqa: BLE001 - persist ANY failure, don't crash the worker
                errors["nmap"] = f"{type(e).__name__}: {e}"

        if "nuclei" in tools_to_run:
            try:
                nuclei_result = await run_nuclei_scan(target)
                results["nuclei"] = dataclasses.asdict(nuclei_result)
                record_event(
                    db, target=target, action="nuclei_completed", authorized=True,
                    reason=f"Found {len(nuclei_result.findings)} finding(s): {nuclei_result.severity_counts()}",
                    requested_by=requested_by,
                )
            except NucleiNotFoundError as e:
                errors["nuclei"] = str(e)
            except Exception as e:  # noqa: BLE001
                errors["nuclei"] = f"{type(e).__name__}: {e}"

        job.results_json = json.dumps(results) if results else None
        job.error = json.dumps(errors) if errors else None

        if results:
            job.status = ScanStatus.COMPLETED
        else:
            job.status = ScanStatus.FAILED
            record_event(
                db, target=target, action="scan_failed", authorized=True,
                reason=job.error, requested_by=requested_by,
            )

        job.finished_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()


async def execute_prioritize_job(job_id: str) -> None:
    """
    Runs AI prioritization as a background task, same pattern as
    execute_scan_job. This exists specifically so the API can return
    immediately (202) instead of holding a request open for up to two
    minutes while a CPU-only local model generates text - a long-held
    synchronous request is fragile over real networks (proxies, VPNs,
    or a browser tab's websocket to a UI like Streamlit can all time
    out or drop mid-wait), so the client polls for the result instead.
    """
    from ai.prioritizer import OllamaNotAvailableError, prioritize_findings

    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if job is None:
            return

        try:
            results = json.loads(job.results_json) if job.results_json else {}
            summary = await prioritize_findings(job.target, results)
            job.ai_summary = summary
            job.ai_status = "completed"
            job.ai_error = None
        except OllamaNotAvailableError as e:
            job.ai_status = "failed"
            job.ai_error = str(e)
        except Exception as e:  # noqa: BLE001 - persist ANY failure, don't crash the worker
            job.ai_status = "failed"
            job.ai_error = f"{type(e).__name__}: {e}"

        db.commit()
    finally:
        db.close()
