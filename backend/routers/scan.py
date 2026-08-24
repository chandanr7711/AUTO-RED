from __future__ import annotations

import json

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from backend.core.audit import record_event
from backend.core.scan_runner import execute_prioritize_job, execute_scan_job
from backend.core.scope import is_authorized
from backend.models.database import ScanJob, ScanStatus, get_db
from backend.models.schemas import ScanJobOut, ScanRequest
from reports.generator import render_html, render_pdf

router = APIRouter(prefix="/scan", tags=["scan"])


@router.post("", response_model=ScanJobOut, status_code=202)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    if not request.scope_confirmation:
        raise HTTPException(
            status_code=400,
            detail="scope_confirmation must be true. This tool will not run against a target the caller hasn't explicitly confirmed.",
        )

    decision = is_authorized(request.target)
    if not decision.authorized:
        record_event(
            db, target=request.target, action="scan_rejected_at_api",
            authorized=False, reason=decision.reason, requested_by=request.requested_by,
        )
        raise HTTPException(status_code=403, detail=decision.reason)

    job = ScanJob(target=request.target, scan_type=request.scan_type, status=ScanStatus.PENDING)
    db.add(job)
    db.commit()
    db.refresh(job)

    background_tasks.add_task(execute_scan_job, job.id, request.requested_by)

    return _to_out(job)


@router.get("/{job_id}", response_model=ScanJobOut)
def get_scan(job_id: str, db: Session = Depends(get_db)):
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found.")
    return _to_out(job)


@router.post("/{job_id}/prioritize", response_model=ScanJobOut, status_code=202)
async def prioritize_scan(job_id: str, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """
    Kicks off AI prioritization as a background task and returns
    immediately - the client is expected to poll GET /scan/{id} and
    watch the `ai_status` field (idle -> running -> completed/failed),
    the same pattern already used for the scan itself. This avoids
    holding a single HTTP request open for up to two minutes while a
    CPU-only local model generates text, which is fragile over real
    networks and especially over a browser's websocket connection to
    a UI like Streamlit.
    """
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found.")

    if not job.results_json:
        raise HTTPException(
            status_code=400,
            detail="This job has no results to prioritize yet. Poll until status is 'completed' first.",
        )

    job.ai_status = "running"
    job.ai_error = None
    db.commit()
    db.refresh(job)

    background_tasks.add_task(execute_prioritize_job, job.id)

    return _to_out(job)


@router.get("/{job_id}/report")
def get_report(job_id: str, format: str = "pdf", db: Session = Depends(get_db)):
    """
    Renders the scan job as a report. `format` is `pdf` (default) or
    `html`. Works with or without an ai_summary present - a report can
    be generated right after a scan completes, before /prioritize has
    been run, and will just omit that section.
    """
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found.")

    if not job.results_json:
        raise HTTPException(
            status_code=400,
            detail="This job has no results to report on yet. Poll until status is 'completed' first.",
        )

    try:
        if format == "html":
            return HTMLResponse(content=render_html(job))

        if format == "pdf":
            pdf_bytes = render_pdf(job)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="autored_report_{job.id}.pdf"'},
            )
    except Exception as e:  # noqa: BLE001 - report rendering (e.g. a WeasyPrint/font issue) should never crash as a raw 500
        raise HTTPException(status_code=500, detail=f"Report generation failed: {type(e).__name__}: {e}")

    raise HTTPException(status_code=400, detail="format must be 'pdf' or 'html'.")


@router.get("", response_model=list[ScanJobOut])
def list_scans(db: Session = Depends(get_db)):
    jobs = db.query(ScanJob).order_by(ScanJob.created_at.desc()).limit(50).all()
    return [_to_out(j) for j in jobs]


def _to_out(job: ScanJob) -> ScanJobOut:
    results = json.loads(job.results_json) if job.results_json else None
    return ScanJobOut(
        id=job.id,
        target=job.target,
        scan_type=job.scan_type,
        status=job.status.value if hasattr(job.status, "value") else job.status,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        results=results,
        error=job.error,
        ai_summary=job.ai_summary,
        ai_status=job.ai_status,
        ai_error=job.ai_error,
    )
