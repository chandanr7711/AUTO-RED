from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target: str = Field(..., description="Hostname or IP address to scan")
    scan_type: str = Field(
        default="recon",
        description="recon (nmap only) | vuln (nuclei only) | full (nmap + nuclei)",
    )
    scope_confirmation: bool = Field(
        ...,
        description="Caller must explicitly set this to true, confirming they have verified authorization for this target.",
    )
    requested_by: str = Field(default="unknown", description="Who/what initiated this scan")


class ScanJobOut(BaseModel):
    id: str
    target: str
    scan_type: str
    status: str
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    results: Optional[Any] = None
    error: Optional[str] = None
    ai_summary: Optional[str] = None
    ai_status: str = "idle"
    ai_error: Optional[str] = None

    class Config:
        from_attributes = True
