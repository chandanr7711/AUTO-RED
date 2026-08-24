# AutoRed — AI-Assisted Red Teaming Orchestrator

## Architecture

```
backend/
  main.py              # FastAPI app entrypoint
  core/
    scope.py           # Authorization gate — the ONE place every target is checked
    scope.yaml          # Allowlist of authorized targets (edit this to add targets)
    audit.py            # Immutable audit log writer
    scan_runner.py       # Background task: enforces scope -> dispatches tools -> persists results
  models/
    database.py          # SQLAlchemy models (ScanJob, AuditLog) + session
    schemas.py            # Pydantic request/response models
  routers/
    scan.py                # /scan endpoints (launch, poll, prioritize, report)
tools/
  nmap_wrapper.py           # nmap subprocess -> parsed JSON (recon)
  nuclei_wrapper.py          # nuclei subprocess -> parsed JSON (vuln scanning)
ai/
  prioritizer.py               # Sends findings to a local Ollama model, returns a prioritized summary
reports/
  generator.py                  # Renders a ScanJob into HTML/PDF via Jinja2 + WeasyPrint
  templates/report.html          # Report template
frontend/
  dashboard.py                    # Streamlit UI over the FastAPI backend
```

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

External tools needed on the system (not pip-installable):
- **nmap** — `sudo apt install nmap` (recon)
- **nuclei** — `sudo apt install nuclei && nuclei -update-templates` (vuln scanning)
- **Ollama** — `curl -fsSL https://ollama.com/install.sh | sh`, then `ollama pull llama3.2:1b`
  (or any model — update `DEFAULT_MODEL` in `ai/prioritizer.py` to match, and
  run `ollama serve` before using the AI summary feature)

> **Known dependency quirk:** `weasyprint==62.3` needs `pydyf==0.10.0`
> specifically — a newer `pydyf` changed its internal API and breaks PDF
> generation with an `AttributeError: 'super' object has no attribute
> 'transform'`. This is already pinned correctly in `requirements.txt`,
> but if you ever `pip install --upgrade` weasyprint/pydyf separately,
> keep this pin in mind.

## Run

**API (required for everything):**
```bash
uvicorn backend.main:app --reload
```
Swagger UI: http://localhost:8000/docs

**Dashboard (optional, needs the API running in a separate terminal):**
```bash
streamlit run frontend/dashboard.py
```
Opens at http://localhost:8501

## Before you scan ANYTHING

Add the target to `backend/core/scope.yaml` first. Requests against
targets not listed there are rejected with a `403` — enforced in two
places (the API route, and again inside the background job) so
there's no path around it. Only add targets you own or have explicit
written permission to test.

`127.0.0.1` / `localhost` are pre-authorized for local lab testing.

## Try it (via curl)

```bash
# Launch a scan
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1", "scan_type": "full", "scope_confirmation": true, "requested_by": "your-name"}'

# Poll status (use the id from above)
curl http://localhost:8000/scan/<job_id>

# Once status is "completed", get an AI-prioritized summary
curl -X POST http://localhost:8000/scan/<job_id>/prioritize

# Download a PDF report
curl -o report.pdf "http://localhost:8000/scan/<job_id>/report?format=pdf"

# Or preview the HTML version
curl "http://localhost:8000/scan/<job_id>/report?format=html" > report.html
```

`scan_type` is one of: `recon` (nmap only), `vuln` (nuclei only), `full` (both).

## Or just use the dashboard

The Streamlit UI does all of the above through buttons: launch a scan
from the sidebar, watch its status, view findings tables with
severity-colored badges, generate the AI summary, and download the
PDF — no curl required.

## Design principles this project follows

- **Fail closed**: no scope file entry = no scan, full stop.
- **Audit everything**: denials are logged just as thoroughly as
  successes — often the more interesting record.
- **One enforcement point**: tool wrappers (`tools/*.py`) never check
  scope themselves; only `scan_runner.py` does, so there's exactly
  one place to audit for correctness.
- **AI reasons over findings, never generates attacks**: the
  prioritization layer explicitly summarizes and ranks what scanners
  already found — it is prompted not to suggest exploit commands or
  payloads, keeping it in "analyst" territory rather than "offensive
  tooling" territory.
- **Every endpoint returns clean JSON on failure, never a raw error
  page.** AI calls, report rendering, and scan dispatch all have
  broad exception handling so a client (curl, the dashboard, anything
  else) never has to guess what went wrong.
- **Small local models will occasionally hallucinate details not in
  the input.** The prompt in `ai/prioritizer.py` explicitly instructs
  the model to only reference findings that are present, but a 1B
  parameter model on CPU is not perfectly reliable — worth mentioning
  as a known tradeoff if demoing this, and worth upgrading to a
  larger model (`llama3.1`, `llama3.2:3b`, etc.) if accuracy matters
  more than speed for your use case.

## Status: all planned phases complete

1. ✅ Authorization gate + audit logging
2. ✅ Async job system
3. ✅ Nmap recon
4. ✅ Nuclei vulnerability scanning
5. ✅ AI prioritization layer (Ollama)
6. ✅ PDF/HTML report generation
7. ✅ Streamlit dashboard

## Possible next steps, if you want to keep going

- **Celery + Redis** instead of FastAPI `BackgroundTasks`, so scans
  survive an API restart and can run concurrently at real scale.
- **Alembic** for database migrations, instead of deleting
  `autored.db` every time a model changes.
- **Historical trend view** in the dashboard — findings over time for
  a given target across multiple scans.
- **More tool wrappers** (ffuf for directory brute-forcing, sqlmap for
  targeted SQLi testing) following the same wrapper pattern as
  nmap/nuclei.

## Troubleshooting notes from real-world testing

- **`unzip` creating a nested `AutoRed/AutoRed/` folder**: happens if
  you extract while already inside a folder named `AutoRed`. Always
  extract from your home directory or wherever the *parent* folder
  should live.
- **`ModuleNotFoundError` for anything under `backend.core`**: almost
  always means you're running `uvicorn` from the wrong working
  directory. Run it from the project root (where `requirements.txt`
  lives), not from inside `backend/`.
- **`sqlite3.OperationalError: table scan_jobs has no column named X`**:
  the SQLite file was created before a model change added a new
  column. SQLAlchemy's `init_db()` only creates missing tables, it
  doesn't migrate existing ones. Fix: `rm autored.db` and restart
  (you'll lose scan history, which is fine in dev).
- **`pip install` failing with DNS/connection errors**: check
  `ping -c 3 8.8.8.8` vs `ping -c 3 google.com` to isolate whether
  it's a DNS problem specifically; `echo "nameserver 8.8.8.8" | sudo
  tee /etc/resolv.conf` is a quick fix on many VMs.
- **Ollama `segmentation fault` or `llama-server binary not found`**:
  the install is corrupted, not fixable from the app side. Fully
  remove (`sudo rm -rf /usr/local/lib/ollama /usr/local/bin/ollama
  ~/.ollama`) and reinstall from scratch.
=======

