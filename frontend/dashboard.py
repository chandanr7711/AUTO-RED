"""
AutoRed Streamlit dashboard.

A thin UI layer over the FastAPI backend - every action here just
calls the same REST endpoints you'd hit with curl. Run the API first
(uvicorn backend.main:app), then run this with:

    streamlit run frontend/dashboard.py

Nothing in this file talks to nmap/nuclei/Ollama directly - it only
ever calls http://localhost:8000, which keeps the authorization gate
and audit logging as the single source of truth regardless of which
client is driving it.
"""

from __future__ import annotations

import time

import requests
import streamlit as st

API_BASE = "http://localhost:8000"

st.set_page_config(page_title="AutoRed Dashboard", page_icon="🛡️", layout="wide")

SEVERITY_COLORS = {
    "critical": "#7f1d1d",
    "high": "#dc2626",
    "medium": "#d97706",
    "low": "#65a30d",
    "info": "#64748b",
    "unknown": "#94a3b8",
}

STATUS_COLORS = {
    "completed": "🟢",
    "running": "🟡",
    "pending": "⚪",
    "failed": "🔴",
    "denied": "🚫",
}


def api_get(path: str):
    try:
        r = requests.get(f"{API_BASE}{path}", timeout=10)
        return r
    except requests.ConnectionError:
        st.error(f"Can't reach the AutoRed API at {API_BASE}. Is `uvicorn backend.main:app` running?")
        st.stop()


def api_post(path: str, json_body: dict | None = None, timeout: int = 15):
    try:
        r = requests.post(f"{API_BASE}{path}", json=json_body, timeout=timeout)
        return r
    except requests.ConnectionError:
        st.error(f"Can't reach the AutoRed API at {API_BASE}. Is `uvicorn backend.main:app` running?")
        st.stop()
    except requests.Timeout:
        st.error("Request timed out - this can happen with AI prioritization on a slow/CPU-only model. Try again.")
        st.stop()


def safe_error_detail(resp) -> str:
    """
    Pulls a human-readable error message out of a response, whether it's
    valid JSON (the normal case) or not (e.g. a timeout/proxy error page,
    a dropped connection, or a raw 500 with no JSON body). Never raises -
    worst case it falls back to the raw response text or a generic note.
    """
    try:
        return resp.json().get("detail", resp.text)
    except (ValueError, AttributeError):
        return resp.text.strip() or f"No response body (HTTP {resp.status_code})."


# ---------------------------------------------------------------- sidebar

st.sidebar.title("🛡️ AutoRed")
st.sidebar.caption("AI-assisted red teaming orchestrator")

st.sidebar.markdown("---")
st.sidebar.subheader("New Scan")

with st.sidebar.form("new_scan_form"):
    target = st.text_input("Target (hostname or IP)", placeholder="127.0.0.1")
    scan_type = st.selectbox("Scan type", ["recon", "vuln", "full"], index=2,
                              help="recon = nmap only, vuln = nuclei only, full = both")
    requested_by = st.text_input("Requested by", value="dashboard-user")
    confirm = st.checkbox("I confirm this target is in scope.yaml and I'm authorized to scan it")
    submitted = st.form_submit_button("Launch Scan", use_container_width=True)

    if submitted:
        if not target:
            st.sidebar.warning("Enter a target first.")
        elif not confirm:
            st.sidebar.warning("You must confirm authorization to launch a scan.")
        else:
            resp = api_post("/scan", {
                "target": target,
                "scan_type": scan_type,
                "scope_confirmation": True,
                "requested_by": requested_by or "dashboard-user",
            })
            if resp.status_code == 202:
                st.sidebar.success(f"Scan launched: {resp.json()['id'][:8]}...")
                st.session_state["selected_job"] = resp.json()["id"]
                st.rerun()
            elif resp.status_code == 403:
                st.sidebar.error(f"Blocked: {safe_error_detail(resp)}")
            else:
                st.sidebar.error(f"Error ({resp.status_code}): {safe_error_detail(resp)}")

st.sidebar.markdown("---")
if st.sidebar.button("🔄 Refresh job list", use_container_width=True):
    st.rerun()

# ---------------------------------------------------------------- main area

st.title("Scan Jobs")

resp = api_get("/scan")
jobs = resp.json() if resp.status_code == 200 else []

if not jobs:
    st.info("No scans yet. Launch one from the sidebar to get started.")
    st.stop()

job_labels = {
    j["id"]: f"{STATUS_COLORS.get(j['status'], '⚪')} {j['target']} — {j['scan_type']} — {j['id'][:8]}"
    for j in jobs
}
default_id = st.session_state.get("selected_job", jobs[0]["id"])
if default_id not in job_labels:
    default_id = jobs[0]["id"]

selected_id = st.selectbox(
    "Select a job",
    options=list(job_labels.keys()),
    format_func=lambda jid: job_labels[jid],
    index=list(job_labels.keys()).index(default_id),
)
st.session_state["selected_job"] = selected_id

job_resp = api_get(f"/scan/{selected_id}")
job = job_resp.json()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Status", f"{STATUS_COLORS.get(job['status'], '')} {job['status']}")
col2.metric("Target", job["target"])
col3.metric("Scan type", job["scan_type"])
col4.metric("Job ID", job["id"][:8] + "...")

if job["status"] in ("pending", "running"):
    st.warning("Scan is still in progress...")
    if st.button("⏳ Poll for updates"):
        st.rerun()

if job["status"] == "denied":
    st.error(f"This scan was denied: {job.get('error')}")

if job["status"] == "failed":
    st.error(f"Scan failed: {job.get('error')}")

results = job.get("results")

if results:
    st.markdown("---")

    nmap = results.get("nmap")
    if nmap:
        st.subheader(f"🔍 Recon (Nmap) — {len(nmap.get('open_ports', []))} open port(s)")
        ports = nmap.get("open_ports", [])
        if ports:
            st.dataframe(
                [{"Port": p["port"], "Protocol": p["protocol"], "Service": p["service"],
                  "Product": p.get("product", ""), "Version": p.get("version", "")} for p in ports],
                use_container_width=True, hide_index=True,
            )
        else:
            st.caption("No open ports found.")

    nuclei = results.get("nuclei")
    if nuclei:
        findings = nuclei.get("findings", [])
        st.subheader(f"🛡️ Vulnerability Findings (Nuclei) — {len(findings)} finding(s)")
        if findings:
            for f in findings:
                sev = f.get("severity", "unknown").lower()
                color = SEVERITY_COLORS.get(sev, "#94a3b8")
                st.markdown(
                    f"<span style='background:{color};color:white;padding:2px 8px;"
                    f"border-radius:4px;font-size:11px;font-weight:bold;text-transform:uppercase'>"
                    f"{sev}</span> &nbsp; **{f.get('name')}** &nbsp; `{f.get('template_id')}`",
                    unsafe_allow_html=True,
                )
                if f.get("description"):
                    st.caption(f["description"])
        else:
            st.caption("No vulnerability findings.")

    st.markdown("---")

    st.subheader("🤖 AI-Prioritized Summary")
    ai_status = job.get("ai_status", "idle")

    if ai_status == "running":
        st.info("⏳ Generating summary... this can take up to a couple minutes on CPU-only models.")
        st.caption("This page updates automatically - no need to keep clicking.")
        if st.button("🔄 Check for update"):
            st.rerun()
        # Auto-poll: wait briefly, then rerun the script to check status again.
        # This keeps each individual request short (just a fast status check)
        # instead of one long-held request, which is what caused the
        # "SessionInfo" / websocket timeout error in the old blocking version.
        time.sleep(2)
        st.rerun()

    elif ai_status == "completed" and job.get("ai_summary"):
        st.markdown(job["ai_summary"])
        if st.button("🔄 Regenerate summary"):
            p_resp = api_post(f"/scan/{selected_id}/prioritize", timeout=15)
            if p_resp.status_code == 202:
                st.rerun()
            else:
                st.error(f"Error ({p_resp.status_code}): {safe_error_detail(p_resp)}")

    elif ai_status == "failed":
        st.error(f"AI summary failed: {job.get('ai_error', 'Unknown error')}")
        if st.button("🔁 Try again"):
            p_resp = api_post(f"/scan/{selected_id}/prioritize", timeout=15)
            if p_resp.status_code == 202:
                st.rerun()
            else:
                st.error(f"Error ({p_resp.status_code}): {safe_error_detail(p_resp)}")

    else:  # idle
        st.caption("No AI summary generated yet.")
        if st.button("✨ Generate AI Summary", type="primary"):
            # This call only launches the background job and returns fast (202) -
            # it does NOT wait for the model to finish, which is the fix.
            p_resp = api_post(f"/scan/{selected_id}/prioritize", timeout=15)
            if p_resp.status_code == 202:
                st.rerun()
            elif p_resp.status_code == 503:
                st.error(f"Ollama isn't reachable: {safe_error_detail(p_resp)}")
            else:
                st.error(f"Error ({p_resp.status_code}): {safe_error_detail(p_resp)}")

    st.markdown("---")

    st.subheader("📄 Report")
    dl_col1, dl_col2 = st.columns(2)
    with dl_col1:
        pdf_resp = requests.get(f"{API_BASE}/scan/{selected_id}/report?format=pdf")
        if pdf_resp.status_code == 200:
            st.download_button(
                "⬇️ Download PDF Report", data=pdf_resp.content,
                file_name=f"autored_report_{selected_id[:8]}.pdf",
                mime="application/pdf", use_container_width=True,
            )
        else:
            st.caption(f"PDF not ready: {safe_error_detail(pdf_resp)}")
    with dl_col2:
        if st.button("👁️ Preview HTML report", use_container_width=True):
            html_resp = requests.get(f"{API_BASE}/scan/{selected_id}/report?format=html")
            st.session_state["html_preview"] = html_resp.text

    if st.session_state.get("html_preview"):
        with st.expander("HTML Report Preview", expanded=True):
            st.components.v1.html(st.session_state["html_preview"], height=800, scrolling=True)
else:
    st.info("No results yet for this job.")
