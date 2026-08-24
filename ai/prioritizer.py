"""
AI prioritization layer.

Takes the structured JSON output already produced by the nmap/nuclei
wrappers and asks a local LLM (via Ollama) to prioritize and summarize
it in plain language. This module's job is strictly to REASON OVER
findings that already exist - it never generates exploit code,
payloads, or attack instructions.

Uses Ollama's local HTTP API directly rather than pulling in the full
LangChain dependency stack - for a single prompt-in/text-out call,
that's simpler and has fewer moving parts to break.
"""

from __future__ import annotations

import httpx

OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "llama3.2:1b"

SYSTEM_PROMPT = """You are a security analyst assistant. You are given \
structured JSON output from automated recon (nmap) and vulnerability \
scanning (nuclei) tools that were run against a target the user is \
authorized to test.

Your job is ONLY to summarize and prioritize what was already found - \
you do not suggest specific exploit commands, payloads, or attack \
sequences. For each finding, briefly explain what it means in plain \
language and suggest a general remediation direction (e.g. "update to \
the latest version", "restrict access with a firewall rule", "disable \
the unused service").

Structure your response as:
1. A one-paragraph executive summary
2. A prioritized list (highest severity/impact first) with a short \
   explanation and general remediation guidance for each item
3. If there is nothing notable, say so plainly - do not invent findings. \
   Only reference ports, services, and findings that are explicitly \
   listed below - do not assume or add any not present in the data."""


class OllamaNotAvailableError(RuntimeError):
    pass


def _build_user_prompt(target: str, results: dict) -> str:
    nmap = results.get("nmap")
    nuclei = results.get("nuclei")

    parts = [f"Target: {target}\n"]

    if nmap:
        ports = nmap.get("open_ports", [])
        parts.append(f"--- Nmap: {len(ports)} open port(s) ---")
        for p in ports:
            svc = f"{p.get('product', '')} {p.get('version', '')}".strip()
            parts.append(f"- Port {p['port']}/{p['protocol']}: {p['service']} ({svc or 'unknown product'})")

    if nuclei:
        findings = nuclei.get("findings", [])
        parts.append(f"\n--- Nuclei: {len(findings)} finding(s) ---")
        for f in findings:
            parts.append(f"- [{f.get('severity', 'unknown').upper()}] {f.get('name')} ({f.get('template_id')})")
            if f.get("description"):
                parts.append(f"  {f['description']}")

    if not nmap and not nuclei:
        parts.append("No structured results were available for this job.")

    return "\n".join(parts)


async def prioritize_findings(
    target: str,
    results: dict,
    *,
    model: str = DEFAULT_MODEL,
    timeout_seconds: int = 120,
) -> str:
    """
    Sends the scan results to a local Ollama model and returns a
    prioritized, plain-language summary as a string.

    Raises OllamaNotAvailableError for any connection, timeout, or
    other HTTP-level failure talking to Ollama.
    """
    user_prompt = _build_user_prompt(target, results)
    full_prompt = f"{SYSTEM_PROMPT}\n\n{user_prompt}"

    payload = {"model": model, "prompt": full_prompt, "stream": False}

    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.post(OLLAMA_URL, json=payload)
    except httpx.ConnectError as e:
        raise OllamaNotAvailableError(
            "Could not connect to Ollama at http://localhost:11434. "
            "Make sure Ollama is installed and running ('ollama serve'), "
            f"and that the model is pulled ('ollama pull {model}')."
        ) from e
    except httpx.TimeoutException as e:
        raise OllamaNotAvailableError(
            f"Ollama took longer than {timeout_seconds}s to respond. This is common with "
            "larger models on CPU-only hardware - try a smaller model, or increase the timeout."
        ) from e
    except httpx.HTTPError as e:
        raise OllamaNotAvailableError(f"Unexpected error talking to Ollama: {e}") from e

    if response.status_code == 404:
        raise OllamaNotAvailableError(
            f"Ollama responded but model '{model}' isn't available. Pull it first with: ollama pull {model}"
        )

    response.raise_for_status()
    data = response.json()
    return data.get("response", "").strip()
