# WebSentry AI

WebSentry AI is an **AI-assisted web application security reviewer** (not a brute-force vulnerability scanner).
It performs **permission-based, read-only checks** and produces a **prioritized, human-readable report** with evidence and mitigation guidance.

## Why this exists

Most “security scanners” projects focus on aggressive probing or exploit attempts.
WebSentry AI is intentionally different:

- **Ethical by design**: only for apps you own or have explicit permission to test
- **Read-only checks** (MVP): focused on baseline hardening and misconfigurations
- **Recruiter-readable output**: executive summary + engineering findings
- **Honest scope**: clear limitations and coverage notes

## Features (MVP)

- **CLI**: scan a URL and print findings
- **HTML + JSON reports** saved to `reports/`
- **FastAPI Web UI**:
  - submit URL
  - view results
  - download HTML/JSON
- **API endpoint** (`/scan-json`) with optional `X-API-Key` auth
- **AI-assisted Executive Summary** (feature-flagged)
  - enabled only when `WEBSENTRY_LLM_ENABLED=true` and `OPENAI_API_KEY` is set
  - safe fallback to rule-based executive summary if LLM is unavailable

## Tech Stack

- Python
- Requests (lightweight HTTP)
- FastAPI + Uvicorn (web app + API)
- Jinja2 templates (UI + report rendering)
- Playwright (installed in Docker for future crawling phases)
- OpenAI SDK (optional, behind flag)

## Project structure

- `src/websentry/` – application code
- `templates/web/` – UI templates
- `templates/report.html.j2` – HTML report template
- `reports/` – generated outputs
- `Dockerfile.api` – deployable FastAPI container

## Local setup

### 1) Create and activate venv (PowerShell)

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -e .
