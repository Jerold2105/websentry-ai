import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple

import requests
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape

from websentry.llm.summary import generate_executive_summary, llm_enabled
from websentry.cli import run_rule_based_checks  # reuse existing checks


app = FastAPI(title="WebSentry AI", version=os.getenv("WEBSENTRY_VERSION", "0.1.0"))

BASE_DIR = Path(__file__).resolve().parents[2]  # .../src/websentry -> .../
TEMPLATES_DIR = BASE_DIR / "templates"
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Static serving for downloaded reports
app.mount("/reports", StaticFiles(directory=str(REPORTS_DIR)), name="reports")

ui_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR / "web")),
    autoescape=select_autoescape(["html", "xml"]),
)

report_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _llm_mode_string() -> str:
    # "Mode" means what capability is configured, not necessarily what succeeded.
    if llm_enabled():
        return "AI-assisted (LLM enabled)"
    return "Rule-based (LLM disabled)"


def fetch_page_title_and_headers(url: str) -> Tuple[str, Dict[str, str]]:
    # Lightweight: use requests for headers + HTML title (no heavy crawling in MVP)
    r = requests.get(url, timeout=20, headers={"User-Agent": "WebSentryAI/0.1 (+https://example.invalid)"})
    headers = dict(r.headers)

    title = "Unknown"
    try:
        # naive title parse; good enough for MVP
        text = r.text
        lo = text.lower()
        t1 = lo.find("<title>")
        t2 = lo.find("</title>")
        if t1 != -1 and t2 != -1 and t2 > t1:
            title = text[t1 + 7 : t2].strip()
    except Exception:
        pass

    return title, headers


def _build_report(url: str) -> Dict[str, Any]:
    title, headers = fetch_page_title_and_headers(url)
    findings = run_rule_based_checks(headers)

    exec_summary = generate_executive_summary(url, title, findings)

    report = {
        "url": url,
        "title": title,
        "executive_summary": exec_summary,
        "headers_sample": dict(list(headers.items())[:20]),
        "findings": findings,
        "meta": {
            "tool": "WebSentry AI",
            "version": os.getenv("WEBSENTRY_VERSION", "0.1.0"),
            "scanned_at": _utc_iso(),
            "mode": _llm_mode_string(),
            "scope": "Unauthenticated, read-only checks (MVP)",
        },
    }
    return report


@app.get("/", response_class=HTMLResponse)
def home():
    tpl = ui_env.get_template("index.html")
    return tpl.render()


@app.post("/scan", response_class=HTMLResponse)
def scan_ui(url: str = Form(...)):
    report = _build_report(url)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out_json = REPORTS_DIR / f"report-{ts}.json"
    out_html = REPORTS_DIR / f"report-{ts}.html"

    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    out_html.write_text(report_env.get_template("report.html.j2").render(**report), encoding="utf-8")

    tpl = ui_env.get_template("result.html")
    return tpl.render(
        report=report,
        json_report_url=f"/reports/{out_json.name}",
        html_report_url=f"/reports/{out_html.name}",
    )


@app.post("/scan-json")
async def scan_json(request: Request):
    # API key auth (optional)
    required_key = os.getenv("WEBSENTRY_API_KEY")
    if required_key:
        provided = request.headers.get("X-API-Key", "")
        if provided != required_key:
            return JSONResponse({"detail": "Invalid or missing API key"}, status_code=401)

    data = await request.json()
    url = (data.get("url") or "").strip()
    if not url:
        return JSONResponse({"detail": "Missing url"}, status_code=400)

    report = _build_report(url)
    return JSONResponse(report)
