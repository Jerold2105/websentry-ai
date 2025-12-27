import json
from datetime import datetime
from pathlib import Path

import typer
from jinja2 import Environment, FileSystemLoader, select_autoescape
from playwright.sync_api import sync_playwright

app = typer.Typer(add_completion=False)


def fetch_page_title_and_headers(url: str) -> tuple[str, dict]:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        response = page.goto(url, timeout=15000)
        title = page.title()
        headers = response.headers if response else {}
        browser.close()
        return title, headers


def run_rule_based_checks(headers: dict) -> list[dict]:
    findings = []

    if "content-security-policy" not in headers:
        findings.append(
            {
                "title": "Missing Content-Security-Policy header",
                "severity": "Medium",
                "evidence": "No Content-Security-Policy header present in response",
                "mitigation": "Add a strict Content-Security-Policy header to reduce XSS risk",
            }
        )

    if "x-frame-options" not in headers:
        findings.append(
            {
                "title": "Missing X-Frame-Options header",
                "severity": "Low",
                "evidence": "No X-Frame-Options header present in response",
                "mitigation": "Add X-Frame-Options or frame-ancestors to prevent clickjacking",
            }
        )

    if "server" in headers:
        findings.append(
            {
                "title": "Server version disclosure",
                "severity": "Low",
                "evidence": f"Server header present: {headers.get('server')}",
                "mitigation": "Disable or obfuscate server version headers",
            }
        )

    return findings


def render_html(report: dict, out_html: Path) -> None:
    env = Environment(
        loader=FileSystemLoader("templates"),
        autoescape=select_autoescape(["html", "xml"]),
    )
    tpl = env.get_template("report.html.j2")
    html = tpl.render(**report)
    out_html.write_text(html, encoding="utf-8")


@app.command()
def main(
    url: str,
    out_json: Path = typer.Option(Path("reports/report.json"), "--out-json", help="Output JSON report path"),
    out_html: Path = typer.Option(Path("reports/report.html"), "--out-html", help="Output HTML report path"),
):
    typer.echo(f"Scanning {url}\n")

    title, headers = fetch_page_title_and_headers(url)
    typer.echo(f"Page title: {title}\n")

    findings = run_rule_based_checks(headers)

    severity_counts = {
        "High": sum(1 for f in findings if f.get("severity") == "High"),
        "Medium": sum(1 for f in findings if f.get("severity") == "Medium"),
        "Low": sum(1 for f in findings if f.get("severity") == "Low"),
    }

    # Keep top-level keys for the HTML template (url/title/findings/headers_sample),
    # while also adding richer metadata for JSON/reporting.
    report = {
        "url": url,
        "title": title,
        "headers_sample": {k: headers[k] for k in sorted(headers.keys())[:25]},
        "findings": findings,
        "meta": {
            "tool": "WebSentry AI",
            "version": "0.1.0",
            "scanned_at": datetime.utcnow().isoformat() + "Z",
        },
        "summary": {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
        },
    }

    # Ensure output directories exist
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_html.parent.mkdir(parents=True, exist_ok=True)

    # Save JSON
    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    typer.echo(f"Saved JSON report: {out_json}")

    # Save HTML
    render_html(report, out_html)
    typer.echo(f"Saved HTML report: {out_html}\n")

    # Console summary
    if not findings:
        typer.echo("No obvious issues detected.")
        return

    for i, f in enumerate(findings, start=1):
        typer.echo(f"[{i}] {f['title']}")
        typer.echo(f"    Severity  : {f['severity']}")
        typer.echo(f"    Evidence  : {f['evidence']}")
        typer.echo(f"    Mitigation: {f['mitigation']}\n")


if __name__ == "__main__":
    app()
