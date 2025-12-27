import os
from typing import List, Dict, Optional


def llm_enabled() -> bool:
    return (
        os.getenv("WEBSENTRY_LLM_ENABLED", "false").lower() == "true"
        and bool(os.getenv("OPENAI_API_KEY"))
    )


def rule_based_executive_summary(url: str, title: str, findings: List[Dict]) -> str:
    """
    Always returns a professional executive summary even without LLM.
    """
    high = sum(1 for f in findings if f.get("severity") == "High")
    med = sum(1 for f in findings if f.get("severity") == "Medium")
    low = sum(1 for f in findings if f.get("severity") == "Low")

    if not findings:
        return (
            f"A lightweight security review of {url} ({title}) did not identify "
            "obvious baseline security misconfigurations during limited automated checks. "
            "This does not guarantee the application is secure, and deeper authenticated "
            "testing may still be required."
        )

    if high > 0:
        posture = "elevated risk"
        priority = "address High severity issues immediately, followed by Medium and Low findings"
    elif med > 0:
        posture = "moderate risk"
        priority = "remediate Medium severity issues first, then address Low severity hardening gaps"
    else:
        posture = "low-to-moderate risk"
        priority = "resolve Low severity configuration and hardening issues"

    return (
        f"A lightweight security review of {url} ({title}) identified {len(findings)} issue(s): "
        f"{high} High, {med} Medium, and {low} Low. Overall, the application presents a {posture} "
        "security posture driven primarily by configuration and security header gaps. "
        f"It is recommended to {priority} and re-test to validate remediation."
    )


def generate_executive_summary(
    url: str,
    title: str,
    findings: List[Dict],
) -> Optional[str]:
    """
    LLM-first executive summary with safe fallback.
    Never raises exceptions and never returns blank output.
    """
    fallback = rule_based_executive_summary(url, title, findings)

    if not llm_enabled():
        return fallback

    try:
        from openai import OpenAI

        client = OpenAI()

        high = sum(1 for f in findings if f.get("severity") == "High")
        med = sum(1 for f in findings if f.get("severity") == "Medium")
        low = sum(1 for f in findings if f.get("severity") == "Low")
        top_titles = [f.get("title", "") for f in findings if f.get("title")][:8]

        user_prompt = f"""
Write ONE concise executive summary paragraph for a web application security review.

Target URL: {url}
Page title: {title}

Findings count:
High={high}, Medium={med}, Low={low}

Key issues:
{", ".join(top_titles) if top_titles else "No issues detected"}

Requirements:
- One paragraph only
- Non-technical, executive-friendly language
- State overall risk level
- Clearly state what should be prioritized first
- No bullet points
"""

        resp = client.chat.completions.create(
            model=os.getenv("WEBSENTRY_LLM_MODEL", "gpt-4o-mini"),
            messages=[
                {"role": "system", "content": "You write concise executive security summaries."},
                {"role": "user", "content": user_prompt.strip()},
            ],
            max_tokens=int(os.getenv("WEBSENTRY_LLM_MAX_TOKENS", "140")),
            temperature=float(os.getenv("WEBSENTRY_LLM_TEMPERATURE", "0.3")),
        )

        text = (resp.choices[0].message.content or "").strip()
        return text if text else fallback

    except Exception:
        return fallback
