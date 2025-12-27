import os
from openai import OpenAI

def summarize_findings(findings_text: str) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")

    client = OpenAI(api_key=api_key)

    resp = client.responses.create(
        model="gpt-4.1-mini",
        input=(
            "You are a security reviewer. Summarize and prioritize the findings. "
            "Group duplicates, assign severity (High/Medium/Low), and give 1-2 mitigations each.\n\n"
            f"FINDINGS:\n{findings_text}"
        ),
    )

    return resp.output_text
