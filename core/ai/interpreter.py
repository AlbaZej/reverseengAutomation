"""AI interpretation layer — uses Claude API to explain analysis results.

This module is designed to work when an API key is available and gracefully
degrade when it's not. All functions return a result dict that includes
an "ai_available" flag.

Set ANTHROPIC_API_KEY environment variable to enable.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from core.models import AnalysisReport


def is_ai_available() -> bool:
    """Check if the AI API key is configured."""
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def explain_report(report: AnalysisReport) -> dict:
    """Generate an AI explanation of the analysis report.

    Returns a dict with:
        - ai_available: bool
        - summary: str (plain English explanation)
        - function_names: dict (address -> suggested name)
        - next_steps: list[str]
        - yara_suggestion: str (suggested YARA rule)
    """
    if not is_ai_available():
        return {
            "ai_available": False,
            "summary": None,
            "function_names": {},
            "next_steps": [],
            "yara_suggestion": None,
            "message": "Set ANTHROPIC_API_KEY to enable AI analysis",
        }

    from anthropic import Anthropic

    client = Anthropic()

    # Build context from the report
    context = _build_context(report)

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        system=(
            "You are a senior malware analyst. Given the automated analysis results below, "
            "provide a concise, actionable interpretation. Be direct — the user is technical."
        ),
        messages=[
            {
                "role": "user",
                "content": f"""Here are the automated analysis results for a binary:

{context}

Respond in this exact JSON format:
{{
    "summary": "2-3 sentence plain English explanation of what this binary does and whether it's malicious",
    "function_names": {{"0xADDR": "suggested_name", ...}},
    "next_steps": ["step 1", "step 2", ...],
    "yara_suggestion": "A YARA rule to detect similar samples (or null if not enough info)"
}}"""
            }
        ],
    )

    try:
        # Extract JSON from response
        text = response.content[0].text
        # Find JSON in the response
        start = text.index("{")
        end = text.rindex("}") + 1
        result = json.loads(text[start:end])
        result["ai_available"] = True
        return result
    except (json.JSONDecodeError, ValueError):
        return {
            "ai_available": True,
            "summary": response.content[0].text,
            "function_names": {},
            "next_steps": [],
            "yara_suggestion": None,
        }


def explain_function(code: str, context: str = "") -> dict:
    """Ask AI to explain a decompiled function."""
    if not is_ai_available():
        return {"ai_available": False, "explanation": None}

    from anthropic import Anthropic

    client = Anthropic()

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[
            {
                "role": "user",
                "content": (
                    f"Explain what this decompiled function does in 2-3 sentences. "
                    f"Suggest a descriptive name.\n\n"
                    f"Context: {context}\n\n"
                    f"```c\n{code}\n```"
                ),
            }
        ],
    )

    return {
        "ai_available": True,
        "explanation": response.content[0].text,
    }


def ask_about_binary(report: AnalysisReport, question: str) -> dict:
    """Answer a question about the analyzed binary."""
    if not is_ai_available():
        return {"ai_available": False, "answer": None}

    from anthropic import Anthropic

    client = Anthropic()
    context = _build_context(report)

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2048,
        system=(
            "You are a malware analyst assistant. Answer questions about the binary "
            "based on the analysis data provided. Be specific and cite evidence from the data."
        ),
        messages=[
            {
                "role": "user",
                "content": f"Analysis data:\n{context}\n\nQuestion: {question}",
            }
        ],
    )

    return {
        "ai_available": True,
        "answer": response.content[0].text,
    }


def generate_yara_rule(report: AnalysisReport) -> dict:
    """Generate a YARA rule to detect similar samples."""
    if not is_ai_available():
        return {"ai_available": False, "rule": None}

    from anthropic import Anthropic

    client = Anthropic()
    context = _build_context(report)

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2048,
        messages=[
            {
                "role": "user",
                "content": (
                    f"Based on this analysis, write a YARA rule that would detect "
                    f"this binary and similar variants. Use unique strings, imports, "
                    f"or byte patterns as indicators. Output only the YARA rule.\n\n"
                    f"Analysis:\n{context}"
                ),
            }
        ],
    )

    return {
        "ai_available": True,
        "rule": response.content[0].text,
    }


def _build_context(report: AnalysisReport) -> str:
    """Build a text context from the report for the AI."""
    fi = report.file_info
    parts = [
        f"File: {fi.path.name}",
        f"Type: {fi.file_type.value} ({fi.architecture.value})",
        f"Size: {fi.size} bytes",
        f"SHA256: {fi.sha256}",
        f"Packed: {fi.is_packed} ({fi.packer_name or 'N/A'})",
        f"Verdict: {report.verdict} ({report.verdict_confidence:.0%})",
        "",
    ]

    if report.findings:
        parts.append("FINDINGS:")
        for f in report.findings[:20]:
            parts.append(f"  [{f.severity.value}] {f.title}: {f.description}")
        parts.append("")

    if report.iocs:
        parts.append("IOCs:")
        for ioc in report.iocs[:20]:
            parts.append(f"  [{ioc.type}] {ioc.value}")
        parts.append("")

    if report.yara_matches:
        parts.append("YARA MATCHES:")
        for m in report.yara_matches:
            parts.append(f"  {m.rule_name}: {m.meta.get('description', '')}")
        parts.append("")

    interesting_strings = [s for s in report.strings if s.is_interesting][:30]
    if interesting_strings:
        parts.append("INTERESTING STRINGS:")
        for s in interesting_strings:
            parts.append(f"  [{s.category}] {s.value}")
        parts.append("")

    if report.imports:
        suspicious = [i for i in report.imports if i.is_suspicious]
        if suspicious:
            parts.append("SUSPICIOUS IMPORTS:")
            for i in suspicious[:20]:
                parts.append(f"  {i.library}:{i.name} ({i.category})")
            parts.append("")

    interesting_funcs = [f for f in report.functions if f.is_interesting][:5]
    if interesting_funcs:
        parts.append("INTERESTING FUNCTIONS:")
        for f in interesting_funcs:
            parts.append(f"  {f.name} @ 0x{f.address:x} ({', '.join(f.tags)})")
            if f.code:
                # Truncate to keep context manageable
                code_preview = f.code[:500]
                parts.append(f"  ```\n{code_preview}\n  ```")
        parts.append("")

    return "\n".join(parts)
