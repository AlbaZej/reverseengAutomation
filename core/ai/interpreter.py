"""AI interpretation layer — uses Google Gemini (free tier) to explain analysis results.

Get a free API key at: https://aistudio.google.com/apikey

Set GEMINI_API_KEY environment variable to enable.
"""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error

from core.models import AnalysisReport

GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta"


def is_ai_available() -> bool:
    """Check if the Gemini API key is configured."""
    return bool(os.environ.get("GEMINI_API_KEY"))


def _call_gemini(system_prompt: str, user_prompt: str, max_tokens: int = 2048) -> str:
    """Call the Gemini API and return the text response."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not set")

    url = f"{GEMINI_API_BASE}/models/{GEMINI_MODEL}:generateContent?key={api_key}"

    body = {
        "system_instruction": {"parts": [{"text": system_prompt}]} if system_prompt else None,
        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
        "generationConfig": {
            "maxOutputTokens": max_tokens,
            "temperature": 0.3,
        },
    }
    # Remove None values
    body = {k: v for k, v in body.items() if v is not None}

    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        raise RuntimeError(f"Gemini API error {e.code}: {error_body}")

    candidates = data.get("candidates", [])
    if not candidates:
        block_reason = data.get("promptFeedback", {}).get("blockReason", "unknown")
        raise RuntimeError(f"No response from Gemini (blocked: {block_reason})")

    parts = candidates[0].get("content", {}).get("parts", [])
    return "".join(p.get("text", "") for p in parts)


def explain_report(report: AnalysisReport) -> dict:
    """Generate an AI explanation of the analysis report."""
    if not is_ai_available():
        return {
            "ai_available": False,
            "summary": None,
            "function_names": {},
            "next_steps": [],
            "yara_suggestion": None,
            "message": "Set GEMINI_API_KEY to enable AI analysis (free at aistudio.google.com/apikey)",
        }

    context = _build_context(report)

    system = (
        "You are a senior malware analyst. Given automated analysis results, "
        "provide concise, actionable interpretation. Be direct — the user is technical. "
        "Always respond with valid JSON only, no markdown fences."
    )
    user = f"""Analysis results:

{context}

Respond with ONLY valid JSON in this exact format:
{{
    "summary": "2-3 sentence plain English explanation of what this binary does and whether it's malicious",
    "function_names": {{}},
    "next_steps": ["step 1", "step 2"],
    "yara_suggestion": "A YARA rule to detect similar samples, or null if not enough info"
}}"""

    try:
        text = _call_gemini(system, user, max_tokens=2048)
        # Strip markdown fences if present
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]
        text = text.strip()

        result = json.loads(text)
        result["ai_available"] = True
        return result
    except json.JSONDecodeError:
        return {
            "ai_available": True,
            "summary": text,
            "function_names": {},
            "next_steps": [],
            "yara_suggestion": None,
        }
    except Exception as e:
        return {
            "ai_available": True,
            "summary": None,
            "error": str(e),
            "function_names": {},
            "next_steps": [],
            "yara_suggestion": None,
        }


def explain_function(code: str, context: str = "") -> dict:
    """Ask AI to explain a decompiled function."""
    if not is_ai_available():
        return {"ai_available": False, "explanation": None}

    user = (
        f"Explain what this decompiled function does in 2-3 sentences. "
        f"Suggest a descriptive name.\n\n"
        f"Context: {context}\n\n"
        f"```c\n{code}\n```"
    )

    try:
        text = _call_gemini("", user, max_tokens=1024)
        return {"ai_available": True, "explanation": text}
    except Exception as e:
        return {"ai_available": True, "explanation": None, "error": str(e)}


def ask_about_binary(report: AnalysisReport, question: str) -> dict:
    """Answer a question about the analyzed binary."""
    if not is_ai_available():
        return {"ai_available": False, "answer": None}

    context = _build_context(report)
    system = (
        "You are a malware analyst assistant. Answer questions about the binary "
        "based on the analysis data provided. Be specific and cite evidence from the data."
    )
    user = f"Analysis data:\n{context}\n\nQuestion: {question}"

    try:
        text = _call_gemini(system, user, max_tokens=2048)
        return {"ai_available": True, "answer": text}
    except Exception as e:
        return {"ai_available": True, "answer": None, "error": str(e)}


def generate_yara_rule(report: AnalysisReport) -> dict:
    """Generate a YARA rule to detect similar samples."""
    if not is_ai_available():
        return {"ai_available": False, "rule": None}

    context = _build_context(report)
    user = (
        f"Based on this analysis, write a YARA rule that would detect "
        f"this binary and similar variants. Use unique strings, imports, "
        f"or byte patterns as indicators. Output ONLY the YARA rule, no explanation.\n\n"
        f"Analysis:\n{context}"
    )

    try:
        text = _call_gemini("", user, max_tokens=2048)
        # Strip markdown fences
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]
        return {"ai_available": True, "rule": text.strip()}
    except Exception as e:
        return {"ai_available": True, "rule": None, "error": str(e)}


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
                code_preview = f.code[:500]
                parts.append(f"  ```\n{code_preview}\n  ```")
        parts.append("")

    return "\n".join(parts)
