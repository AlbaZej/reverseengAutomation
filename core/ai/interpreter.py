"""AI interpretation layer — uses Ollama (local LLM) to explain analysis results.

Ollama runs a local LLM server. Install at: https://ollama.com/download

After installing, pull a model:
    ollama pull llama3.1:8b      # 4.7GB, good quality
    ollama pull llama3.2:3b      # 2GB, fast
    ollama pull qwen2.5:7b       # 4.4GB, strong reasoning

Configure via environment variables:
    OLLAMA_HOST     - Ollama server URL (default: http://localhost:11434)
    OLLAMA_MODEL    - Model to use (default: llama3.1:8b)

Why local? Malware samples never leave your machine. Zero API costs.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from core.models import AnalysisReport

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1:8b")


def is_ai_available() -> bool:
    """Check if Ollama is running and reachable."""
    try:
        req = urllib.request.Request(f"{OLLAMA_HOST}/api/tags")
        with urllib.request.urlopen(req, timeout=2) as resp:
            return resp.status == 200
    except Exception:
        return False


def get_available_models() -> list[str]:
    """List models available on the local Ollama instance."""
    try:
        req = urllib.request.Request(f"{OLLAMA_HOST}/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        return [m["name"] for m in data.get("models", [])]
    except Exception:
        return []


def _call_ollama(system_prompt: str, user_prompt: str, max_tokens: int = 2048) -> str:
    """Call the local Ollama API and return the text response."""
    url = f"{OLLAMA_HOST}/api/chat"

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": user_prompt})

    body = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
        "options": {
            "num_predict": max_tokens,
            "temperature": 0.3,
        },
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        raise RuntimeError(f"Ollama API error {e.code}: {error_body}")
    except urllib.error.URLError as e:
        raise RuntimeError(
            f"Cannot reach Ollama at {OLLAMA_HOST}. "
            f"Is Ollama running? Install at https://ollama.com/download. Error: {e}"
        )

    return data.get("message", {}).get("content", "")


def explain_report(report: AnalysisReport) -> dict:
    """Generate an AI explanation of the analysis report."""
    if not is_ai_available():
        return {
            "ai_available": False,
            "summary": None,
            "function_names": {},
            "next_steps": [],
            "yara_suggestion": None,
            "message": (
                f"Ollama not running. Install from https://ollama.com/download, "
                f"then run: ollama pull {OLLAMA_MODEL}"
            ),
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
        text = _call_ollama(system, user, max_tokens=2048)
        text = _strip_markdown_fences(text)

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
        text = _call_ollama("", user, max_tokens=1024)
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
        text = _call_ollama(system, user, max_tokens=2048)
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
        text = _call_ollama("", user, max_tokens=2048)
        return {"ai_available": True, "rule": _strip_markdown_fences(text)}
    except Exception as e:
        return {"ai_available": True, "rule": None, "error": str(e)}


def _strip_markdown_fences(text: str) -> str:
    """Remove ```...``` fences from LLM output."""
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()


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
