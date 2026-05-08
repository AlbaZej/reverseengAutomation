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
    """Generate an AI explanation of the analysis report.

    If Ollama is unreachable, falls back to a deterministic rule-based
    summary so the UI never shows an empty AI panel during a demo.
    """
    if not is_ai_available():
        # Deterministic fallback — generate a plausible summary from the findings.
        # Marks the response with `source: 'fallback'` so the UI can label it.
        return _fallback_explanation(report)

    context = _build_context(report)

    system = (
        "You are a senior malware analyst. Given automated analysis results, "
        "provide concise, evidence-based interpretation. CRITICAL RULES:\n"
        "- Only describe behaviors that are SUPPORTED by the evidence below\n"
        "- DO NOT invent findings that aren't in the data\n"
        "- If the verdict is 'clean' and there are few/no high-severity findings, "
        "say the binary appears benign\n"
        "- Common Windows APIs (CreateFile, RegSetValueEx, IsDebuggerPresent) "
        "are used by ALL apps — don't call this 'malicious' just because they're present\n"
        "- The verdict and confidence in the data is authoritative; align your summary with it\n"
        "- Respond with valid JSON only, no markdown fences."
    )
    user = f"""Analysis results (this is ground truth — base your summary ONLY on this data):

{context}

Respond with ONLY valid JSON:
{{
    "summary": "2-3 sentence summary that ALIGNS with the verdict above. If verdict is 'clean', say it appears benign and explain why. If 'malicious'/'suspicious', explain what specific findings indicate that.",
    "function_names": {{}},
    "next_steps": ["specific actionable steps based on the actual findings"],
    "yara_suggestion": "A YARA rule based on UNIQUE strings/patterns from the data, or null if the binary appears benign"
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


def _fallback_explanation(report: AnalysisReport) -> dict:
    """Generate a rule-based summary when Ollama is unavailable.

    This produces a plausible-looking, accurate summary by stringing together
    the deterministic findings with templated language. It does not invent
    details; everything in the summary is grounded in actual data.
    """
    fi = report.file_info
    findings = report.findings
    yara_matches = report.yara_matches
    iocs = report.iocs

    high_findings = [f for f in findings if f.severity.value in ("high", "critical")]
    high_titles = [f.title.split("] ")[-1] if "] " in f.title else f.title for f in high_findings]

    # Build a verdict-aligned summary
    if report.verdict == "malicious":
        summary_parts = [
            f"This {fi.file_type.value.upper()} file ({fi.size:,} bytes) is classified as MALICIOUS "
            f"with {report.verdict_confidence:.0%} confidence based on {len(findings)} static-analysis findings."
        ]
        if yara_matches:
            rule_names = list({m.rule_name for m in yara_matches})
            summary_parts.append(
                f"YARA rule matches ({', '.join(rule_names[:4])}) indicate "
                f"behavioral patterns consistent with known malware techniques."
            )
        if high_findings:
            summary_parts.append(
                f"High-severity indicators include: {'; '.join(high_titles[:4])}."
            )
        if fi.is_packed:
            summary_parts.append(
                f"The binary appears packed{' with ' + fi.packer_name if fi.packer_name else ''}, "
                f"suggesting payload obfuscation."
            )
        if iocs:
            ioc_types = sorted({i.type for i in iocs})
            summary_parts.append(
                f"{len(iocs)} indicators of compromise extracted ({', '.join(ioc_types)})."
            )
    elif report.verdict == "suspicious":
        summary_parts = [
            f"This {fi.file_type.value.upper()} file shows SUSPICIOUS characteristics "
            f"({report.verdict_confidence:.0%} confidence). It is not definitively malicious "
            f"but exhibits behaviors that warrant further investigation."
        ]
        if high_findings:
            summary_parts.append(f"Notable findings: {'; '.join(high_titles[:3])}.")
    else:
        summary_parts = [
            f"This {fi.file_type.value.upper()} file appears benign ("
            f"{report.verdict_confidence:.0%} clean confidence). "
            f"While {len(findings)} findings were generated, none reach the threshold for "
            f"a malicious verdict."
        ]
        if findings:
            summary_parts.append(
                "These findings document API usage and structural characteristics typical of "
                "ordinary Windows software."
            )

    summary = " ".join(summary_parts)

    next_steps = []
    if report.verdict == "malicious":
        next_steps.append("Submit the SHA256 to VirusTotal to identify family attribution")
        if fi.is_packed:
            next_steps.append("Unpack with the appropriate tool (UPX, manual unpacker, or dynamic analysis)")
        if iocs:
            next_steps.append("Block the extracted IOCs at network and host level")
        next_steps.append("Pivot on shared infrastructure (C2 domains, certificates) to find related samples")
    elif report.verdict == "suspicious":
        next_steps.append("Run dynamic analysis in a sandbox to observe runtime behavior")
        next_steps.append("Check VirusTotal for prior detections")
    else:
        next_steps.append("No further action required based on static analysis alone")

    # Generate a basic YARA suggestion from interesting strings
    yara_rule = None
    interesting_strings = [s.value for s in report.strings if s.is_interesting][:5]
    if interesting_strings and report.verdict in ("suspicious", "malicious"):
        rule_strings = "\n".join(
            f'        $s{i} = "{s[:60]}" ascii'
            for i, s in enumerate(interesting_strings)
        )
        yara_rule = f"""rule deshifro_auto_{fi.sha256[:8]} {{
    meta:
        description = "Auto-generated rule from Deshifro analysis"
        sha256 = "{fi.sha256}"
    strings:
{rule_strings}
    condition:
        2 of them
}}"""

    return {
        "ai_available": False,
        "source": "fallback",
        "summary": summary,
        "function_names": {},
        "next_steps": next_steps,
        "yara_suggestion": yara_rule,
        "message": (
            "Ollama is not running — this summary was generated from the deterministic "
            "findings (no AI required). For richer analysis, start Ollama: "
            f"`ollama pull {OLLAMA_MODEL}` then refresh."
        ),
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
        return _fallback_answer(report, question)

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


def _fallback_answer(report: AnalysisReport, question: str) -> dict:
    """Rule-based answer for common demo questions when Ollama is down."""
    q = question.lower().strip()
    fi = report.file_info
    findings = report.findings
    iocs = report.iocs

    def has_finding(keyword: str) -> bool:
        kw = keyword.lower()
        return any(kw in f.title.lower() or kw in f.description.lower() for f in findings)

    def find_findings(keyword: str) -> list:
        kw = keyword.lower()
        return [f for f in findings if kw in f.title.lower() or kw in f.description.lower()]

    answer = None

    if any(k in q for k in ("packed", "packer", "encrypted", "obfuscated")):
        if fi.is_packed:
            packer = fi.packer_name or "unknown"
            answer = f"Yes, this binary appears packed (detected: {packer})."
        else:
            entropy_findings = find_findings("entropy")
            if entropy_findings:
                answer = f"Possibly. {entropy_findings[0].description}"
            else:
                answer = "No strong indicators of packing detected. Entropy distribution looks normal for a regular Windows executable."

    elif any(k in q for k in ("inject", "process injection", "remote thread")):
        inj = find_findings("injection")
        if inj:
            answer = (
                f"Yes — {len(inj)} finding(s) related to process injection: "
                f"{'; '.join(f.title for f in inj[:3])}. "
                f"This is consistent with MITRE T1055 (Process Injection)."
            )
        else:
            answer = "No process-injection indicators found in the static analysis."

    elif any(k in q for k in ("anti-debug", "anti debug", "debugger", "evade")):
        ad = find_findings("anti-debug") + find_findings("anti_debug") + find_findings("debugger")
        if ad:
            answer = (
                f"Yes — {len(ad)} finding(s) related to anti-debug techniques: "
                f"{'; '.join(f.title for f in ad[:3])}. "
                f"This suggests the malware is trying to evade dynamic analysis."
            )
        else:
            answer = "No clear anti-debug techniques detected."

    elif any(k in q for k in ("c2", "command and control", "network", "connect")):
        net_iocs = [i for i in iocs if i.type in ("url", "ip", "domain")]
        net_findings = find_findings("network")
        parts = []
        if net_findings:
            parts.append(f"Found {len(net_findings)} network-related finding(s).")
        if net_iocs:
            sample = ", ".join(i.value for i in net_iocs[:5])
            parts.append(f"Network IOCs ({len(net_iocs)} total) include: {sample}.")
        answer = " ".join(parts) if parts else "No clear C2 or network communication indicators found."

    elif any(k in q for k in ("persistence", "autostart", "startup", "registry run")):
        p = find_findings("persistence") + find_findings("registry")
        if p:
            answer = (
                f"Found {len(p)} finding(s) related to persistence: "
                f"{'; '.join(f.title for f in p[:3])}."
            )
        else:
            answer = "No clear persistence mechanisms detected via static analysis."

    elif any(k in q for k in ("crypto", "encrypt", "cipher", "hash")):
        c = find_findings("crypto")
        if c:
            answer = f"Found {len(c)} crypto-related indicator(s): {c[0].description}"
        else:
            answer = "No cryptographic API usage detected."

    elif any(k in q for k in ("verdict", "malicious", "safe", "clean")):
        answer = (
            f"Verdict: {report.verdict.upper()} ({report.verdict_confidence:.0%} confidence). "
            f"Based on {len(findings)} findings and {len(iocs)} IOCs."
        )

    elif any(k in q for k in ("ioc", "indicator", "url", "ip address", "domain")):
        if iocs:
            by_type = {}
            for i in iocs:
                by_type.setdefault(i.type, []).append(i.value)
            parts = [f"{len(v)} {k}(s)" for k, v in by_type.items()]
            answer = f"{len(iocs)} IOCs extracted: {', '.join(parts)}. First few: " + \
                     ", ".join(i.value for i in iocs[:5])
        else:
            answer = "No IOCs extracted from this sample."

    if answer is None:
        answer = (
            f"I can't answer that without Ollama running. The deterministic analysis "
            f"shows: verdict={report.verdict.upper()} ({report.verdict_confidence:.0%}), "
            f"{len(findings)} findings, {len(iocs)} IOCs. "
            f"Try one of the suggested questions for a better answer."
        )

    return {
        "ai_available": False,
        "source": "fallback",
        "answer": answer,
        "message": "Answer generated from deterministic findings (Ollama is not running).",
    }


def generate_yara_rule(report: AnalysisReport) -> dict:
    """Generate a YARA rule to detect similar samples."""
    if not is_ai_available():
        # Reuse the explain fallback's YARA generator
        fb = _fallback_explanation(report)
        return {
            "ai_available": False,
            "source": "fallback",
            "rule": fb.get("yara_suggestion") or "// No suitable patterns found for auto-rule generation",
        }

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
