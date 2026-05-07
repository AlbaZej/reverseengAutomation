"""Heuristics for classifying findings and computing verdicts.

Design principles:
- Single API category usage = INFO/LOW (every legit Windows app uses these)
- Combinations of categories = MEDIUM
- Strong indicators (injection, packed+suspicious, multiple shellcode patterns) = HIGH
- YARA matches and known malware signatures dominate the verdict
- Be conservative: false positives erode user trust faster than missed detections
"""

from __future__ import annotations

from core.models import (
    AnalysisReport,
    EntropyRegion,
    Finding,
    IOC,
    SignalType,
    ExtractedString,
    YaraMatch,
)
from core.knowledge.signatures import API_TO_CATEGORY, CATEGORY_TO_MITRE

# Categories where mere presence is too common to flag highly
# Every legitimate Windows app uses these. Only flag combinations.
COMMON_API_CATEGORIES = {"file", "registry", "process", "evasion", "anti_debug"}

# These are stronger indicators — even individual usage is concerning
STRONG_API_CATEGORIES = {"injection", "persistence", "crypto", "network"}


def extract_iocs_from_strings(strings: list[ExtractedString]) -> list[IOC]:
    """Extract IOCs from classified strings."""
    iocs = []
    for s in strings:
        if s.category == "url":
            # Filter out documentation URLs / Microsoft-signed URLs
            lower = s.value.lower()
            if not any(d in lower for d in (
                "schemas.microsoft.com", "go.microsoft.com",
                "schemas.openxmlformats.org", "www.w3.org",
            )):
                iocs.append(IOC(type="url", value=s.value, context=f"string at offset {s.offset}"))
        elif s.category == "ip":
            if not s.value.startswith(("0.0.", "127.0.", "255.255.", "169.254.", "10.0.0.0")):
                iocs.append(IOC(type="ip", value=s.value, context=f"string at offset {s.offset}"))
        elif s.category == "email":
            iocs.append(IOC(type="email", value=s.value, context=f"string at offset {s.offset}"))
        elif s.category == "registry":
            iocs.append(IOC(type="registry", value=s.value, context=f"string at offset {s.offset}"))
    return iocs


def generate_findings_from_imports(report: AnalysisReport) -> list[Finding]:
    """Generate findings from import analysis. Conservative — single categories rarely escalate."""
    findings = []
    categories_seen: dict[str, list[str]] = {}

    for imp in report.imports:
        if imp.name in API_TO_CATEGORY:
            cat = API_TO_CATEGORY[imp.name]
            if cat not in categories_seen:
                categories_seen[cat] = []
            categories_seen[cat].append(imp.name)

    # Determine severity based on combinations
    has_injection = "injection" in categories_seen
    has_anti_debug = "anti_debug" in categories_seen
    has_network = "network" in categories_seen
    has_crypto = "crypto" in categories_seen

    # Combination heuristic: certain pairs are highly suggestive
    dangerous_combo = (
        has_injection and has_anti_debug
    ) or (
        has_injection and has_network
    ) or (
        has_anti_debug and has_crypto and has_network
    )

    for cat, apis in categories_seen.items():
        # Default severities — much more conservative than before
        if cat == "injection":
            # Process injection APIs together strongly suggest malware
            if len(apis) >= 2:
                sev = SignalType.HIGH
            else:
                sev = SignalType.MEDIUM
        elif cat in ("anti_debug",):
            # Single anti-debug API (e.g. just IsDebuggerPresent) is very common
            # Only escalate if multiple anti-debug APIs are used together
            sev = SignalType.MEDIUM if len(apis) >= 3 else SignalType.LOW
        elif cat == "persistence":
            # Persistence APIs alone are common (apps save settings)
            # The persistence keys themselves are stronger signals (caught in IOC extraction)
            sev = SignalType.LOW
        elif cat == "network":
            # Network APIs are common for legit software too
            sev = SignalType.LOW
        elif cat == "crypto":
            # Crypto APIs are used by browsers, installers, etc.
            sev = SignalType.LOW
        elif cat in ("process", "registry", "file", "evasion"):
            # Ubiquitous in normal Windows software — informational only
            sev = SignalType.INFO
        else:
            sev = SignalType.LOW

        mitre = CATEGORY_TO_MITRE.get(cat, [])
        findings.append(Finding(
            title=f"{cat.replace('_', '-').title()} API usage",
            description=(
                f"Binary imports {len(apis)} {cat}-related API{'s' if len(apis) > 1 else ''}: "
                f"{', '.join(apis[:5])}{'...' if len(apis) > 5 else ''}"
            ),
            severity=sev,
            source_tool="import_analysis",
            evidence=", ".join(apis),
            mitre_ids=mitre,
        ))

    # Add a combination finding if dangerous patterns coexist
    if dangerous_combo:
        combo_desc = []
        if has_injection: combo_desc.append("process injection")
        if has_anti_debug: combo_desc.append("anti-debug")
        if has_network: combo_desc.append("network")
        if has_crypto: combo_desc.append("crypto")
        findings.append(Finding(
            title="Dangerous API combination",
            description=(
                f"Binary uses APIs across multiple high-risk categories simultaneously: "
                f"{', '.join(combo_desc)}. This combination is rare in legitimate software."
            ),
            severity=SignalType.HIGH,
            source_tool="import_analysis",
            mitre_ids=["T1055"],
        ))

    return findings


def generate_findings_from_yara(matches: list[YaraMatch]) -> list[Finding]:
    """Generate findings from YARA matches. YARA is high-signal so trust the rule severity."""
    findings = []
    for match in matches:
        severity_str = match.meta.get("severity", "medium")
        severity_map = {
            "info": SignalType.INFO,
            "low": SignalType.LOW,
            "medium": SignalType.MEDIUM,
            "high": SignalType.HIGH,
            "critical": SignalType.CRITICAL,
        }
        mitre = match.meta.get("mitre", "")
        findings.append(Finding(
            title=f"YARA: {match.rule_name}",
            description=match.meta.get("description", match.rule_name),
            severity=severity_map.get(severity_str, SignalType.MEDIUM),
            source_tool="yara",
            evidence=f"Matched {len(match.strings_matched)} string(s)",
            mitre_ids=[mitre] if mitre else [],
        ))
    return findings


def generate_findings_from_entropy(regions: list[EntropyRegion], file_size: int) -> list[Finding]:
    """Generate findings based on entropy analysis."""
    findings = []
    packed_size = sum(r.size for r in regions if r.label in ("packed", "encrypted"))
    packed_pct = packed_size / file_size * 100 if file_size else 0

    if packed_pct > 70:
        findings.append(Finding(
            title="Binary appears heavily packed or encrypted",
            description=f"{packed_pct:.0f}% of the binary has high entropy (>7.0), suggesting packing or encryption.",
            severity=SignalType.HIGH,
            source_tool="entropy",
            mitre_ids=["T1027.002"],
        ))
    elif packed_pct > 30:
        findings.append(Finding(
            title="Binary contains high-entropy sections",
            description=f"{packed_pct:.0f}% of the binary has high entropy, suggesting compression or encrypted resources.",
            severity=SignalType.LOW,
            source_tool="entropy",
            mitre_ids=["T1027.002"],
        ))

    return findings


def compute_verdict(report: AnalysisReport) -> tuple[str, float]:
    """Compute overall verdict — calibrated to be conservative.

    Strong signals (YARA, packed+suspicious, multiple shellcode patterns) push toward
    malicious. Single weak signals (one anti-debug API) stay clean.
    """
    score = 0.0

    # Severity weights — reduced from previous version
    severity_weights = {
        SignalType.INFO: 0.0,    # was 0.05 — informational shouldn't move verdict
        SignalType.LOW: 0.05,    # was 0.10
        SignalType.MEDIUM: 0.15, # was 0.20
        SignalType.HIGH: 0.30,   # was 0.35
        SignalType.CRITICAL: 0.50,
    }
    for finding in report.findings:
        score += severity_weights.get(finding.severity, 0.0)

    # YARA: high-signal — each match is meaningful
    score += len(report.yara_matches) * 0.20

    # Packed + suspicious imports = bad combination
    if report.file_info.is_packed and any(
        f.severity in (SignalType.HIGH, SignalType.CRITICAL) for f in report.findings
    ):
        score += 0.20

    # Suspicious strings — capped low. Many legit apps have one or two.
    interesting_count = sum(1 for s in report.strings if s.is_interesting)
    if interesting_count >= 5:
        score += min((interesting_count - 4) * 0.02, 0.15)

    # Microsoft-signed-looking binaries (path hints) get a small benefit
    # This isn't a real signature check but a soft heuristic
    fi = report.file_info
    path_lower = str(fi.path).lower()
    if any(d in path_lower for d in (
        "\\windows\\system32\\", "\\windows\\syswow64\\",
        "\\program files\\", "\\program files (x86)\\",
    )):
        score *= 0.6  # 40% reduction — known-good location

    score = min(score, 1.0)

    # Higher thresholds to reduce false positives
    if score >= 0.75:
        return "malicious", score
    elif score >= 0.40:
        return "suspicious", score
    else:
        return "clean", 1.0 - score
