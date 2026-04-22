"""Heuristics for classifying findings and computing verdicts."""

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


def extract_iocs_from_strings(strings: list[ExtractedString]) -> list[IOC]:
    """Extract IOCs from classified strings."""
    iocs = []
    for s in strings:
        if s.category == "url":
            iocs.append(IOC(type="url", value=s.value, context=f"string at offset {s.offset}"))
        elif s.category == "ip":
            # Filter out common non-IOC IPs
            if not s.value.startswith(("0.0.", "127.0.", "255.255.")):
                iocs.append(IOC(type="ip", value=s.value, context=f"string at offset {s.offset}"))
        elif s.category == "email":
            iocs.append(IOC(type="email", value=s.value, context=f"string at offset {s.offset}"))
        elif s.category == "registry":
            iocs.append(IOC(type="registry", value=s.value, context=f"string at offset {s.offset}"))
    return iocs


def generate_findings_from_imports(report: AnalysisReport) -> list[Finding]:
    """Generate findings based on imported API analysis."""
    findings = []
    categories_seen: dict[str, list[str]] = {}

    for imp in report.imports:
        if imp.name in API_TO_CATEGORY:
            cat = API_TO_CATEGORY[imp.name]
            if cat not in categories_seen:
                categories_seen[cat] = []
            categories_seen[cat].append(imp.name)

    for cat, apis in categories_seen.items():
        severity_map = {
            "injection": SignalType.CRITICAL,
            "anti_debug": SignalType.HIGH,
            "persistence": SignalType.HIGH,
            "process": SignalType.MEDIUM,
            "crypto": SignalType.MEDIUM,
            "network": SignalType.MEDIUM,
            "evasion": SignalType.MEDIUM,
            "registry": SignalType.LOW,
            "file": SignalType.INFO,
        }
        mitre = CATEGORY_TO_MITRE.get(cat, [])
        findings.append(Finding(
            title=f"Suspicious {cat} API usage detected",
            description=f"Binary imports {len(apis)} {cat}-related APIs: {', '.join(apis[:5])}{'...' if len(apis) > 5 else ''}",
            severity=severity_map.get(cat, SignalType.LOW),
            source_tool="import_analysis",
            evidence=", ".join(apis),
            mitre_ids=mitre,
        ))

    return findings


def generate_findings_from_yara(matches: list[YaraMatch]) -> list[Finding]:
    """Generate findings from YARA matches."""
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
            title="Binary contains packed/encrypted sections",
            description=f"{packed_pct:.0f}% of the binary has high entropy, suggesting partial packing or encrypted payloads.",
            severity=SignalType.MEDIUM,
            source_tool="entropy",
            mitre_ids=["T1027.002"],
        ))

    return findings


def compute_verdict(report: AnalysisReport) -> tuple[str, float]:
    """Compute overall verdict: clean / suspicious / malicious with confidence."""
    score = 0.0

    # Score from findings
    severity_weights = {
        SignalType.INFO: 0.05,
        SignalType.LOW: 0.1,
        SignalType.MEDIUM: 0.2,
        SignalType.HIGH: 0.35,
        SignalType.CRITICAL: 0.5,
    }
    for finding in report.findings:
        score += severity_weights.get(finding.severity, 0.1)

    # Score from YARA matches
    score += len(report.yara_matches) * 0.15

    # Score from packing
    if report.file_info.is_packed:
        score += 0.2

    # Score from suspicious strings
    interesting_strings = sum(1 for s in report.strings if s.is_interesting)
    score += min(interesting_strings * 0.02, 0.3)

    # Clamp
    score = min(score, 1.0)

    if score >= 0.7:
        return "malicious", score
    elif score >= 0.3:
        return "suspicious", score
    else:
        return "clean", 1.0 - score  # confidence in being clean
