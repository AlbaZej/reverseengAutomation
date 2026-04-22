"""Report generation — JSON, HTML, and summary text."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from core.models import AnalysisReport


def _serialize(obj):
    """Custom JSON serializer for dataclass fields."""
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, set):
        return list(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def to_json(report: AnalysisReport, pretty: bool = True) -> str:
    """Serialize an AnalysisReport to JSON."""
    data = {
        "deshifro_version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "file_info": {
            "path": str(report.file_info.path),
            "size": report.file_info.size,
            "md5": report.file_info.md5,
            "sha256": report.file_info.sha256,
            "file_type": report.file_info.file_type.value,
            "architecture": report.file_info.architecture.value,
            "mime_type": report.file_info.mime_type,
            "is_packed": report.file_info.is_packed,
            "packer_name": report.file_info.packer_name,
            "compiler": report.file_info.compiler,
        },
        "verdict": report.verdict,
        "verdict_confidence": round(report.verdict_confidence, 4),
        "summary": {
            "total_strings": len(report.strings),
            "interesting_strings": sum(1 for s in report.strings if s.is_interesting),
            "yara_matches": len(report.yara_matches),
            "findings_count": len(report.findings),
            "ioc_count": len(report.iocs),
            "function_count": len(report.functions),
            "import_count": len(report.imports),
        },
        "findings": [
            {
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "source_tool": f.source_tool,
                "evidence": f.evidence,
                "mitre_ids": f.mitre_ids,
            }
            for f in sorted(report.findings, key=lambda f: _severity_rank(f.severity), reverse=True)
        ],
        "iocs": [
            {"type": i.type, "value": i.value, "context": i.context}
            for i in report.iocs
        ],
        "yara_matches": [
            {
                "rule": m.rule_name,
                "tags": m.tags,
                "meta": m.meta,
            }
            for m in report.yara_matches
        ],
        "entropy_regions": [
            {
                "offset": r.offset,
                "size": r.size,
                "entropy": r.entropy,
                "label": r.label,
            }
            for r in report.entropy_regions
        ],
        "strings": {
            "interesting": [
                {"value": s.value, "offset": s.offset, "category": s.category}
                for s in report.strings if s.is_interesting
            ],
        },
        "tool_results": [
            {
                "tool": t.tool_name,
                "success": t.success,
                "duration_seconds": round(t.duration_seconds, 3),
                "error": t.error or None,
            }
            for t in report.tool_results
        ],
    }

    return json.dumps(data, indent=2 if pretty else None, default=_serialize)


def to_summary(report: AnalysisReport) -> str:
    """Generate a human-readable text summary."""
    fi = report.file_info
    lines = [
        f"{'=' * 60}",
        f"  DESHIFRO ANALYSIS REPORT",
        f"{'=' * 60}",
        f"",
        f"  File:         {fi.path.name}",
        f"  Type:         {fi.file_type.value.upper()} ({fi.architecture.value})",
        f"  Size:         {fi.size:,} bytes",
        f"  MD5:          {fi.md5}",
        f"  SHA256:       {fi.sha256}",
        f"  Packed:       {'Yes (' + fi.packer_name + ')' if fi.is_packed else 'No'}",
        f"  Compiler:     {fi.compiler or 'Unknown'}",
        f"",
        f"  VERDICT:      {report.verdict.upper()} (confidence: {report.verdict_confidence:.0%})",
        f"",
    ]

    if report.findings:
        lines.append(f"  FINDINGS ({len(report.findings)}):")
        lines.append(f"  {'-' * 56}")
        for f in sorted(report.findings, key=lambda x: _severity_rank(x.severity), reverse=True):
            lines.append(f"  [{f.severity.value.upper():8s}] {f.title}")
            lines.append(f"             {f.description}")
            if f.mitre_ids:
                lines.append(f"             MITRE: {', '.join(f.mitre_ids)}")
            lines.append("")

    if report.iocs:
        lines.append(f"  IOCs ({len(report.iocs)}):")
        lines.append(f"  {'-' * 56}")
        for ioc in report.iocs[:20]:
            lines.append(f"  [{ioc.type:10s}] {ioc.value}")
        if len(report.iocs) > 20:
            lines.append(f"  ... and {len(report.iocs) - 20} more")
        lines.append("")

    if report.yara_matches:
        lines.append(f"  YARA MATCHES ({len(report.yara_matches)}):")
        lines.append(f"  {'-' * 56}")
        for m in report.yara_matches:
            lines.append(f"  - {m.rule_name}: {m.meta.get('description', '')}")
        lines.append("")

    lines.append(f"  TOOL EXECUTION:")
    lines.append(f"  {'-' * 56}")
    for t in report.tool_results:
        status = "OK" if t.success else "FAIL"
        lines.append(f"  [{status:4s}] {t.tool_name:15s} ({t.duration_seconds:.2f}s)")
    lines.append(f"{'=' * 60}")

    return "\n".join(lines)


def _severity_rank(severity) -> int:
    from core.models import SignalType
    return {
        SignalType.INFO: 0,
        SignalType.LOW: 1,
        SignalType.MEDIUM: 2,
        SignalType.HIGH: 3,
        SignalType.CRITICAL: 4,
    }.get(severity, 0)
