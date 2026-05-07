"""Archive analysis pipeline — extract archive, analyze each contained file, aggregate."""

from __future__ import annotations

from pathlib import Path

from core.ingest.reader import triage_file
from core.knowledge.heuristics import compute_verdict
from core.models import AnalysisReport, Finding, SignalType
from core.tools.archive_tool import ArchiveTool


class ArchiveAnalyzer:
    """Extract archives, run binary/firmware pipeline on each contained file."""

    def __init__(self, max_files: int = 25, max_file_size_mb: int = 100):
        self.archive_tool = ArchiveTool()
        self.max_files = max_files
        self.max_file_size = max_file_size_mb * 1024 * 1024

    def analyze(self, target: Path, quick: bool = True) -> AnalysisReport:
        file_info = triage_file(target)
        report = AnalysisReport(file_info=file_info)

        # Extract archive
        result = self.archive_tool._timed_run(target)
        report.tool_results.append(result)

        if not result.success:
            report.findings.append(Finding(
                title="Archive extraction failed",
                description=result.error,
                severity=SignalType.LOW,
                source_tool="archive",
            ))
            report.verdict = "unknown"
            return report

        data = result.data
        files = data.get("files", [])

        # Add summary findings
        report.findings.append(Finding(
            title=f"Archive extracted ({data['archive_format'].upper()})",
            description=(
                f"Found {len(files)} file(s)"
                + (f" using password '{data['password_used']}'"
                   if data.get("password_used") else "")
            ),
            severity=SignalType.INFO,
            source_tool="archive",
        ))

        # Analyze each contained file
        from core.analyzers.auto_analyzer import auto_analyze

        contained_reports = []
        analyzed = 0
        skipped = 0

        for file_entry in files:
            if analyzed >= self.max_files:
                skipped += 1
                continue
            if file_entry["size"] > self.max_file_size:
                skipped += 1
                continue

            contained_path = Path(file_entry["abs_path"])
            try:
                # Run the auto-analyzer on each file (will route to right pipeline)
                # quick=True to skip Ghidra for archive contents (would be too slow)
                sub_report = _analyze_contained(contained_path, quick=True)
                contained_reports.append({
                    "path": file_entry["path"],
                    "size": file_entry["size"],
                    "report": sub_report,
                })
                analyzed += 1
            except Exception as e:
                contained_reports.append({
                    "path": file_entry["path"],
                    "size": file_entry["size"],
                    "error": str(e),
                })

        # Aggregate findings from contained files into parent report
        max_severity = SignalType.INFO
        worst_verdict = "clean"
        verdict_priority = {"clean": 0, "suspicious": 1, "malicious": 2}

        for cr in contained_reports:
            sub = cr.get("report")
            if not sub:
                continue

            # Roll up worst verdict
            if verdict_priority.get(sub.verdict, 0) > verdict_priority.get(worst_verdict, 0):
                worst_verdict = sub.verdict

            # Add critical/high findings from sub-files to parent
            for f in sub.findings:
                if f.severity in (SignalType.HIGH, SignalType.CRITICAL):
                    report.findings.append(Finding(
                        title=f"[{cr['path']}] {f.title}",
                        description=f.description,
                        severity=f.severity,
                        source_tool=f"archive→{f.source_tool}",
                        mitre_ids=f.mitre_ids,
                    ))

            # Roll up IOCs
            for ioc in sub.iocs:
                # Prefix context with the contained file path
                from core.models import IOC
                report.iocs.append(IOC(
                    type=ioc.type,
                    value=ioc.value,
                    context=f"{cr['path']} → {ioc.context}",
                ))

        # Store contained file metadata
        report.tool_results.append(type(result)(
            tool_name="archive_aggregate",
            success=True,
            duration_seconds=0,
            data={
                "total_files": len(files),
                "analyzed": analyzed,
                "skipped": skipped,
                "contained": [
                    {
                        "path": cr["path"],
                        "size": cr["size"],
                        "verdict": cr.get("report").verdict if cr.get("report") else None,
                        "verdict_confidence": cr.get("report").verdict_confidence if cr.get("report") else None,
                        "findings": len(cr.get("report").findings) if cr.get("report") else 0,
                        "file_type": cr.get("report").file_info.file_type.value if cr.get("report") else "error",
                        "error": cr.get("error"),
                    }
                    for cr in contained_reports
                ],
            },
        ))

        # Set parent verdict to worst contained verdict
        report.verdict = worst_verdict
        # Recompute confidence based on parent findings
        _, conf = compute_verdict(report)
        report.verdict_confidence = conf

        return report


def _analyze_contained(path: Path, quick: bool = True) -> AnalysisReport:
    """Analyze a single contained file. Lazy import to avoid circular dep."""
    file_info = triage_file(path)

    from core.models import FileType
    if file_info.file_type in (FileType.PE, FileType.ELF, FileType.MACHO):
        from core.analyzers.binary_analyzer import BinaryAnalyzer
        return BinaryAnalyzer(enable_ghidra=False).analyze(path, quick=quick)

    from core.tools.archive_tool import is_archive
    if is_archive(path):
        # Don't recurse into nested archives — return basic triage only
        report = AnalysisReport(file_info=file_info)
        report.verdict = "unknown"
        return report

    # Unknown / other → run firmware pipeline (good for any blob)
    from core.analyzers.firmware_analyzer import FirmwareAnalyzer
    return FirmwareAnalyzer().analyze(path, quick=quick)
