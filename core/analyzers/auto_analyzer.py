"""Auto-detect file type and route to the appropriate analysis pipeline."""

from __future__ import annotations

from pathlib import Path

from core.ingest.reader import triage_file
from core.models import AnalysisReport, FileType


def auto_analyze(target: Path, quick: bool = False) -> AnalysisReport:
    """Auto-detect file type and run the appropriate pipeline.

    Args:
        target: Path to the file to analyze.
        quick: If True, skip heavy tools like Ghidra.
    """
    file_info = triage_file(target)

    if file_info.file_type in (FileType.PE, FileType.ELF, FileType.MACHO):
        from core.analyzers.binary_analyzer import BinaryAnalyzer
        analyzer = BinaryAnalyzer()
        return analyzer.analyze(target, quick=quick)

    if file_info.file_type == FileType.PCAP:
        # Protocol analyzer — coming soon
        # For now, run basic analysis
        from core.analyzers.binary_analyzer import BinaryAnalyzer
        analyzer = BinaryAnalyzer(enable_ghidra=False)
        return analyzer.analyze(target, quick=True)

    if file_info.file_type == FileType.FIRMWARE:
        from core.analyzers.firmware_analyzer import FirmwareAnalyzer
        analyzer = FirmwareAnalyzer()
        return analyzer.analyze(target, quick=quick)

    # Unknown type — try firmware pipeline first (binwalk can detect embedded content)
    # then fall back to basic binary analysis
    from core.analyzers.firmware_analyzer import FirmwareAnalyzer
    try:
        analyzer = FirmwareAnalyzer()
        report = analyzer.analyze(target, quick=quick)
        # If binwalk found signatures, this is likely firmware
        binwalk_data = next(
            (t.data for t in report.tool_results if t.tool_name == "binwalk" and t.success),
            {},
        )
        if binwalk_data.get("signatures"):
            return report
    except Exception:
        pass

    # Fall back to binary analysis (strings + entropy + YARA still work on anything)
    from core.analyzers.binary_analyzer import BinaryAnalyzer
    analyzer = BinaryAnalyzer(enable_ghidra=False)
    return analyzer.analyze(target, quick=quick)
