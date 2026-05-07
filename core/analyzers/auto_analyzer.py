"""Auto-detect file type and route to the appropriate analysis pipeline."""

from __future__ import annotations

from pathlib import Path

from core.ingest.reader import triage_file
from core.models import AnalysisReport, FileType
from core.tools.archive_tool import is_archive


def auto_analyze(target: Path, quick: bool = False) -> AnalysisReport:
    """Auto-detect file type and run the appropriate pipeline.

    Routing:
    - Archive (ZIP/RAR/7z/TAR/etc.) → ArchiveAnalyzer (extract + analyze each file)
    - PE/ELF/Mach-O → BinaryAnalyzer
    - Firmware → FirmwareAnalyzer
    - Unknown → try firmware pipeline, then binary as fallback
    """
    file_info = triage_file(target)

    # Check for archives first (before file type routing)
    if is_archive(target):
        from core.analyzers.archive_analyzer import ArchiveAnalyzer
        return ArchiveAnalyzer().analyze(target, quick=quick)

    if file_info.file_type in (FileType.PE, FileType.ELF, FileType.MACHO):
        from core.analyzers.binary_analyzer import BinaryAnalyzer
        return BinaryAnalyzer().analyze(target, quick=quick)

    if file_info.file_type == FileType.PCAP:
        from core.analyzers.binary_analyzer import BinaryAnalyzer
        return BinaryAnalyzer(enable_ghidra=False).analyze(target, quick=True)

    if file_info.file_type == FileType.FIRMWARE:
        from core.analyzers.firmware_analyzer import FirmwareAnalyzer
        return FirmwareAnalyzer().analyze(target, quick=quick)

    # Unknown — try firmware pipeline (binwalk can detect embedded content)
    from core.analyzers.firmware_analyzer import FirmwareAnalyzer
    try:
        analyzer = FirmwareAnalyzer()
        report = analyzer.analyze(target, quick=quick)
        binwalk_data = next(
            (t.data for t in report.tool_results if t.tool_name == "binwalk" and t.success),
            {},
        )
        if binwalk_data.get("signatures"):
            return report
    except Exception:
        pass

    from core.analyzers.binary_analyzer import BinaryAnalyzer
    return BinaryAnalyzer(enable_ghidra=False).analyze(target, quick=quick)
