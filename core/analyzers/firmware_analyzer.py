"""Firmware analysis pipeline — extract, scan, and analyze firmware images."""

from __future__ import annotations

from pathlib import Path

from core.ingest.reader import triage_file
from core.knowledge.heuristics import (
    compute_verdict,
    extract_iocs_from_strings,
    generate_findings_from_entropy,
    generate_findings_from_yara,
)
from core.models import AnalysisReport, Finding, SignalType
from core.tools.binwalk_tool import BinwalkTool
from core.tools.entropy_tool import EntropyTool
from core.tools.strings_tool import StringsTool
from core.tools.yara_tool import YaraTool


class FirmwareAnalyzer:
    """Firmware RE pipeline: binwalk → strings → entropy → YARA → report."""

    def __init__(self):
        self.binwalk_tool = BinwalkTool()
        self.strings_tool = StringsTool()
        self.entropy_tool = EntropyTool()
        self.yara_tool = YaraTool()

    def analyze(self, target: Path, quick: bool = False) -> AnalysisReport:
        file_info = triage_file(target)
        report = AnalysisReport(file_info=file_info)

        # Stage 1: Binwalk extraction
        binwalk_result = self.binwalk_tool._timed_run(target)
        report.tool_results.append(binwalk_result)
        if binwalk_result.success:
            data = binwalk_result.data

            # Report interesting files
            for f in data.get("interesting_files", []):
                report.findings.append(Finding(
                    title=f"Interesting file: {f['path']}",
                    description=f"Found {f.get('reason', 'interesting file')} ({f['size']} bytes)",
                    severity=SignalType.INFO,
                    source_tool="binwalk",
                ))

            # Report potential credentials
            for cred in data.get("potential_credentials", []):
                report.findings.append(Finding(
                    title=f"Potential hardcoded credential in {cred['path']}",
                    description=f"Pattern '{cred['pattern']}' found in extracted file",
                    severity=SignalType.HIGH,
                    source_tool="binwalk",
                    mitre_ids=["T1552.001"],
                ))

            # Report embedded executables
            for exe in data.get("executables", []):
                report.findings.append(Finding(
                    title=f"Embedded {exe['type']} executable: {exe['path']}",
                    description=f"Executable binary found in firmware ({exe['size']} bytes)",
                    severity=SignalType.MEDIUM,
                    source_tool="binwalk",
                ))

            # Report signatures
            sig_count = len(data.get("signatures", []))
            if sig_count > 0:
                report.findings.append(Finding(
                    title=f"Firmware contains {sig_count} recognized signatures",
                    description="Binwalk identified embedded filesystems, compressed data, or known formats",
                    severity=SignalType.INFO,
                    source_tool="binwalk",
                ))

        # Stage 2: Strings
        strings_result = self.strings_tool._timed_run(target)
        report.tool_results.append(strings_result)
        if strings_result.success:
            report.strings = strings_result.data.get("strings", [])

        # Stage 3: Entropy
        entropy_result = self.entropy_tool._timed_run(target)
        report.tool_results.append(entropy_result)
        if entropy_result.success:
            report.entropy_regions = entropy_result.data.get("regions", [])
            report.findings.extend(
                generate_findings_from_entropy(report.entropy_regions, file_info.size)
            )

        # Stage 4: YARA
        if self.yara_tool.is_available():
            yara_result = self.yara_tool._timed_run(target)
            report.tool_results.append(yara_result)
            if yara_result.success:
                report.yara_matches = yara_result.data.get("matches", [])
                report.findings.extend(generate_findings_from_yara(report.yara_matches))

        # Stage 5: IOC extraction
        report.iocs = extract_iocs_from_strings(report.strings)

        # Stage 6: Verdict
        report.verdict, report.verdict_confidence = compute_verdict(report)

        return report
