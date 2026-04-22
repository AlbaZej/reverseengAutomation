"""Binary analysis pipeline — orchestrates tools for PE/ELF/Mach-O analysis."""

from __future__ import annotations

from pathlib import Path

from core.ingest.reader import triage_file
from core.knowledge.heuristics import (
    compute_verdict,
    extract_iocs_from_strings,
    generate_findings_from_entropy,
    generate_findings_from_imports,
    generate_findings_from_yara,
)
from core.models import AnalysisReport, Finding, SignalType
from core.tools.die_tool import DieTool
from core.tools.entropy_tool import EntropyTool
from core.tools.ghidra import GhidraTool
from core.tools.radare2 import Radare2Tool
from core.tools.strings_tool import StringsTool
from core.tools.virustotal import VirusTotalTool
from core.tools.yara_tool import YaraTool


class BinaryAnalyzer:
    """Full binary RE pipeline: triage → strings → entropy → YARA → DIE → r2/Ghidra → VT → report."""

    def __init__(self, enable_ghidra: bool = True):
        self.strings_tool = StringsTool()
        self.entropy_tool = EntropyTool()
        self.yara_tool = YaraTool()
        self.die_tool = DieTool()
        self.r2_tool = Radare2Tool()
        self.ghidra_tool = GhidraTool()
        self.vt_tool = VirusTotalTool()
        self.enable_ghidra = enable_ghidra

    def analyze(self, target: Path, quick: bool = False) -> AnalysisReport:
        """Run the full binary analysis pipeline.

        Args:
            target: Path to the binary file.
            quick: If True, skip Ghidra and heavy tools.
        """
        # Stage 1: Triage — file type, hashes, architecture
        file_info = triage_file(target)
        report = AnalysisReport(file_info=file_info)

        # Stage 2: Strings — extract and classify
        strings_result = self.strings_tool._timed_run(target)
        report.tool_results.append(strings_result)
        if strings_result.success:
            report.strings = strings_result.data.get("strings", [])

        # Stage 3: Entropy — detect packing/encryption
        entropy_result = self.entropy_tool._timed_run(target)
        report.tool_results.append(entropy_result)
        if entropy_result.success:
            report.entropy_regions = entropy_result.data.get("regions", [])
            if entropy_result.data.get("likely_packed"):
                file_info.is_packed = True
            report.findings.extend(
                generate_findings_from_entropy(report.entropy_regions, file_info.size)
            )

        # Stage 4: YARA — rule matching
        if self.yara_tool.is_available():
            yara_result = self.yara_tool._timed_run(target)
            report.tool_results.append(yara_result)
            if yara_result.success:
                report.yara_matches = yara_result.data.get("matches", [])
                report.findings.extend(generate_findings_from_yara(report.yara_matches))

        # Stage 5: DIE — packer/compiler detection
        if self.die_tool.is_available():
            die_result = self.die_tool._timed_run(target)
            report.tool_results.append(die_result)
            if die_result.success:
                data = die_result.data
                if data.get("is_packed"):
                    file_info.is_packed = True
                    packer = next(
                        (d["name"] for d in data.get("detections", []) if d["type"] == "packer"),
                        None,
                    )
                    file_info.packer_name = packer
                file_info.compiler = data.get("compiler")

        # Stage 6: Radare2 — fast disassembly + import/function analysis
        if self.r2_tool.is_available():
            r2_result = self.r2_tool._timed_run(target)
            report.tool_results.append(r2_result)
            if r2_result.success:
                # Use r2 results for imports/exports/functions if Ghidra won't run
                if quick or not self.ghidra_tool.is_available():
                    report.functions = r2_result.data.get("functions", [])
                    report.imports = r2_result.data.get("imports", [])
                    report.exports = r2_result.data.get("exports", [])
                    report.findings.extend(generate_findings_from_imports(report))

        # Stage 7: Ghidra — decompilation and deep analysis (if not quick)
        if not quick and self.enable_ghidra and self.ghidra_tool.is_available():
            ghidra_result = self.ghidra_tool._timed_run(target)
            report.tool_results.append(ghidra_result)
            if ghidra_result.success:
                report.functions = ghidra_result.data.get("functions", [])
                report.imports = ghidra_result.data.get("imports", [])
                report.exports = ghidra_result.data.get("exports", [])
                report.findings.extend(generate_findings_from_imports(report))

        # Stage 8: VirusTotal — check if known
        if self.vt_tool.is_available():
            vt_result = self.vt_tool._timed_run(target)
            report.tool_results.append(vt_result)
            if vt_result.success:
                vt_data = vt_result.data
                if vt_data.get("found"):
                    detections = vt_data.get("detections", 0)
                    total = vt_data.get("total_engines", 0)
                    label = vt_data.get("threat_label", "")

                    if detections > 0:
                        severity = SignalType.CRITICAL if detections > 10 else SignalType.HIGH
                        report.findings.append(Finding(
                            title=f"VirusTotal: {detections}/{total} engines detect this file",
                            description=f"Threat label: {label}" if label else f"Detected by {detections} engines",
                            severity=severity,
                            source_tool="virustotal",
                            evidence=", ".join(
                                f"{k}: {v}" for k, v in
                                list(vt_data.get("positive_engines", {}).items())[:5]
                            ),
                        ))
                    else:
                        report.findings.append(Finding(
                            title="VirusTotal: Clean — 0 detections",
                            description=f"Scanned by {total} engines, no detections",
                            severity=SignalType.INFO,
                            source_tool="virustotal",
                        ))
                else:
                    report.findings.append(Finding(
                        title="VirusTotal: Not found — possibly novel sample",
                        description="File hash not in VT database",
                        severity=SignalType.MEDIUM,
                        source_tool="virustotal",
                    ))

        # Stage 9: IOC extraction from strings
        report.iocs = extract_iocs_from_strings(report.strings)

        # Stage 10: Compute verdict
        report.verdict, report.verdict_confidence = compute_verdict(report)

        return report
