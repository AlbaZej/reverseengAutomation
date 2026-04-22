"""Ghidra headless mode wrapper for automated binary analysis."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

from core.models import DecompiledFunction, ExportedFunction, ImportedFunction, ToolResult
from core.tools.base import BaseTool

GHIDRA_SCRIPTS_DIR = Path(__file__).parent.parent.parent / "ghidra_scripts"


class GhidraTool(BaseTool):
    name = "ghidra"
    description = "Decompile and analyze binaries using Ghidra headless mode"
    supported_types = ["pe", "elf", "macho"]

    def __init__(self, ghidra_path: str | None = None):
        self._ghidra_path = ghidra_path or os.environ.get("GHIDRA_INSTALL_DIR")

    def is_available(self) -> bool:
        if self._ghidra_path and Path(self._ghidra_path).exists():
            return True
        # Check PATH for analyzeHeadless
        return shutil.which("analyzeHeadless") is not None

    def _get_headless_path(self) -> str:
        if self._ghidra_path:
            # Standard Ghidra install layout
            headless = Path(self._ghidra_path) / "support" / "analyzeHeadless"
            if headless.exists():
                return str(headless)
            # Windows variant
            headless_bat = headless.with_suffix(".bat")
            if headless_bat.exists():
                return str(headless_bat)
        return "analyzeHeadless"

    def run(self, target: Path, **kwargs) -> ToolResult:
        if not self.is_available():
            return ToolResult(
                tool_name=self.name,
                success=False,
                duration_seconds=0,
                error=(
                    "Ghidra not found. Set GHIDRA_INSTALL_DIR environment variable "
                    "or ensure analyzeHeadless is in PATH."
                ),
            )

        with tempfile.TemporaryDirectory(prefix="deshifro_ghidra_") as tmpdir:
            project_dir = Path(tmpdir)
            output_file = project_dir / "analysis_output.json"

            # Run Ghidra headless with our analysis script
            headless = self._get_headless_path()
            cmd = [
                headless,
                str(project_dir),
                "DeshifroProject",
                "-import", str(target),
                "-postScript", str(GHIDRA_SCRIPTS_DIR / "auto_analyze.py"),
                str(output_file),
                "-scriptPath", str(GHIDRA_SCRIPTS_DIR),
                "-deleteProject",  # clean up after
            ]

            stdout, stderr, rc = self._exec(cmd, timeout=600)

            if not output_file.exists():
                return ToolResult(
                    tool_name=self.name,
                    success=False,
                    duration_seconds=0,
                    error=f"Ghidra analysis produced no output. RC={rc}. Stderr: {stderr[:2000]}",
                    raw_output=stdout[:2000],
                )

            try:
                results = json.loads(output_file.read_text())
            except json.JSONDecodeError as e:
                return ToolResult(
                    tool_name=self.name,
                    success=False,
                    duration_seconds=0,
                    error=f"Failed to parse Ghidra output: {e}",
                )

            # Parse into structured models
            functions = [
                DecompiledFunction(
                    name=f["name"],
                    address=f["address"],
                    size=f.get("size", 0),
                    code=f.get("decompiled", ""),
                    calls=f.get("calls", []),
                    called_by=f.get("called_by", []),
                    is_interesting=f.get("is_interesting", False),
                    tags=f.get("tags", []),
                )
                for f in results.get("functions", [])
            ]

            imports = [
                ImportedFunction(
                    library=i.get("library", ""),
                    name=i["name"],
                    is_suspicious=i.get("is_suspicious", False),
                    category=i.get("category", ""),
                )
                for i in results.get("imports", [])
            ]

            exports = [
                ExportedFunction(
                    name=e["name"],
                    address=e.get("address", 0),
                )
                for e in results.get("exports", [])
            ]

            return ToolResult(
                tool_name=self.name,
                success=True,
                duration_seconds=0,
                data={
                    "function_count": len(functions),
                    "import_count": len(imports),
                    "export_count": len(exports),
                    "functions": functions,
                    "imports": imports,
                    "exports": exports,
                    "entry_point": results.get("entry_point"),
                    "architecture": results.get("architecture"),
                },
            )
