"""Detect It Easy (DIE) wrapper — packer/compiler/linker detection.

Falls back to pefile-based detection if DIE is not installed.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from core.models import ToolResult
from core.tools.base import BaseTool


# Known packer section names
PACKER_SECTIONS = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".themida": "Themida", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
    ".enigma1": "Enigma", ".enigma2": "Enigma",
    ".nsp0": "NsPack", ".nsp1": "NsPack",
    ".petite": "Petite",
    ".yP": "Y0da Protector",
    ".MaskPE": "MaskPE",
}

# Known compiler signatures in PE header
COMPILER_HINTS = {
    "Rich": "Microsoft Visual C++",
    "Borland": "Borland Delphi/C++",
    "Mingw": "MinGW GCC",
    ".go": "Go",
    "PyInstaller": "PyInstaller (Python)",
    "py2exe": "py2exe (Python)",
    "AutoIt": "AutoIt",
    ".rsrc": "Resource section (likely GUI app)",
}


class DieTool(BaseTool):
    name = "die"
    description = "Detect packers, compilers, and linkers"
    supported_types = ["pe", "elf", "macho"]

    def is_available(self) -> bool:
        # Check for DIE CLI or fall back to pefile
        if shutil.which("diec") or shutil.which("die"):
            return True
        try:
            import pefile  # noqa: F401
            return True
        except ImportError:
            return False

    def run(self, target: Path, **kwargs) -> ToolResult:
        # Try DIE CLI first
        die_path = shutil.which("diec") or shutil.which("die")
        if die_path:
            return self._run_die_cli(target, die_path)

        # Fall back to pefile-based detection
        return self._run_pefile(target)

    def _run_die_cli(self, target: Path, die_path: str) -> ToolResult:
        stdout, stderr, rc = self._exec([die_path, "-j", str(target)])

        if rc != 0:
            return ToolResult(
                tool_name=self.name,
                success=False,
                duration_seconds=0,
                error=f"DIE failed: {stderr}",
                raw_output=stdout,
            )

        import json
        try:
            results = json.loads(stdout)
        except json.JSONDecodeError:
            results = {"raw": stdout}

        return ToolResult(
            tool_name=self.name,
            success=True,
            duration_seconds=0,
            raw_output=stdout,
            data={
                "source": "die",
                "results": results,
            },
        )

    def _run_pefile(self, target: Path) -> ToolResult:
        try:
            import pefile
        except ImportError:
            return ToolResult(
                tool_name=self.name,
                success=False,
                duration_seconds=0,
                error="Neither DIE CLI nor pefile is available",
            )

        try:
            pe = pefile.PE(str(target))
        except pefile.PEFormatError as e:
            return ToolResult(
                tool_name=self.name,
                success=False,
                duration_seconds=0,
                error=f"Not a valid PE file: {e}",
            )

        # Detect packers from section names
        detections = []
        sections = []
        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            sections.append({
                "name": name,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(section.get_entropy(), 4),
            })
            if name in PACKER_SECTIONS:
                detections.append({
                    "type": "packer",
                    "name": PACKER_SECTIONS[name],
                    "confidence": 0.9,
                })

        # Check for compiler hints in the binary
        data = target.read_bytes()[:4096]  # just the header area
        text = data.decode("ascii", errors="replace")
        for hint, compiler in COMPILER_HINTS.items():
            if hint in text:
                detections.append({
                    "type": "compiler",
                    "name": compiler,
                    "confidence": 0.7,
                })

        # Check for high entropy sections (sign of packing)
        for s in sections:
            if s["entropy"] > 7.0 and s["raw_size"] > 1024:
                detections.append({
                    "type": "packer",
                    "name": f"Unknown (high entropy in {s['name']})",
                    "confidence": 0.5,
                })

        is_packed = any(d["type"] == "packer" for d in detections)
        compiler = next(
            (d["name"] for d in detections if d["type"] == "compiler"), None
        )

        pe.close()

        return ToolResult(
            tool_name=self.name,
            success=True,
            duration_seconds=0,
            data={
                "source": "pefile",
                "is_packed": is_packed,
                "compiler": compiler,
                "detections": detections,
                "sections": sections,
            },
        )
