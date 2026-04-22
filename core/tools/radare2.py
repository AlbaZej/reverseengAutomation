"""Radare2 wrapper via r2pipe — fast disassembly and analysis."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from core.models import DecompiledFunction, ExportedFunction, ImportedFunction, ToolResult
from core.tools.base import BaseTool
from core.knowledge.signatures import API_TO_CATEGORY


class Radare2Tool(BaseTool):
    name = "radare2"
    description = "Fast binary analysis via radare2 — disassembly, imports, strings, xrefs"
    supported_types = ["pe", "elf", "macho"]

    def is_available(self) -> bool:
        if shutil.which("radare2") or shutil.which("r2"):
            try:
                import r2pipe  # noqa: F401
                return True
            except ImportError:
                return False
        return False

    def run(self, target: Path, **kwargs) -> ToolResult:
        if not self.is_available():
            return ToolResult(
                tool_name=self.name,
                success=False,
                duration_seconds=0,
                error="radare2 or r2pipe not installed. Install radare2 and pip install r2pipe",
            )

        import r2pipe

        r2 = r2pipe.open(str(target), flags=["-2"])  # -2 = no stderr
        try:
            return self._analyze(r2, target)
        finally:
            r2.quit()

    def _analyze(self, r2, target: Path) -> ToolResult:
        # Run auto-analysis
        r2.cmd("aaa")

        # File info
        info = json.loads(r2.cmd("ij"))
        bin_info = info.get("bin", {})

        # Imports
        raw_imports = json.loads(r2.cmd("iij") or "[]")
        imports = []
        for imp in raw_imports:
            name = imp.get("name", "")
            # Strip library prefix if present (e.g., "kernel32.dll_CreateFileA")
            short_name = name.split("_", 1)[-1] if "_" in name else name
            category = API_TO_CATEGORY.get(short_name, "")
            imports.append(ImportedFunction(
                library=imp.get("libname", ""),
                name=short_name,
                ordinal=imp.get("ordinal"),
                is_suspicious=short_name in API_TO_CATEGORY,
                category=category,
            ))

        # Exports
        raw_exports = json.loads(r2.cmd("iEj") or "[]")
        exports = [
            ExportedFunction(
                name=exp.get("name", ""),
                address=exp.get("vaddr", 0),
            )
            for exp in raw_exports
        ]

        # Functions
        raw_functions = json.loads(r2.cmd("aflj") or "[]")
        functions = []
        for func in raw_functions:
            name = func.get("name", "")
            addr = func.get("offset", 0)
            size = func.get("size", 0)

            # Get disassembly for interesting functions (limit to keep it fast)
            disasm = ""
            is_interesting = False
            tags = []

            # Check if function calls suspicious APIs
            xrefs_out = json.loads(r2.cmd(f"axfj @{addr}") or "[]")
            calls = []
            for xref in xrefs_out:
                ref_name = xref.get("name", "")
                if ref_name:
                    calls.append(ref_name)
                    short = ref_name.split("_", 1)[-1] if "_" in ref_name else ref_name
                    if short in API_TO_CATEGORY:
                        is_interesting = True
                        tags.append(API_TO_CATEGORY[short])

            # Decompile interesting functions (using r2 pseudo-decompiler)
            if is_interesting and len(functions) < 30:
                disasm = r2.cmd(f"pdc @{addr}") or ""

            functions.append(DecompiledFunction(
                name=name,
                address=addr,
                size=size,
                code=disasm,
                calls=calls,
                is_interesting=is_interesting,
                tags=list(set(tags)),
            ))

        # Sections
        sections = json.loads(r2.cmd("iSj") or "[]")
        section_info = [
            {
                "name": s.get("name", ""),
                "size": s.get("size", 0),
                "vsize": s.get("vsize", 0),
                "entropy": s.get("entropy", 0),
                "perm": s.get("perm", ""),
            }
            for s in sections
        ]

        return ToolResult(
            tool_name=self.name,
            success=True,
            duration_seconds=0,
            data={
                "architecture": bin_info.get("arch", "unknown"),
                "bits": bin_info.get("bits", 0),
                "os": bin_info.get("os", "unknown"),
                "compiler": bin_info.get("compiler", ""),
                "language": bin_info.get("lang", ""),
                "stripped": bin_info.get("stripped", False),
                "static": bin_info.get("static", False),
                "entry_point": bin_info.get("baddr", 0),
                "function_count": len(functions),
                "import_count": len(imports),
                "export_count": len(exports),
                "functions": functions,
                "imports": imports,
                "exports": exports,
                "sections": section_info,
            },
        )
