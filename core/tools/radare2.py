"""Radare2 wrapper via r2pipe — fast disassembly and analysis."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from core.models import DecompiledFunction, ExportedFunction, ImportedFunction, ToolResult
from core.tools.base import BaseTool
from core.knowledge.signatures import API_TO_CATEGORY


# Common r2 prefixes for imported/external symbols
_R2_PREFIXES = ("sym.imp.", "imp.", "sym.", "fcn.")


def _strip_api_prefix(name: str) -> str:
    """Reduce an r2 symbol name like 'sym.imp.kernel32.dll_VirtualAllocEx'
    to a bare API name 'VirtualAllocEx' that matches our API_TO_CATEGORY table.

    Handles:
      sym.imp.VirtualAllocEx               -> VirtualAllocEx
      sym.imp.kernel32.dll_VirtualAllocEx  -> VirtualAllocEx
      kernel32.dll_VirtualAllocEx          -> VirtualAllocEx
      VirtualAllocEx                       -> VirtualAllocEx
    """
    if not name:
        return name
    # Strip r2 prefixes
    for prefix in _R2_PREFIXES:
        if name.startswith(prefix):
            name = name[len(prefix):]
    # If there's a "DLL_API" pattern, take the part after the last underscore
    # (but not numeric suffixes like _0, _1)
    if "_" in name:
        head, _, tail = name.rpartition("_")
        if tail and not tail.isdigit():
            name = tail
    return name


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
        # Run basic auto-analysis (aa) instead of deep (aaa).
        # aa: function discovery + symbol resolution — fast (~3-5s on real malware)
        # aaa: also recovers types, calling conventions, full control flow — slow (~60-120s)
        # For triage, aa gives us imports, exports, and function list; that's enough.
        # Use aaa only when --quick is False AND the binary is small.
        r2.cmd("aa")
        # Run aac to analyze function calls — gives us cross-references cheaply.
        r2.cmd("aac")

        # File info
        info = json.loads(r2.cmd("ij"))
        bin_info = info.get("bin", {})

        # Imports
        raw_imports = json.loads(r2.cmd("iij") or "[]")
        imports = []
        for imp in raw_imports:
            name = imp.get("name", "")
            short_name = _strip_api_prefix(name)
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

        # Build a map: function_addr -> (set of tags, set of called API names)
        # by querying axtj on each suspicious import. This is much more reliable
        # than axfj per function (which doesn't include symbol names).
        suspicious_callers: dict[int, dict] = {}
        for imp in raw_imports:
            imp_name = imp.get("name", "")
            short = _strip_api_prefix(imp_name)
            if short not in API_TO_CATEGORY:
                continue
            category = API_TO_CATEGORY[short]
            plt = imp.get("plt") or 0
            if not plt:
                continue
            refs = json.loads(r2.cmd(f"axtj {plt}") or "[]")
            for ref in refs:
                fcn_addr = ref.get("fcn_addr")
                if fcn_addr is None:
                    continue
                bucket = suspicious_callers.setdefault(fcn_addr, {"tags": set(), "calls": []})
                bucket["tags"].add(category)
                bucket["calls"].append(short)

        functions = []
        for func in raw_functions:
            name = func.get("name", "")
            # r2 6.x uses "addr"; older versions used "offset". Support both.
            addr = func.get("addr") if func.get("addr") is not None else func.get("offset", 0)
            size = func.get("size", 0)

            interesting_data = suspicious_callers.get(addr)
            is_interesting = interesting_data is not None
            tags = sorted(interesting_data["tags"]) if interesting_data else []
            calls = interesting_data["calls"] if interesting_data else []

            # Decompile interesting functions (using r2 pseudo-decompiler)
            disasm = ""
            if is_interesting and sum(1 for f in functions if f.is_interesting) < 30:
                disasm = r2.cmd(f"pdc @{addr}") or ""

            functions.append(DecompiledFunction(
                name=name,
                address=addr,
                size=size,
                code=disasm,
                calls=calls,
                is_interesting=is_interesting,
                tags=tags,
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
