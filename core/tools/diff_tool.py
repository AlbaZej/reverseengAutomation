"""Binary diff/comparison tool — find differences between two binaries."""

from __future__ import annotations

import hashlib
from pathlib import Path

import numpy as np

from core.models import ToolResult
from core.tools.base import BaseTool


class DiffTool(BaseTool):
    name = "diff"
    description = "Compare two binaries — byte-level diff, section changes, string differences"
    supported_types = ["pe", "elf", "macho", "firmware", "unknown"]

    def run(self, target: Path, **kwargs) -> ToolResult:
        target2 = kwargs.get("target2")
        if not target2:
            return ToolResult(
                tool_name=self.name,
                success=False,
                duration_seconds=0,
                error="Second target file required (target2 kwarg)",
            )

        target2 = Path(target2)
        if not target2.exists():
            return ToolResult(
                tool_name=self.name,
                success=False,
                duration_seconds=0,
                error=f"Second file not found: {target2}",
            )

        data1 = target.read_bytes()
        data2 = target2.read_bytes()

        # Basic metadata comparison
        meta1 = {
            "size": len(data1),
            "md5": hashlib.md5(data1).hexdigest(),
            "sha256": hashlib.sha256(data1).hexdigest(),
        }
        meta2 = {
            "size": len(data2),
            "md5": hashlib.md5(data2).hexdigest(),
            "sha256": hashlib.sha256(data2).hexdigest(),
        }

        identical = meta1["sha256"] == meta2["sha256"]
        if identical:
            return ToolResult(
                tool_name=self.name,
                success=True,
                duration_seconds=0,
                data={
                    "identical": True,
                    "file1": {"name": target.name, **meta1},
                    "file2": {"name": target2.name, **meta2},
                },
            )

        # Byte-level diff
        diff_regions = self._find_diff_regions(data1, data2)

        # String diff
        strings1 = set(self._extract_strings(data1))
        strings2 = set(self._extract_strings(data2))
        added_strings = sorted(strings2 - strings1)
        removed_strings = sorted(strings1 - strings2)

        # Section comparison (PE)
        sections1 = self._get_sections(data1)
        sections2 = self._get_sections(data2)
        section_changes = self._compare_sections(sections1, sections2)

        # Similarity score
        min_len = min(len(data1), len(data2))
        if min_len > 0:
            arr1 = np.frombuffer(data1[:min_len], dtype=np.uint8)
            arr2 = np.frombuffer(data2[:min_len], dtype=np.uint8)
            matching_bytes = int(np.sum(arr1 == arr2))
            similarity = matching_bytes / max(len(data1), len(data2))
        else:
            similarity = 0.0

        return ToolResult(
            tool_name=self.name,
            success=True,
            duration_seconds=0,
            data={
                "identical": False,
                "similarity": round(similarity, 4),
                "file1": {"name": target.name, **meta1},
                "file2": {"name": target2.name, **meta2},
                "size_diff": len(data2) - len(data1),
                "diff_region_count": len(diff_regions),
                "diff_regions": diff_regions[:100],  # cap
                "added_strings": added_strings[:50],
                "removed_strings": removed_strings[:50],
                "common_string_count": len(strings1 & strings2),
                "section_changes": section_changes,
            },
        )

    def _find_diff_regions(self, data1: bytes, data2: bytes) -> list[dict]:
        """Find contiguous regions that differ between the two files."""
        regions = []
        min_len = min(len(data1), len(data2))

        in_diff = False
        diff_start = 0

        for i in range(min_len):
            if data1[i] != data2[i]:
                if not in_diff:
                    diff_start = i
                    in_diff = True
            else:
                if in_diff:
                    regions.append({
                        "offset": diff_start,
                        "size": i - diff_start,
                        "hex_offset": hex(diff_start),
                    })
                    in_diff = False

        if in_diff:
            regions.append({
                "offset": diff_start,
                "size": min_len - diff_start,
                "hex_offset": hex(diff_start),
            })

        # If files are different lengths, add trailing region
        if len(data1) != len(data2):
            regions.append({
                "offset": min_len,
                "size": abs(len(data1) - len(data2)),
                "hex_offset": hex(min_len),
                "note": "size difference",
            })

        return regions

    def _extract_strings(self, data: bytes, min_length: int = 6) -> list[str]:
        """Quick ASCII string extraction for comparison."""
        strings = []
        current = []
        for byte in data:
            if 0x20 <= byte <= 0x7E:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append("".join(current))
                current = []
        if len(current) >= min_length:
            strings.append("".join(current))
        return strings

    def _get_sections(self, data: bytes) -> list[dict]:
        """Extract PE section headers if applicable."""
        if data[:2] != b"MZ" or len(data) < 0x40:
            return []

        try:
            import pefile
            pe = pefile.PE(data=data)
            sections = []
            for s in pe.sections:
                sections.append({
                    "name": s.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
                    "virtual_size": s.Misc_VirtualSize,
                    "raw_size": s.SizeOfRawData,
                    "entropy": round(s.get_entropy(), 4),
                    "md5": hashlib.md5(s.get_data()).hexdigest(),
                })
            pe.close()
            return sections
        except Exception:
            return []

    def _compare_sections(self, sections1: list[dict], sections2: list[dict]) -> list[dict]:
        """Compare sections between two PE files."""
        changes = []
        names1 = {s["name"]: s for s in sections1}
        names2 = {s["name"]: s for s in sections2}

        all_names = set(names1.keys()) | set(names2.keys())
        for name in sorted(all_names):
            s1 = names1.get(name)
            s2 = names2.get(name)

            if s1 and not s2:
                changes.append({"section": name, "change": "removed"})
            elif s2 and not s1:
                changes.append({"section": name, "change": "added"})
            elif s1 and s2 and s1["md5"] != s2["md5"]:
                changes.append({
                    "section": name,
                    "change": "modified",
                    "size_diff": s2["raw_size"] - s1["raw_size"],
                    "entropy_diff": round(s2["entropy"] - s1["entropy"], 4),
                })

        return changes
