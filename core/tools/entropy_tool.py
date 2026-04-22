"""Entropy analysis tool for detecting packed/encrypted sections."""

from __future__ import annotations

import math
from pathlib import Path

import numpy as np

from core.models import EntropyRegion, ToolResult
from core.tools.base import BaseTool

# Entropy thresholds (byte-level Shannon entropy, max = 8.0)
THRESHOLD_EMPTY = 0.5
THRESHOLD_NORMAL = 6.0
THRESHOLD_PACKED = 7.0
THRESHOLD_ENCRYPTED = 7.5  # near-random data

DEFAULT_BLOCK_SIZE = 256


class EntropyTool(BaseTool):
    name = "entropy"
    description = "Compute entropy map to detect packed/encrypted/compressed regions"
    supported_types = ["pe", "elf", "macho", "firmware", "unknown"]

    def run(self, target: Path, block_size: int = DEFAULT_BLOCK_SIZE, **kwargs) -> ToolResult:
        data = target.read_bytes()

        if not data:
            return ToolResult(
                tool_name=self.name,
                success=False,
                duration_seconds=0,
                error="Empty file",
            )

        overall_entropy = self._shannon_entropy(data)
        regions = self._compute_regions(data, block_size)
        merged = self._merge_adjacent(regions)

        high_entropy_pct = sum(
            r.size for r in merged if r.label in ("packed", "encrypted")
        ) / len(data) * 100

        return ToolResult(
            tool_name=self.name,
            success=True,
            duration_seconds=0,
            data={
                "overall_entropy": round(overall_entropy, 4),
                "file_size": len(data),
                "block_size": block_size,
                "regions": merged,
                "high_entropy_percentage": round(high_entropy_pct, 2),
                "likely_packed": high_entropy_pct > 50,
            },
        )

    def _shannon_entropy(self, data: bytes) -> float:
        """Compute byte-level Shannon entropy (0.0 to 8.0)."""
        if not data:
            return 0.0

        counts = np.zeros(256, dtype=np.int64)
        for byte in data:
            counts[byte] += 1

        probs = counts[counts > 0] / len(data)
        return -float(np.sum(probs * np.log2(probs)))

    def _label_entropy(self, entropy: float) -> str:
        """Label an entropy value."""
        if entropy < THRESHOLD_EMPTY:
            return "empty"
        if entropy < THRESHOLD_NORMAL:
            return "normal"
        if entropy < THRESHOLD_PACKED:
            return "compressed"
        if entropy < THRESHOLD_ENCRYPTED:
            return "packed"
        return "encrypted"

    def _compute_regions(self, data: bytes, block_size: int) -> list[EntropyRegion]:
        """Split file into blocks and compute entropy for each."""
        regions = []
        for offset in range(0, len(data), block_size):
            block = data[offset:offset + block_size]
            entropy = self._shannon_entropy(block)
            regions.append(EntropyRegion(
                offset=offset,
                size=len(block),
                entropy=round(entropy, 4),
                label=self._label_entropy(entropy),
            ))
        return regions

    def _merge_adjacent(self, regions: list[EntropyRegion]) -> list[EntropyRegion]:
        """Merge adjacent regions with the same label."""
        if not regions:
            return []

        merged = [regions[0]]
        for region in regions[1:]:
            prev = merged[-1]
            if prev.label == region.label:
                # Merge: extend size, average entropy
                total_size = prev.size + region.size
                prev.entropy = round(
                    (prev.entropy * prev.size + region.entropy * region.size) / total_size, 4
                )
                prev.size = total_size
            else:
                merged.append(region)

        return merged
