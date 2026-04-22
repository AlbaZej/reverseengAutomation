"""VirusTotal integration — check file hashes against VT database."""

from __future__ import annotations

import hashlib
import json
import os
import urllib.request
import urllib.error
from pathlib import Path

from core.models import ToolResult
from core.tools.base import BaseTool

VT_API_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalTool(BaseTool):
    name = "virustotal"
    description = "Check file hash against VirusTotal for known detections"
    supported_types = ["pe", "elf", "macho", "firmware", "unknown"]

    def __init__(self, api_key: str | None = None):
        self._api_key = api_key or os.environ.get("VT_API_KEY")

    def is_available(self) -> bool:
        return self._api_key is not None

    def run(self, target: Path, **kwargs) -> ToolResult:
        if not self._api_key:
            return ToolResult(
                tool_name=self.name,
                success=False,
                duration_seconds=0,
                error="No VirusTotal API key. Set VT_API_KEY environment variable.",
            )

        sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
        return self._lookup_hash(sha256)

    def lookup_hash(self, file_hash: str) -> ToolResult:
        """Public method to look up a hash directly."""
        if not self._api_key:
            return ToolResult(
                tool_name=self.name,
                success=False,
                duration_seconds=0,
                error="No VirusTotal API key.",
            )
        return self._lookup_hash(file_hash)

    def _lookup_hash(self, file_hash: str) -> ToolResult:
        url = f"{VT_API_BASE}/files/{file_hash}"
        req = urllib.request.Request(url, headers={"x-apikey": self._api_key})

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return ToolResult(
                    tool_name=self.name,
                    success=True,
                    duration_seconds=0,
                    data={
                        "found": False,
                        "hash": file_hash,
                        "message": "Not found in VirusTotal database — possibly novel/unknown sample",
                    },
                )
            return ToolResult(
                tool_name=self.name,
                success=False,
                duration_seconds=0,
                error=f"VirusTotal API error: HTTP {e.code}",
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                success=False,
                duration_seconds=0,
                error=f"VirusTotal request failed: {e}",
            )

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        total_engines = sum(stats.values())
        detections = stats.get("malicious", 0) + stats.get("suspicious", 0)

        # Extract engine detections
        results = attrs.get("last_analysis_results", {})
        positive_engines = {
            engine: info.get("result", "")
            for engine, info in results.items()
            if info.get("category") in ("malicious", "suspicious")
        }

        # Tags and names
        popular_threat = attrs.get("popular_threat_classification", {})
        suggested_label = popular_threat.get("suggested_threat_label", "")
        family_labels = [
            f.get("value", "")
            for f in popular_threat.get("popular_threat_name", [])
        ]

        return ToolResult(
            tool_name=self.name,
            success=True,
            duration_seconds=0,
            data={
                "found": True,
                "hash": file_hash,
                "detection_ratio": f"{detections}/{total_engines}",
                "detections": detections,
                "total_engines": total_engines,
                "threat_label": suggested_label,
                "family_labels": family_labels,
                "positive_engines": dict(list(positive_engines.items())[:20]),
                "first_seen": attrs.get("first_submission_date"),
                "last_seen": attrs.get("last_analysis_date"),
                "file_type": attrs.get("type_description", ""),
                "tags": attrs.get("tags", []),
                "names": attrs.get("names", [])[:10],
            },
        )
