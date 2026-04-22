"""String extraction and classification tool."""

from __future__ import annotations

import re
from pathlib import Path

from core.models import ExtractedString, ToolResult
from core.tools.base import BaseTool

# Patterns for classifying strings
PATTERNS = {
    "url": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "filepath_win": re.compile(r"[A-Z]:\\(?:[^\\\s\"'<>]+\\)*[^\\\s\"'<>]*"),
    "filepath_unix": re.compile(r"/(?:usr|etc|tmp|var|home|opt|bin|sbin|dev|proc)/[^\s\"'<>]+"),
    "registry": re.compile(r"HKEY_[A-Z_]+\\[^\s\"'<>]+", re.IGNORECASE),
    "crypto": re.compile(
        r"\b(?:AES|RSA|DES|RC4|SHA[0-9]*|MD5|HMAC|PBKDF|BEGIN\s+(?:RSA|DSA|EC|PRIVATE|PUBLIC|CERTIFICATE))\b",
        re.IGNORECASE,
    ),
    "debug": re.compile(r"\b(?:debug|assert|breakpoint|__FILE__|__LINE__|__func__)\b", re.IGNORECASE),
}

# Suspicious keywords that make a string "interesting"
SUSPICIOUS_KEYWORDS = {
    "cmd.exe", "powershell", "/bin/sh", "/bin/bash",
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
    "NtUnmapViewOfSection", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "wget", "curl", "socket", "connect", "recv", "send",
    "password", "passwd", "credential", "token", "secret", "apikey",
    "ransomware", "encrypt", "decrypt", "bitcoin", "wallet",
    "mutex", "pipe", "inject", "hook", "shellcode",
}

MIN_STRING_LENGTH = 4


class StringsTool(BaseTool):
    name = "strings"
    description = "Extract and classify strings from binary files"
    supported_types = ["pe", "elf", "macho", "firmware", "unknown"]

    def run(self, target: Path, min_length: int = MIN_STRING_LENGTH, **kwargs) -> ToolResult:
        data = target.read_bytes()

        strings = []
        strings.extend(self._extract_ascii(data, min_length))
        strings.extend(self._extract_utf16(data, min_length))

        # Classify each string
        for s in strings:
            s.category = self._classify(s.value)
            s.is_interesting = self._is_interesting(s.value)

        interesting_count = sum(1 for s in strings if s.is_interesting)
        categories = {}
        for s in strings:
            categories[s.category] = categories.get(s.category, 0) + 1

        return ToolResult(
            tool_name=self.name,
            success=True,
            duration_seconds=0,
            data={
                "total_strings": len(strings),
                "interesting_count": interesting_count,
                "categories": categories,
                "strings": strings,
            },
        )

    def _extract_ascii(self, data: bytes, min_length: int) -> list[ExtractedString]:
        """Extract printable ASCII strings."""
        strings = []
        current = []
        start_offset = 0

        for i, byte in enumerate(data):
            if 0x20 <= byte <= 0x7E:
                if not current:
                    start_offset = i
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(ExtractedString(
                        value="".join(current),
                        offset=start_offset,
                        encoding="ascii",
                        category="other",
                    ))
                current = []

        if len(current) >= min_length:
            strings.append(ExtractedString(
                value="".join(current),
                offset=start_offset,
                encoding="ascii",
                category="other",
            ))

        return strings

    def _extract_utf16(self, data: bytes, min_length: int) -> list[ExtractedString]:
        """Extract UTF-16 LE strings (common in Windows PE files)."""
        strings = []
        current = []
        start_offset = 0

        i = 0
        while i < len(data) - 1:
            low, high = data[i], data[i + 1]
            if high == 0 and 0x20 <= low <= 0x7E:
                if not current:
                    start_offset = i
                current.append(chr(low))
                i += 2
            else:
                if len(current) >= min_length:
                    strings.append(ExtractedString(
                        value="".join(current),
                        offset=start_offset,
                        encoding="utf-16-le",
                        category="other",
                    ))
                current = []
                i += 1

        if len(current) >= min_length:
            strings.append(ExtractedString(
                value="".join(current),
                offset=start_offset,
                encoding="utf-16-le",
                category="other",
            ))

        return strings

    def _classify(self, value: str) -> str:
        """Classify a string into a category."""
        for category, pattern in PATTERNS.items():
            if pattern.search(value):
                if category.startswith("filepath"):
                    return "filepath"
                return category
        return "other"

    def _is_interesting(self, value: str) -> bool:
        """Check if a string is security-relevant."""
        lower = value.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword.lower() in lower:
                return True
        return False
