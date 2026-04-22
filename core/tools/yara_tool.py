"""YARA rule matching tool."""

from __future__ import annotations

from pathlib import Path

from core.models import ToolResult, YaraMatch
from core.tools.base import BaseTool

# Built-in rules for common malware indicators (no external rule files needed for MVP)
BUILTIN_RULES = r"""
rule suspicious_strings {
    meta:
        description = "Contains suspicious strings commonly found in malware"
        severity = "medium"
    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell" nocase
        $s3 = "CreateRemoteThread"
        $s4 = "VirtualAllocEx"
        $s5 = "WriteProcessMemory"
        $s6 = "NtUnmapViewOfSection"
        $s7 = "IsDebuggerPresent"
        $s8 = "CheckRemoteDebuggerPresent"
        $s9 = "ShellExecute" nocase
        $s10 = "WScript.Shell" nocase
    condition:
        3 of them
}

rule anti_debug_techniques {
    meta:
        description = "Uses anti-debugging techniques"
        severity = "high"
        mitre = "T1622"
    strings:
        $a1 = "IsDebuggerPresent"
        $a2 = "CheckRemoteDebuggerPresent"
        $a3 = "NtQueryInformationProcess"
        $a4 = "OutputDebugString"
        $a5 = "GetTickCount"
        $a6 = "QueryPerformanceCounter"
        $a7 = "rdtsc"
        $a8 = "int 2dh"
    condition:
        2 of them
}

rule process_injection {
    meta:
        description = "Indicators of process injection"
        severity = "critical"
        mitre = "T1055"
    strings:
        $i1 = "VirtualAllocEx"
        $i2 = "WriteProcessMemory"
        $i3 = "CreateRemoteThread"
        $i4 = "NtMapViewOfSection"
        $i5 = "QueueUserAPC"
        $i6 = "SetThreadContext"
    condition:
        ($i1 and $i2 and $i3) or ($i4) or ($i5 and $i6)
}

rule crypto_indicators {
    meta:
        description = "Contains cryptographic constants or API usage"
        severity = "medium"
        mitre = "T1027"
    strings:
        $c1 = "CryptEncrypt"
        $c2 = "CryptDecrypt"
        $c3 = "BCryptEncrypt"
        $c4 = "AES" nocase
        $c5 = "RSA" nocase
        $c6 = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }  // AES S-box
        $c7 = { 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB }  // AES S-box cont
    condition:
        2 of them
}

rule network_indicators {
    meta:
        description = "Contains network communication indicators"
        severity = "medium"
        mitre = "T1071"
    strings:
        $n1 = "WSAStartup"
        $n2 = "InternetOpen" nocase
        $n3 = "HttpSendRequest" nocase
        $n4 = "URLDownloadToFile" nocase
        $n5 = "WinHttpOpen"
        $n6 = "socket" nocase
        $n7 = "connect" nocase
        $n8 = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
    condition:
        3 of them
}

rule persistence_indicators {
    meta:
        description = "Indicators of persistence mechanisms"
        severity = "high"
        mitre = "T1547"
    strings:
        $p1 = "CurrentVersion\\\\Run" nocase
        $p2 = "CurrentVersion\\\\RunOnce" nocase
        $p3 = "schtasks" nocase
        $p4 = "RegSetValueEx" nocase
        $p5 = "CreateService" nocase
        $p6 = "HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion" nocase
    condition:
        2 of them
}

rule packed_binary {
    meta:
        description = "Binary appears to be packed or obfuscated"
        severity = "medium"
        mitre = "T1027.002"
    strings:
        $upx = "UPX!" ascii
        $aspack = ".aspack" ascii
        $themida = ".themida" ascii
        $vmprotect = ".vmp0" ascii
        $enigma = ".enigma" ascii
    condition:
        any of them
}
"""


class YaraTool(BaseTool):
    name = "yara"
    description = "Scan files with YARA rules for malware indicators"
    supported_types = ["pe", "elf", "macho", "firmware", "unknown"]

    def __init__(self, extra_rules_dir: Path | None = None):
        self._extra_rules_dir = extra_rules_dir
        self._rules = None

    def is_available(self) -> bool:
        try:
            import yara  # noqa: F401
            return True
        except ImportError:
            return False

    def _compile_rules(self):
        """Compile YARA rules (lazy, cached)."""
        import yara

        sources = {"builtin": BUILTIN_RULES}

        if self._extra_rules_dir and self._extra_rules_dir.is_dir():
            for rule_file in self._extra_rules_dir.glob("*.yar"):
                sources[rule_file.stem] = rule_file.read_text()

        self._rules = yara.compile(sources=sources)

    def run(self, target: Path, **kwargs) -> ToolResult:
        if not self.is_available():
            return ToolResult(
                tool_name=self.name,
                success=False,
                duration_seconds=0,
                error="yara-python is not installed. Install with: pip install yara-python",
            )

        if self._rules is None:
            self._compile_rules()

        matches = self._rules.match(str(target))

        yara_matches = []
        for match in matches:
            yara_matches.append(YaraMatch(
                rule_name=match.rule,
                namespace=match.namespace,
                tags=list(match.tags),
                strings_matched=[
                    (s.instances[0].offset if s.instances else 0, s.identifier, s.instances[0].matched_data if s.instances else b"")
                    for s in match.strings
                ],
                meta=dict(match.meta),
            ))

        return ToolResult(
            tool_name=self.name,
            success=True,
            duration_seconds=0,
            data={
                "match_count": len(yara_matches),
                "matches": yara_matches,
                "rule_names": [m.rule_name for m in yara_matches],
            },
        )
