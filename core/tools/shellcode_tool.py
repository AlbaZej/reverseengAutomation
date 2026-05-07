"""Shellcode and x86 pattern detection — aligned with Practical Malware Analysis curriculum.

Detects common malware code patterns:
- Shellcode signatures (GetPC, egg hunters, decoder loops)
- x86 anti-debug instructions (rdtsc, int 2dh, int 3)
- Common malware code constructs (XOR decoder, API hash resolution)
- Patching indicators (NOP sleds, modified jumps)
"""

from __future__ import annotations

import re
from pathlib import Path

from core.models import Finding, SignalType, ToolResult
from core.tools.base import BaseTool


# x86 instruction patterns (raw byte sequences)
X86_PATTERNS = {
    "nop_sled": (
        re.compile(rb"\x90{16,}"),
        "16+ NOPs — possible NOP sled (shellcode jump target or padding)",
        SignalType.MEDIUM,
    ),
    "getpc_call_pop": (
        # Specifically: CALL +5 (E8 00 00 00 00) POP reg — exact short-skip variant
        # The general pattern is too noisy (modern compilers emit it for ASLR)
        re.compile(rb"\xe8\x00\x00\x00\x00[\x58-\x5f]"),
        "CALL/POP GetPC technique — possible shellcode self-relocation",
        SignalType.LOW,  # downgraded — too common in normal compiled code
    ),
    "fnstenv_getpc": (
        re.compile(rb"\xd9[\xee\xd0]\xd9\x74\x24\xf4"),
        "FNSTENV GetPC technique — shellcode self-relocation via FPU",
        SignalType.HIGH,
    ),
    "egg_hunter": (
        re.compile(rb"\x66\x81\xca\xff\x0f"),  # or x66x81xc2 (W^X scan)
        "Possible egg hunter shellcode (memory scanning)",
        SignalType.HIGH,
    ),
    "rdtsc_anti_debug": (
        re.compile(rb"\x0f\x31"),
        "RDTSC instruction — common anti-debug timing check",
        SignalType.LOW,
    ),
    "int_2dh_anti_debug": (
        re.compile(rb"\xcd\x2d"),
        "INT 2Dh — anti-debug interrupt (NtRaiseException trick)",
        SignalType.HIGH,
    ),
    "int3_breakpoints": (
        re.compile(rb"\xcc{4,}"),
        "Multiple INT 3 instructions — debugger detection or trap",
        SignalType.LOW,
    ),
    "xor_decoder_loop": (
        # mov ecx, X; xor [esi+ecx], Y; loop back
        re.compile(rb"\xb9[\x00-\xff]{4}\x80[\x30-\x37][\x00-\xff]\xe2", re.DOTALL),
        "Possible XOR decoder loop — runtime decryption of payload",
        SignalType.HIGH,
    ),
    "api_hash_resolve": (
        # ROR EDX, n followed by ADD EDX — typical API hash calculation
        re.compile(rb"\xc1\xca[\x01-\x1f]\x03"),
        "API hash resolution pattern — typical malware API hiding",
        SignalType.HIGH,
    ),
    "peb_walk": (
        re.compile(rb"\x64\xa1\x30\x00\x00\x00|\x64\x8b[\x00-\xff]\x30\x00\x00\x00", re.DOTALL),
        "PEB access (fs:[0x30]) — used for API resolution / sandbox detection",
        SignalType.MEDIUM,
    ),
    "vm_detection_cpuid": (
        re.compile(rb"\x0f\xa2"),  # CPUID
        "CPUID instruction — possible VM/sandbox detection",
        SignalType.INFO,
    ),
    "in_dx_eax_vmware": (
        re.compile(rb"\xed\x66\xa3"),  # IN dx,eax
        "IN dx,eax — VMware backdoor I/O port detection",
        SignalType.HIGH,
    ),
    "popad_then_pushad": (
        re.compile(rb"\x60\x9c"),  # PUSHAD; PUSHFD
        "PUSHAD/PUSHFD pair — typical shellcode prologue",
        SignalType.LOW,
    ),
}

# Patching/cracking indicators
PATCHING_PATTERNS = {
    "jne_to_je": "Conditional jump inversion (cracked binary?)",
    "jmp_short_nop": "Short jump replaced with NOPs",
    "patched_call": "Modified CALL — possible API redirection",
}


class ShellcodeTool(BaseTool):
    name = "shellcode"
    description = "Detect shellcode patterns and x86 anti-analysis techniques"
    supported_types = ["pe", "elf", "macho", "firmware", "unknown"]

    def is_available(self) -> bool:
        return True  # pure Python regex

    def run(self, target: Path, **kwargs) -> ToolResult:
        data = target.read_bytes()
        max_bytes = 5_000_000  # cap at 5MB to keep fast
        scan_data = data[:max_bytes]

        matches = []
        findings = []

        for pattern_name, (regex, description, severity) in X86_PATTERNS.items():
            offsets = []
            for match in regex.finditer(scan_data):
                offsets.append(match.start())
                if len(offsets) >= 100:
                    break

            if offsets:
                matches.append({
                    "pattern": pattern_name,
                    "description": description,
                    "severity": severity.value,
                    "count": len(offsets),
                    "first_offsets": offsets[:5],
                })

                # Only generate findings for high-severity patterns; low/info ones
                # are reported in match data but don't pollute the findings list
                # (avoid flooding reports with false positives from compiled code)
                if severity in (SignalType.HIGH, SignalType.CRITICAL):
                    findings.append(Finding(
                        title=f"x86 pattern: {pattern_name}",
                        description=f"{description} (found {len(offsets)}x at offsets {[hex(o) for o in offsets[:3]]})",
                        severity=severity,
                        source_tool=self.name,
                        evidence=f"First match at offset {hex(offsets[0])}",
                    ))

        # Heuristic: shellcode-likely if multiple shellcode patterns present
        shellcode_score = sum(
            1 for m in matches
            if m["pattern"] in ("getpc_call_pop", "fnstenv_getpc", "egg_hunter",
                                "xor_decoder_loop", "api_hash_resolve", "peb_walk")
        )

        if shellcode_score >= 2:
            findings.append(Finding(
                title="Likely embedded shellcode detected",
                description=f"Found {shellcode_score} shellcode-typical patterns. "
                            f"Binary likely contains injected shellcode or position-independent code.",
                severity=SignalType.HIGH,
                source_tool=self.name,
                mitre_ids=["T1055"],  # Process Injection
            ))

        return ToolResult(
            tool_name=self.name,
            success=True,
            duration_seconds=0,
            data={
                "patterns_matched": len(matches),
                "shellcode_score": shellcode_score,
                "matches": matches,
                "findings": findings,
                "scanned_bytes": len(scan_data),
                "truncated": len(data) > max_bytes,
            },
        )
