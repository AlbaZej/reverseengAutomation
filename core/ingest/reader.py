"""File type detection and metadata extraction — the triage stage."""

from __future__ import annotations

import hashlib
from pathlib import Path

from core.models import Architecture, FileInfo, FileType


def detect_file_type(data: bytes) -> FileType:
    """Detect file type from magic bytes."""
    if data[:2] == b"MZ":
        return FileType.PE
    if data[:4] == b"\x7fELF":
        return FileType.ELF
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                     b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return FileType.MACHO
    if data[:4] == b"\xd4\xc3\xb2\xa1" or data[:4] == b"\xa1\xb2\xc3\xd4":
        return FileType.PCAP
    if data[:4] == b"\x0a\x0d\x0d\x0a":  # pcapng
        return FileType.PCAP
    return FileType.UNKNOWN


def detect_architecture(data: bytes, file_type: FileType) -> Architecture:
    """Detect CPU architecture from file headers."""
    if file_type == FileType.PE and len(data) > 0x40:
        # PE: read Machine field from COFF header
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
        if len(data) > pe_offset + 6:
            machine = int.from_bytes(data[pe_offset + 4:pe_offset + 6], "little")
            return {
                0x014C: Architecture.X86,
                0x8664: Architecture.X86_64,
                0x01C0: Architecture.ARM,
                0xAA64: Architecture.ARM64,
            }.get(machine, Architecture.UNKNOWN)

    if file_type == FileType.ELF and len(data) > 0x13:
        # ELF: e_machine at offset 0x12
        machine = int.from_bytes(data[0x12:0x14], "little")
        return {
            0x03: Architecture.X86,
            0x3E: Architecture.X86_64,
            0x28: Architecture.ARM,
            0xB7: Architecture.ARM64,
            0x08: Architecture.MIPS,
        }.get(machine, Architecture.UNKNOWN)

    return Architecture.UNKNOWN


def get_mime_type(data: bytes) -> str:
    """Get MIME type from magic bytes (basic fallback)."""
    type_map = {
        FileType.PE: "application/x-dosexec",
        FileType.ELF: "application/x-elf",
        FileType.MACHO: "application/x-mach-binary",
        FileType.PCAP: "application/vnd.tcpdump.pcap",
    }
    ft = detect_file_type(data)
    return type_map.get(ft, "application/octet-stream")


def triage_file(path: Path) -> FileInfo:
    """Quick triage: detect file type, compute hashes, extract basic metadata."""
    data = path.read_bytes()

    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    file_type = detect_file_type(data)
    arch = detect_architecture(data, file_type)
    mime = get_mime_type(data)

    return FileInfo(
        path=path,
        size=len(data),
        md5=md5,
        sha256=sha256,
        file_type=file_type,
        mime_type=mime,
        architecture=arch,
    )
