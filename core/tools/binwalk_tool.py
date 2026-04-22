"""Binwalk wrapper for firmware extraction and analysis."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from core.models import ToolResult
from core.tools.base import BaseTool

# File types that are interesting in extracted firmware
INTERESTING_EXTENSIONS = {
    ".conf", ".cfg", ".ini", ".json", ".xml", ".yaml", ".yml",
    ".key", ".pem", ".crt", ".cer", ".p12", ".pfx",
    ".sh", ".bash", ".py", ".pl", ".lua", ".php",
    ".passwd", ".shadow", ".htpasswd",
    ".db", ".sqlite", ".sqlite3",
    ".elf", ".bin", ".so", ".ko",
}

INTERESTING_FILENAMES = {
    "passwd", "shadow", "hosts", "resolv.conf", "fstab",
    "authorized_keys", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "httpd.conf", "nginx.conf", "lighttpd.conf",
    "dropbear", "sshd_config", "ssh_config",
    "wpa_supplicant.conf", "wireless",
}

CREDENTIAL_PATTERNS = [
    "password", "passwd", "secret", "apikey", "api_key",
    "token", "credential", "private_key",
]


class BinwalkTool(BaseTool):
    name = "binwalk"
    description = "Firmware extraction and filesystem analysis"
    supported_types = ["firmware", "unknown"]

    def is_available(self) -> bool:
        return shutil.which("binwalk") is not None

    def run(self, target: Path, **kwargs) -> ToolResult:
        if not self.is_available():
            return self._run_fallback(target)

        with tempfile.TemporaryDirectory(prefix="deshifro_fw_") as tmpdir:
            extract_dir = Path(tmpdir) / "extracted"

            # Run binwalk signature scan
            stdout_sig, stderr_sig, rc_sig = self._exec(
                ["binwalk", str(target)], timeout=120
            )

            # Run binwalk extraction
            stdout_ext, stderr_ext, rc_ext = self._exec(
                ["binwalk", "-e", "-C", str(extract_dir), str(target)], timeout=300
            )

            # Run entropy analysis
            stdout_ent, _, _ = self._exec(
                ["binwalk", "-E", "-J", str(target)], timeout=60
            )

            # Analyze extracted files
            extracted_files = []
            interesting_files = []
            potential_creds = []
            executables = []

            if extract_dir.exists():
                for f in extract_dir.rglob("*"):
                    if not f.is_file():
                        continue

                    rel_path = str(f.relative_to(extract_dir))
                    size = f.stat().st_size
                    extracted_files.append({"path": rel_path, "size": size})

                    # Check if interesting
                    if (f.suffix.lower() in INTERESTING_EXTENSIONS or
                            f.name.lower() in INTERESTING_FILENAMES):
                        interesting_files.append({
                            "path": rel_path,
                            "size": size,
                            "reason": "interesting filename/extension",
                        })

                        # Check for hardcoded credentials in text files
                        if size < 1_000_000:  # only check files under 1MB
                            try:
                                content = f.read_text(errors="replace").lower()
                                for pattern in CREDENTIAL_PATTERNS:
                                    if pattern in content:
                                        potential_creds.append({
                                            "path": rel_path,
                                            "pattern": pattern,
                                        })
                                        break
                            except Exception:
                                pass

                    # Detect executables by magic bytes
                    if size > 4:
                        try:
                            header = f.read_bytes()[:4]
                            if header[:4] == b"\x7fELF":
                                executables.append({
                                    "path": rel_path,
                                    "size": size,
                                    "type": "ELF",
                                })
                            elif header[:2] == b"MZ":
                                executables.append({
                                    "path": rel_path,
                                    "size": size,
                                    "type": "PE",
                                })
                        except Exception:
                            pass

            # Parse signature scan output
            signatures = []
            for line in stdout_sig.splitlines():
                line = line.strip()
                if line and not line.startswith("DECIMAL"):
                    parts = line.split(None, 2)
                    if len(parts) >= 3:
                        try:
                            signatures.append({
                                "offset": int(parts[0]),
                                "hex_offset": parts[1],
                                "description": parts[2],
                            })
                        except ValueError:
                            pass

            return ToolResult(
                tool_name=self.name,
                success=True,
                duration_seconds=0,
                raw_output=stdout_sig,
                data={
                    "signatures": signatures,
                    "total_extracted": len(extracted_files),
                    "interesting_files": interesting_files,
                    "potential_credentials": potential_creds,
                    "executables": executables,
                    "extracted_files": extracted_files[:500],  # cap list
                },
            )

    def _run_fallback(self, target: Path) -> ToolResult:
        """Basic analysis when binwalk is not installed — magic byte scanning."""
        data = target.read_bytes()

        signatures = []
        # Scan for known magic bytes
        magic_patterns = {
            b"\x7fELF": "ELF executable",
            b"MZ": "PE executable",
            b"\x1f\x8b": "gzip compressed data",
            b"BZh": "bzip2 compressed data",
            b"\xfd7zXZ": "xz compressed data",
            b"PK\x03\x04": "ZIP archive",
            b"hsqs": "SquashFS filesystem (little-endian)",
            b"sqsh": "SquashFS filesystem (big-endian)",
            b"\x68\x73\x71\x73": "SquashFS",
            b"UBI#": "UBI image",
            b"\x27\x05\x19\x56": "uImage header",
            b"ANDROID!": "Android boot image",
            b"\xd0\x0d\xfe\xed": "Device Tree Blob",
        }

        for offset in range(0, min(len(data), 10_000_000), 1):
            for magic, desc in magic_patterns.items():
                if data[offset:offset + len(magic)] == magic:
                    signatures.append({
                        "offset": offset,
                        "hex_offset": hex(offset),
                        "description": desc,
                    })

        return ToolResult(
            tool_name=self.name,
            success=True,
            duration_seconds=0,
            data={
                "source": "fallback (binwalk not installed)",
                "signatures": signatures,
                "total_extracted": 0,
                "interesting_files": [],
                "potential_credentials": [],
                "executables": [],
            },
        )
