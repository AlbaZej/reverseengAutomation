"""Archive extraction tool — handles ZIP, RAR, 7z, TAR with malware password fallback."""

from __future__ import annotations

import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path

from core.models import ToolResult
from core.tools.base import BaseTool

# Common passwords used by malware sample sharing platforms
MALWARE_PASSWORDS = [
    "infected",
    "malware",
    "virus",
    "any.run",
    "abuse.ch",
]

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz"}


def is_archive(path: Path) -> bool:
    """Detect archive files by magic bytes or extension."""
    if path.suffix.lower() in ARCHIVE_EXTENSIONS:
        return True
    try:
        header = path.read_bytes()[:8]
    except Exception:
        return False
    return (
        header[:4] == b"PK\x03\x04"  # ZIP
        or header[:4] == b"Rar!"      # RAR
        or header[:6] == b"7z\xbc\xaf\x27\x1c"  # 7z
        or header[:2] == b"\x1f\x8b"  # gzip
        or header[:3] == b"BZh"        # bzip2
        or header[:6] == b"\xfd7zXZ\x00"  # xz
        or _looks_like_tar(path)
    )


def _looks_like_tar(path: Path) -> bool:
    """Tar magic is at offset 257."""
    try:
        with path.open("rb") as f:
            f.seek(257)
            magic = f.read(8)
        return magic[:5] in (b"ustar", b"\x00ustar")
    except Exception:
        return False


class ArchiveTool(BaseTool):
    name = "archive"
    description = "Extract archives (ZIP/TAR/etc.) with malware-password fallback"
    supported_types = ["unknown", "firmware"]

    def is_available(self) -> bool:
        return True  # uses stdlib only for ZIP/TAR

    def run(self, target: Path, **kwargs) -> ToolResult:
        if not is_archive(target):
            return ToolResult(
                tool_name=self.name,
                success=False,
                duration_seconds=0,
                error="Not a recognized archive",
            )

        extract_dir = Path(tempfile.mkdtemp(prefix="deshifro_archive_"))

        try:
            extracted = self._extract(target, extract_dir)

            # List all extracted files with metadata
            files = []
            for f in extract_dir.rglob("*"):
                if f.is_file():
                    files.append({
                        "path": str(f.relative_to(extract_dir)),
                        "abs_path": str(f),
                        "size": f.stat().st_size,
                    })

            return ToolResult(
                tool_name=self.name,
                success=True,
                duration_seconds=0,
                data={
                    "archive_format": self._detect_format(target),
                    "extract_dir": str(extract_dir),
                    "password_used": extracted.get("password"),
                    "file_count": len(files),
                    "files": files,
                },
            )
        except Exception as e:
            shutil.rmtree(extract_dir, ignore_errors=True)
            return ToolResult(
                tool_name=self.name,
                success=False,
                duration_seconds=0,
                error=f"Extraction failed: {e}",
            )

    def _detect_format(self, path: Path) -> str:
        header = path.read_bytes()[:8]
        if header[:4] == b"PK\x03\x04":
            return "zip"
        if header[:4] == b"Rar!":
            return "rar"
        if header[:6] == b"7z\xbc\xaf\x27\x1c":
            return "7z"
        if header[:2] == b"\x1f\x8b":
            return "gzip"
        if header[:3] == b"BZh":
            return "bzip2"
        if _looks_like_tar(path):
            return "tar"
        return "unknown"

    def _extract(self, archive: Path, dest: Path) -> dict:
        """Extract archive to destination, trying common malware passwords if needed."""
        fmt = self._detect_format(archive)

        if fmt == "zip":
            return self._extract_zip(archive, dest)
        if fmt in ("tar", "gzip", "bzip2"):
            return self._extract_tar(archive, dest)
        if fmt == "7z":
            return self._extract_7z(archive, dest)
        if fmt == "rar":
            return self._extract_rar(archive, dest)
        raise ValueError(f"Unsupported archive format: {fmt}")

    def _extract_zip(self, archive: Path, dest: Path) -> dict:
        # Try without password first
        with zipfile.ZipFile(archive) as zf:
            try:
                zf.extractall(dest)
                return {"password": None}
            except RuntimeError:
                # Encrypted — try common malware passwords
                for pw in MALWARE_PASSWORDS:
                    try:
                        zf.extractall(dest, pwd=pw.encode())
                        return {"password": pw}
                    except (RuntimeError, zipfile.BadZipFile):
                        # Reset destination since partial extraction may have happened
                        for f in dest.iterdir():
                            if f.is_file():
                                f.unlink()
                            elif f.is_dir():
                                shutil.rmtree(f)
                        continue
                raise RuntimeError(f"ZIP is encrypted; tried passwords: {MALWARE_PASSWORDS}")

    def _extract_tar(self, archive: Path, dest: Path) -> dict:
        with tarfile.open(archive, "r:*") as tf:
            # Filter to prevent path traversal (Python 3.12+)
            try:
                tf.extractall(dest, filter="data")
            except TypeError:
                tf.extractall(dest)
        return {"password": None}

    def _extract_7z(self, archive: Path, dest: Path) -> dict:
        if shutil.which("7z"):
            for pw in [None, *MALWARE_PASSWORDS]:
                cmd = ["7z", "x", "-y", f"-o{dest}", str(archive)]
                if pw:
                    cmd.append(f"-p{pw}")
                _, _, rc = self._exec(cmd, timeout=120)
                if rc == 0:
                    return {"password": pw}
            raise RuntimeError("7z extraction failed with all passwords")

        # Fall back to py7zr if installed
        try:
            import py7zr
            for pw in [None, *MALWARE_PASSWORDS]:
                try:
                    with py7zr.SevenZipFile(archive, mode="r", password=pw) as z:
                        z.extractall(dest)
                    return {"password": pw}
                except Exception:
                    continue
            raise RuntimeError("py7zr extraction failed with all passwords")
        except ImportError:
            raise RuntimeError("Need 7z CLI or `pip install py7zr` for 7z archives")

    def _extract_rar(self, archive: Path, dest: Path) -> dict:
        if not shutil.which("unrar") and not shutil.which("7z"):
            raise RuntimeError("Need unrar or 7z installed for RAR archives")

        cmd = (["unrar", "x", "-y", str(archive), str(dest) + "/"]
               if shutil.which("unrar")
               else ["7z", "x", "-y", f"-o{dest}", str(archive)])

        for pw in [None, *MALWARE_PASSWORDS]:
            cmd_with_pw = cmd.copy()
            if pw:
                cmd_with_pw.insert(-1 if "unrar" in cmd[0] else len(cmd), f"-p{pw}")
            _, _, rc = self._exec(cmd_with_pw, timeout=120)
            if rc == 0:
                return {"password": pw}
        raise RuntimeError("RAR extraction failed with all passwords")
