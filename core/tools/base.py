"""Abstract base class for all tool wrappers."""

from __future__ import annotations

import subprocess
import time
from abc import ABC, abstractmethod
from pathlib import Path

from core.models import ToolResult


class BaseTool(ABC):
    """Base class that all RE tool wrappers must implement."""

    name: str = "base"
    description: str = ""
    supported_types: list[str] = []  # file types this tool can handle

    @abstractmethod
    def run(self, target: Path, **kwargs) -> ToolResult:
        """Run the tool against a target file and return structured results."""
        ...

    def is_available(self) -> bool:
        """Check if the tool is installed and accessible."""
        return True

    def _exec(self, cmd: list[str], timeout: int = 300) -> tuple[str, str, int]:
        """Execute a shell command and return (stdout, stderr, returncode)."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", f"Command timed out after {timeout}s", -1
        except FileNotFoundError:
            return "", f"Command not found: {cmd[0]}", -1

    def _timed_run(self, target: Path, **kwargs) -> ToolResult:
        """Wrapper that times the run() call and catches exceptions."""
        start = time.time()
        try:
            result = self.run(target, **kwargs)
            result.duration_seconds = time.time() - start
            return result
        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                success=False,
                duration_seconds=time.time() - start,
                error=str(e),
            )
