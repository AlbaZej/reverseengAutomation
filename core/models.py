"""Domain models for Deshifro reverse engineering platform."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class FileType(str, Enum):
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    PCAP = "pcap"
    FIRMWARE = "firmware"
    UNKNOWN = "unknown"


class Architecture(str, Enum):
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    UNKNOWN = "unknown"


class SignalType(str, Enum):
    """Severity/confidence for findings."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class FileInfo:
    """Basic file metadata detected during triage."""
    path: Path
    size: int
    md5: str
    sha256: str
    file_type: FileType
    mime_type: str
    architecture: Architecture = Architecture.UNKNOWN
    is_packed: bool = False
    packer_name: str | None = None
    compiler: str | None = None


@dataclass
class ExtractedString:
    """A string extracted from a binary with classification."""
    value: str
    offset: int
    encoding: str  # "ascii" | "utf-16-le" | "utf-16-be"
    category: str  # "url" | "ip" | "filepath" | "registry" | "crypto" | "debug" | "other"
    is_interesting: bool = False


@dataclass
class EntropyRegion:
    """A region of the file with its entropy value."""
    offset: int
    size: int
    entropy: float  # 0.0 to 8.0 (byte-level Shannon entropy)
    label: str  # "normal" | "packed" | "encrypted" | "compressed" | "empty"


@dataclass
class YaraMatch:
    """A YARA rule match."""
    rule_name: str
    namespace: str
    tags: list[str]
    strings_matched: list[tuple[int, str, bytes]]  # (offset, identifier, data)
    meta: dict


@dataclass
class ImportedFunction:
    """An imported function from a binary."""
    library: str
    name: str
    ordinal: int | None = None
    is_suspicious: bool = False
    category: str = ""  # "network" | "file" | "process" | "crypto" | "registry" | "anti-debug"


@dataclass
class ExportedFunction:
    """An exported function from a binary."""
    name: str
    address: int
    ordinal: int | None = None


@dataclass
class DecompiledFunction:
    """A decompiled function from Ghidra or radare2."""
    name: str
    address: int
    size: int
    code: str  # decompiled C-like code
    calling_convention: str = ""
    calls: list[str] = field(default_factory=list)  # functions this calls
    called_by: list[str] = field(default_factory=list)
    is_interesting: bool = False
    tags: list[str] = field(default_factory=list)  # "crypto", "network", "anti-debug", etc.


@dataclass
class IOC:
    """An Indicator of Compromise extracted from analysis."""
    type: str  # "ip" | "domain" | "url" | "hash" | "mutex" | "registry" | "filepath" | "email"
    value: str
    context: str  # where/how it was found
    confidence: float = 0.0  # 0.0 to 1.0


@dataclass
class Finding:
    """A single finding from any analysis stage."""
    title: str
    description: str
    severity: SignalType
    source_tool: str  # which tool produced this finding
    evidence: str = ""  # supporting data
    mitre_ids: list[str] = field(default_factory=list)  # e.g. ["T1059.001"]


@dataclass
class ToolResult:
    """Result from running a single tool."""
    tool_name: str
    success: bool
    duration_seconds: float
    raw_output: str = ""
    error: str = ""
    data: dict = field(default_factory=dict)  # tool-specific structured output


@dataclass
class AnalysisReport:
    """Complete analysis report combining all tool results."""
    file_info: FileInfo
    strings: list[ExtractedString] = field(default_factory=list)
    entropy_regions: list[EntropyRegion] = field(default_factory=list)
    yara_matches: list[YaraMatch] = field(default_factory=list)
    imports: list[ImportedFunction] = field(default_factory=list)
    exports: list[ExportedFunction] = field(default_factory=list)
    functions: list[DecompiledFunction] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)
    verdict: str = "unknown"  # "clean" | "suspicious" | "malicious"
    verdict_confidence: float = 0.0
