"""Deshifro CLI — reverse engineering automation from the command line."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(
    name="deshifro",
    help="Deshifro — Cybersecurity reverse engineering automation platform",
    no_args_is_help=True,
)
console = Console()


@app.command()
def analyze(
    target: Path = typer.Argument(..., help="Path to the file to analyze", exists=True),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output report path"),
    format: str = typer.Option("text", "-f", "--format", help="Output format: text, json"),
    quick: bool = typer.Option(False, "-q", "--quick", help="Quick scan (skip Ghidra)"),
    type: Optional[str] = typer.Option(None, "-t", "--type", help="Force type: binary, firmware, protocol"),
):
    """Analyze a file with the full RE pipeline."""
    console.print(Panel.fit(
        f"[bold blue]DESHIFRO[/bold blue] — Analyzing [bold]{target.name}[/bold]",
        border_style="blue",
    ))

    with console.status("[bold green]Running analysis pipeline..."):
        from core.analyzers.auto_analyzer import auto_analyze
        report = auto_analyze(target, quick=quick)

    from core.report.generator import to_json, to_summary

    if format == "json":
        json_output = to_json(report)
        if output:
            output.write_text(json_output)
            console.print(f"\n[green]Report saved to {output}[/green]")
        else:
            console.print(json_output)
    else:
        summary = to_summary(report)
        console.print(summary)
        if output:
            output.write_text(summary)
            console.print(f"\n[green]Report saved to {output}[/green]")

    verdict_colors = {"clean": "green", "suspicious": "yellow", "malicious": "red"}
    color = verdict_colors.get(report.verdict, "white")
    console.print(f"\n  Verdict: [{color} bold]{report.verdict.upper()}[/{color} bold] "
                  f"(confidence: {report.verdict_confidence:.0%})\n")


@app.command()
def scan(
    target: Path = typer.Argument(..., help="Path to the file to scan", exists=True),
):
    """Quick triage — strings, entropy, YARA only (no Ghidra/r2)."""
    console.print(Panel.fit(
        f"[bold cyan]DESHIFRO SCAN[/bold cyan] — Quick triage of [bold]{target.name}[/bold]",
        border_style="cyan",
    ))

    with console.status("[bold green]Scanning..."):
        from core.analyzers.auto_analyzer import auto_analyze
        report = auto_analyze(target, quick=True)

    fi = report.file_info
    table = Table(title="File Info", show_header=False, border_style="dim")
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("File", fi.path.name)
    table.add_row("Type", f"{fi.file_type.value.upper()} ({fi.architecture.value})")
    table.add_row("Size", f"{fi.size:,} bytes")
    table.add_row("MD5", fi.md5)
    table.add_row("SHA256", fi.sha256)
    table.add_row("Packed", "Yes" if fi.is_packed else "No")
    console.print(table)

    if report.findings:
        console.print(f"\n[bold]Findings ({len(report.findings)}):[/bold]")
        for f in report.findings:
            severity_colors = {
                "info": "blue", "low": "green", "medium": "yellow",
                "high": "red", "critical": "bold red",
            }
            color = severity_colors.get(f.severity.value, "white")
            console.print(f"  [{color}][{f.severity.value.upper():8s}][/{color}] {f.title}")

    verdict_colors = {"clean": "green", "suspicious": "yellow", "malicious": "red"}
    color = verdict_colors.get(report.verdict, "white")
    console.print(f"\n  Verdict: [{color} bold]{report.verdict.upper()}[/{color} bold]\n")


@app.command()
def diff(
    file1: Path = typer.Argument(..., help="First binary", exists=True),
    file2: Path = typer.Argument(..., help="Second binary", exists=True),
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output JSON path"),
):
    """Compare two binaries — byte diff, string changes, section comparison."""
    console.print(Panel.fit(
        f"[bold magenta]DESHIFRO DIFF[/bold magenta] — "
        f"[bold]{file1.name}[/bold] vs [bold]{file2.name}[/bold]",
        border_style="magenta",
    ))

    with console.status("[bold green]Comparing..."):
        from core.tools.diff_tool import DiffTool
        tool = DiffTool()
        result = tool._timed_run(file1, target2=file2)

    if not result.success:
        console.print(f"[red]Error: {result.error}[/red]")
        raise typer.Exit(1)

    data = result.data

    if data.get("identical"):
        console.print("\n  [green]Files are identical[/green]\n")
        return

    # Summary table
    table = Table(title="Comparison Summary", show_header=False, border_style="dim")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Similarity", f"{data['similarity']:.1%}")
    table.add_row("Size diff", f"{data['size_diff']:+,} bytes")
    table.add_row("Changed regions", str(data["diff_region_count"]))
    table.add_row("Added strings", str(len(data.get("added_strings", []))))
    table.add_row("Removed strings", str(len(data.get("removed_strings", []))))
    console.print(table)

    # Section changes
    if data.get("section_changes"):
        console.print("\n[bold]Section Changes:[/bold]")
        for sc in data["section_changes"]:
            change_color = {"added": "green", "removed": "red", "modified": "yellow"}
            color = change_color.get(sc["change"], "white")
            console.print(f"  [{color}]{sc['change'].upper():10s}[/{color}] {sc['section']}")

    # String changes
    added = data.get("added_strings", [])
    removed = data.get("removed_strings", [])
    if added:
        console.print(f"\n[bold]Added strings ({len(added)}):[/bold]")
        for s in added[:15]:
            console.print(f"  [green]+[/green] {s}")
        if len(added) > 15:
            console.print(f"  ... and {len(added) - 15} more")

    if removed:
        console.print(f"\n[bold]Removed strings ({len(removed)}):[/bold]")
        for s in removed[:15]:
            console.print(f"  [red]-[/red] {s}")
        if len(removed) > 15:
            console.print(f"  ... and {len(removed) - 15} more")

    if output:
        import json
        output.write_text(json.dumps(data, indent=2))
        console.print(f"\n[green]Full diff saved to {output}[/green]")

    console.print()


@app.command()
def vt(
    target: Path = typer.Argument(None, help="File to check (or use --hash)", exists=True),
    hash: Optional[str] = typer.Option(None, "--hash", "-H", help="Check a hash directly"),
):
    """Check a file or hash against VirusTotal."""
    from core.tools.virustotal import VirusTotalTool
    tool = VirusTotalTool()

    if not tool.is_available():
        console.print("[red]VT_API_KEY environment variable not set[/red]")
        raise typer.Exit(1)

    with console.status("[bold green]Querying VirusTotal..."):
        if hash:
            result = tool.lookup_hash(hash)
        elif target:
            result = tool._timed_run(target)
        else:
            console.print("[red]Provide a file path or --hash[/red]")
            raise typer.Exit(1)

    if not result.success:
        console.print(f"[red]{result.error}[/red]")
        raise typer.Exit(1)

    data = result.data
    if not data.get("found"):
        console.print(f"\n  [yellow]Not found in VirusTotal[/yellow] — {data.get('message', '')}\n")
        return

    det = data["detections"]
    total = data["total_engines"]
    ratio_color = "green" if det == 0 else "yellow" if det < 5 else "red"

    console.print(f"\n  Detection: [{ratio_color}]{det}/{total}[/{ratio_color}]")
    if data.get("threat_label"):
        console.print(f"  Threat:    {data['threat_label']}")
    if data.get("family_labels"):
        console.print(f"  Families:  {', '.join(data['family_labels'][:5])}")
    if data.get("tags"):
        console.print(f"  Tags:      {', '.join(data['tags'][:10])}")
    console.print()


@app.command()
def tools():
    """List available analysis tools and their status."""
    from core.tools.binwalk_tool import BinwalkTool
    from core.tools.die_tool import DieTool
    from core.tools.diff_tool import DiffTool
    from core.tools.entropy_tool import EntropyTool
    from core.tools.frida_tool import FridaTool
    from core.tools.ghidra import GhidraTool
    from core.tools.radare2 import Radare2Tool
    from core.tools.strings_tool import StringsTool
    from core.tools.virustotal import VirusTotalTool
    from core.tools.yara_tool import YaraTool

    all_tools = [
        StringsTool(), EntropyTool(), YaraTool(), DieTool(),
        Radare2Tool(), GhidraTool(), FridaTool(), BinwalkTool(),
        VirusTotalTool(), DiffTool(),
    ]

    table = Table(title="Available Tools", border_style="blue")
    table.add_column("Tool", style="bold")
    table.add_column("Description")
    table.add_column("Status")

    for tool in all_tools:
        available = tool.is_available()
        status = "[green]Available[/green]" if available else "[red]Not installed[/red]"
        table.add_row(tool.name, tool.description, status)

    console.print(table)


@app.command()
def info(
    target: Path = typer.Argument(..., help="Path to the file to inspect", exists=True),
):
    """Quick file info — type, hashes, architecture."""
    from core.ingest.reader import triage_file

    fi = triage_file(target)

    table = Table(title=f"File: {fi.path.name}", show_header=False, border_style="dim")
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Type", fi.file_type.value.upper())
    table.add_row("Architecture", fi.architecture.value)
    table.add_row("MIME", fi.mime_type)
    table.add_row("Size", f"{fi.size:,} bytes")
    table.add_row("MD5", fi.md5)
    table.add_row("SHA256", fi.sha256)
    console.print(table)


if __name__ == "__main__":
    app()
