"""
Security code review command.
"""

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(help="Security code review for AI systems")
console = Console()


@app.callback(invoke_without_command=True)
def review(
    path: Path = typer.Argument(
        None,
        help="File or directory to review",
        exists=True,
    ),
    ai_threats: bool = typer.Option(
        True,
        "--ai-threats/--no-ai-threats",
        help="Check for AI-specific threats (EA, AGH, TM, RA)",
    ),
    owasp: bool = typer.Option(
        True,
        "--owasp/--no-owasp",
        help="Check for OWASP Top 10 vulnerabilities",
    ),
    output: str = typer.Option(
        None,
        "--output",
        "-o",
        help="Output format (json, md, sarif)",
    ),
) -> None:
    """
    Review code or configuration for security issues.

    Analyzes for both standard vulnerabilities (OWASP) and
    AI-specific threats (Excessive Agency, Agent Goal Hijack, etc.).
    """
    if path:
        _review_path(path, ai_threats, owasp, output)
    else:
        _show_review_help()


def _review_path(path: Path, ai_threats: bool, owasp: bool, output: str | None) -> None:
    """Review a file or directory."""
    console.print(
        Panel.fit(
            f"[bold]Reviewing:[/bold] {path}\n\n"
            f"AI Threats: {'✓' if ai_threats else '✗'}\n"
            f"OWASP: {'✓' if owasp else '✗'}",
            title="🔍 Security Review",
            border_style="yellow",
        )
    )

    if path.is_file():
        console.print(f"\n[dim]File: {path.name} ({path.stat().st_size} bytes)[/dim]")
    else:
        file_count = len(list(path.rglob("*")))
        console.print(f"\n[dim]Directory: {file_count} files[/dim]")

    console.print("\n[yellow]Code review engine coming soon![/yellow]")
    console.print("This will analyze code for security issues and generate a report.\n")

    if ai_threats:
        _show_ai_threat_checklist()


def _show_ai_threat_checklist() -> None:
    """Show AI-specific threat checklist."""
    table = Table(title="AI-Specific Threats Checklist")
    table.add_column("Threat", style="cyan", width=6)
    table.add_column("Name", style="white", width=20)
    table.add_column("What to Look For", style="dim")

    threats = [
        ("EA", "Excessive Agency", "Overly broad permissions, missing constraints"),
        ("AGH", "Agent Goal Hijack", "Unvalidated inputs, prompt injection vectors"),
        ("TM", "Tool Misuse", "Unrestricted tool access, missing validation"),
        ("RA", "Rogue Agent", "Missing monitoring, no kill switch, autonomous loops"),
    ]

    for threat_id, name, desc in threats:
        table.add_row(threat_id, name, desc)

    console.print(table)


def _show_review_help() -> None:
    """Show help for review command."""
    console.print(
        Panel.fit(
            "[bold]Security Code Review[/bold]\n\n"
            "Analyze code for security vulnerabilities.\n\n"
            "[dim]Usage:[/dim]\n"
            "  verifhai review <file_or_directory>\n"
            "  verifhai review src/ --output json\n"
            "  verifhai review agent.py --no-owasp",
            title="🔍 Review Help",
            border_style="blue",
        )
    )
