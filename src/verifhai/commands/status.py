"""
Check security progress command.
"""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn

from verifhai.core.haiamm import PRACTICES, DOMAINS

app = typer.Typer(help="Check your security progress")
console = Console()


@app.callback(invoke_without_command=True)
def status(
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed progress for each practice",
    ),
) -> None:
    """
    Check your HAI security progress.

    Shows completed practices, current maturity levels,
    and recommended next steps.
    """
    _show_status(verbose)


def _show_status(verbose: bool) -> None:
    """Show current security status."""
    console.print(
        Panel.fit(
            "[bold]HAI Security Status[/bold]\n\n"
            "[dim]Tracking your progress through HAIAMM practices[/dim]",
            title="📊 Status",
            border_style="blue",
        )
    )

    # Mock progress data (will be loaded from state file)
    completed = 1  # SR was completed in our session
    in_progress = 0
    total = len(PRACTICES)

    # Overall progress
    console.print("\n[bold]Overall Progress:[/bold]")
    console.print(f"  Completed: [green]{completed}/{total}[/green] practices")
    console.print(f"  In Progress: [yellow]{in_progress}[/yellow]")
    console.print(f"  Remaining: [dim]{total - completed - in_progress}[/dim]")

    # Progress bar
    pct = (completed / total) * 100
    bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
    console.print(f"\n  [{bar}] {pct:.0f}%\n")

    # Practice status table
    if verbose:
        table = Table(title="Practice Status")
        table.add_column("ID", style="cyan", width=4)
        table.add_column("Practice", style="white")
        table.add_column("Status", style="white", width=12)
        table.add_column("Level", style="white", width=8)

        for practice in PRACTICES:
            # Mock status
            if practice["id"] == "SR":
                status_str = "[green]Complete[/green]"
                level = "L1"
            else:
                status_str = "[dim]Not started[/dim]"
                level = "-"

            table.add_row(practice["id"], practice["name"], status_str, level)

        console.print(table)

    # Recommendations
    console.print("\n[bold]Recommended Next Steps:[/bold]")
    console.print("  1. [cyan]verifhai practice ta[/cyan] - Threat Assessment")
    console.print("  2. [cyan]verifhai practice sa[/cyan] - Secure Architecture")
    console.print("  3. [cyan]verifhai assess[/cyan] - Quick maturity check")

    console.print("\n[dim]Progress tracking coming soon! Will persist across sessions.[/dim]\n")
