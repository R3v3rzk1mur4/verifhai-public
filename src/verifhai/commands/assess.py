"""
Quick security maturity assessment command.
"""

import typer
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

from verifhai.core.haiamm import PRACTICES, get_practice_by_id

app = typer.Typer(help="Quick security maturity assessment")
console = Console()


@app.callback(invoke_without_command=True)
def assess(
    practice_id: str = typer.Argument(
        None,
        help="Specific practice to assess (e.g., 'sr', 'ta', 'sa')",
    ),
    quick: bool = typer.Option(
        False,
        "--quick",
        "-q",
        help="Run a quick 5-question assessment",
    ),
) -> None:
    """
    Run a quick security maturity assessment.

    Assess your HAI system against HAIAMM practices to identify
    strengths and gaps in your security posture.
    """
    if practice_id:
        _assess_single_practice(practice_id)
    elif quick:
        _quick_assessment()
    else:
        _interactive_assessment()


def _assess_single_practice(practice_id: str) -> None:
    """Assess a single practice."""
    practice = get_practice_by_id(practice_id)
    if not practice:
        console.print(f"[red]Unknown practice: {practice_id}[/red]")
        console.print("\nAvailable practices:")
        for p in PRACTICES:
            console.print(f"  [cyan]{p['id'].lower()}[/cyan] - {p['name']}")
        raise typer.Exit(1)

    console.print(f"\n[bold]Assessing: {practice['name']} ({practice['id']})[/bold]")
    console.print(f"[dim]{practice['description']}[/dim]\n")

    # Assessment questions would go here
    console.print("[yellow]Single practice assessment coming soon![/yellow]")


def _quick_assessment() -> None:
    """Run a quick 5-question assessment."""
    console.print("\n[bold blue]Quick Assessment (5 questions)[/bold blue]\n")
    console.print("[yellow]Quick assessment coming soon![/yellow]")


def _interactive_assessment() -> None:
    """Run a full interactive assessment."""
    console.print("\n[bold blue]Interactive Assessment[/bold blue]\n")

    # Show available practices
    table = Table(title="HAIAMM Practices")
    table.add_column("ID", style="cyan", width=4)
    table.add_column("Practice", style="white")
    table.add_column("Description", style="dim")

    for practice in PRACTICES:
        table.add_row(
            practice["id"],
            practice["name"],
            practice["description"][:50] + "..." if len(practice["description"]) > 50 else practice["description"],
        )

    console.print(table)
    console.print("\n[yellow]Full interactive assessment coming soon![/yellow]")
    console.print("Try: [bold]verifhai assess sr[/bold] to assess Security Requirements\n")
