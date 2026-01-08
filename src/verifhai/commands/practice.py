"""
Work on a specific security practice command.
"""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from verifhai.core.haiamm import PRACTICES, get_practice_by_id

app = typer.Typer(help="Work on a specific security practice")
console = Console()


@app.callback(invoke_without_command=True)
def practice(
    practice_id: str = typer.Argument(
        None,
        help="Practice ID to work on (sr, ta, sa, ir, st, ml, etc.)",
    ),
    level: int = typer.Option(
        1,
        "--level",
        "-l",
        help="Target maturity level (1, 2, or 3)",
        min=1,
        max=3,
    ),
) -> None:
    """
    Work on a specific HAIAMM security practice.

    Get guided activities, templates, and checklists to build
    security capabilities for your HAI system.
    """
    if practice_id:
        _work_on_practice(practice_id, level)
    else:
        _list_practices()


def _work_on_practice(practice_id: str, level: int) -> None:
    """Guide user through building a practice."""
    practice = get_practice_by_id(practice_id)
    if not practice:
        console.print(f"[red]Unknown practice: {practice_id}[/red]")
        _list_practices()
        raise typer.Exit(1)

    console.print(
        Panel.fit(
            f"[bold]{practice['name']}[/bold] ({practice['id']})\n\n"
            f"{practice['description']}\n\n"
            f"[dim]Target: Level {level} maturity[/dim]",
            title=f"🔧 Practice: {practice['id']}",
            border_style="green",
        )
    )

    # Show AI-specific threats this practice addresses
    if practice.get("ai_threats"):
        console.print("\n[bold]AI-Specific Threats Addressed:[/bold]")
        for threat in practice["ai_threats"]:
            console.print(f"  • {threat}")

    console.print(f"\n[yellow]Practice building workflow for L{level} coming soon![/yellow]")
    console.print("This will guide you through activities and generate templates.\n")


def _list_practices() -> None:
    """List all available practices."""
    table = Table(title="HAIAMM Security Practices")
    table.add_column("ID", style="cyan", width=4)
    table.add_column("Practice", style="white", width=25)
    table.add_column("Category", style="blue", width=12)
    table.add_column("Description", style="dim")

    categories = {
        "governance": ["SM", "PC", "EG"],
        "design": ["TA", "SR", "SA"],
        "verification": ["DR", "IR", "ST"],
        "operations": ["EH", "IM", "ML"],
    }

    for practice in PRACTICES:
        category = "unknown"
        for cat, ids in categories.items():
            if practice["id"] in ids:
                category = cat
                break

        table.add_row(
            practice["id"].lower(),
            practice["name"],
            category,
            practice["description"][:40] + "..." if len(practice["description"]) > 40 else practice["description"],
        )

    console.print(table)
    console.print("\n[dim]Usage: verifhai practice <id> [--level 1|2|3][/dim]")
    console.print("[dim]Example: verifhai practice sr --level 1[/dim]\n")
