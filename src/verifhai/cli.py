"""
Verifhai CLI - Main entry point for the command-line interface.
"""

import typer
from rich.console import Console
from rich.panel import Panel

from verifhai import __version__
from verifhai.commands import assess, measure, practice, review, status

app = typer.Typer(
    name="verifhai",
    help="HAI Security Assessment Tool - Build and measure secure Human-Assisted Intelligence systems",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()

# Register subcommands
app.add_typer(assess.app, name="assess", help="Quick security maturity assessment")
app.add_typer(measure.app, name="measure", help="Full HAIAMM maturity measurement")
app.add_typer(practice.app, name="practice", help="Work on a specific security practice")
app.add_typer(review.app, name="review", help="Security code review")
app.add_typer(status.app, name="status", help="Check your security progress")


@app.command()
def start() -> None:
    """Begin your HAI security journey with an interactive guide."""
    console.print(
        Panel.fit(
            "[bold blue]Welcome to Verifhai![/bold blue]\n\n"
            "I'll help you build secure Human-Assisted Intelligence systems.\n\n"
            "[dim]Let's start by understanding what you're building.[/dim]",
            title="🛡️ Verifhai",
            border_style="blue",
        )
    )

    # Interactive prompts will go here
    console.print("\n[yellow]Interactive journey coming soon![/yellow]")
    console.print("For now, try: [bold]verifhai assess[/bold] for a quick assessment\n")


@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"[bold]verifhai[/bold] version [green]{__version__}[/green]")


@app.callback()
def main() -> None:
    """
    Verifhai - HAI Security Assessment Tool

    Build and measure secure Human-Assisted Intelligence systems
    using the HAIAMM framework.
    """
    pass


if __name__ == "__main__":
    app()
