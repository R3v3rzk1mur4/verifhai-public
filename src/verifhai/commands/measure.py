"""
Full HAIAMM maturity measurement command.
"""

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from verifhai.core.haiamm import PRACTICES, DOMAINS, MATURITY_LEVELS

app = typer.Typer(help="Full HAIAMM maturity measurement")
console = Console()


@app.callback(invoke_without_command=True)
def measure(
    domain: str = typer.Option(
        None,
        "--domain",
        "-d",
        help="Measure a specific domain (software, data, infrastructure, vendors, processes, endpoints)",
    ),
    export: str = typer.Option(
        None,
        "--export",
        "-e",
        help="Export results to file (json, html, md)",
    ),
) -> None:
    """
    Run a full HAIAMM maturity measurement.

    Evaluate all 12 practices across 6 domains to get a comprehensive
    security maturity score for your HAI system.
    """
    if domain:
        _measure_domain(domain)
    else:
        _full_measurement(export)


def _measure_domain(domain: str) -> None:
    """Measure a specific domain."""
    domain_upper = domain.upper()
    valid_domains = [d["id"] for d in DOMAINS]

    if domain_upper not in valid_domains:
        console.print(f"[red]Unknown domain: {domain}[/red]")
        console.print("\nAvailable domains:")
        for d in DOMAINS:
            console.print(f"  [cyan]{d['id'].lower()}[/cyan] - {d['name']}")
        raise typer.Exit(1)

    domain_info = next(d for d in DOMAINS if d["id"] == domain_upper)
    console.print(f"\n[bold]Measuring Domain: {domain_info['name']}[/bold]")
    console.print(f"[dim]{domain_info['description']}[/dim]\n")

    console.print("[yellow]Domain measurement coming soon![/yellow]")


def _full_measurement(export: str | None) -> None:
    """Run a full maturity measurement."""
    console.print("\n[bold blue]Full HAIAMM Maturity Measurement[/bold blue]\n")

    # Show framework overview
    console.print("[bold]Framework Overview:[/bold]")
    console.print(f"  • {len(DOMAINS)} Security Domains")
    console.print(f"  • {len(PRACTICES)} Security Practices")
    console.print(f"  • {len(MATURITY_LEVELS)} Maturity Levels\n")

    # Domain table
    domain_table = Table(title="Security Domains")
    domain_table.add_column("ID", style="cyan", width=6)
    domain_table.add_column("Domain", style="white")
    domain_table.add_column("Description", style="dim")

    for domain in DOMAINS:
        domain_table.add_row(domain["id"], domain["name"], domain["description"])

    console.print(domain_table)

    # Maturity levels
    console.print("\n[bold]Maturity Levels:[/bold]")
    for level in MATURITY_LEVELS:
        console.print(f"  [cyan]L{level['level']}[/cyan] - {level['name']}: {level['description']}")

    console.print("\n[yellow]Full measurement wizard coming soon![/yellow]")
    console.print("This will guide you through assessing all practices.\n")

    if export:
        console.print(f"[dim]Export to {export} will be available after assessment.[/dim]")
