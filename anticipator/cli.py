import os
import click
from anticipator.detection.scanner import scan as run_scan
from anticipator.integrations.exporter import export_json
from anticipator.integrations.visualizer import export_html
from anticipator.integrations.monitor import print_summary

EXPORT_PATH = os.getenv("ANTICIPATOR_EXPORTS", "exports")
os.makedirs(EXPORT_PATH, exist_ok=True)


@click.group()
@click.version_option(version="0.1.0")
def main():
    """Anticipator — Runtime threat detection for multi-agent AI systems."""
    pass


@main.command()
@click.argument("message")
@click.option("--agent", default="agent_a", help="Agent ID")
@click.option("--source", default=None, help="Source agent ID")
def scan(message, agent, source):
    """Scan a message for threats."""
    result = run_scan(text=message, agent_id=agent, source_agent_id=source)

    if result["detected"]:
        sev = result["severity"]
        col = "red" if sev == "critical" else "yellow"
        click.echo(click.style(f"[ANTICIPATOR] ⚠ {sev.upper()} detected", fg=col))
        click.echo(f"  Message : {message[:80]}")
        click.echo(f"  Severity: {sev}")
    else:
        click.echo("✅ Clean — no threats detected")


@main.command()
@click.option("--graph", default=None, help="Filter by graph/pipeline name")
@click.option("--last", default=None, help="Time window e.g. 24h, 7d, 30d")
def monitor(graph, last):
    """Show persistent threat monitor from SQLite."""
    print_summary(graph=graph, last=last)


@main.command()
def export():
    """Export reports."""
    export_json(source="both")
    export_html(log=[])
    click.echo("✅ Reports generated.")


if __name__ == "__main__":
    main()