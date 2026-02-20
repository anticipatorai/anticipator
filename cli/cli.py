import click
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), 
    '../../../python-sdk/src/'))

from observer import AgentObserver


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
    observer = AgentObserver(agent)
    result = observer.observe(message, source_agent_id=source)
    if not result["detected"]:
        click.echo("✅ Clean — no threats detected")


@main.command()
def monitor():
    """Monitor agent messages in real time."""
    click.echo("Monitoring agents...")


if __name__ == "__main__":
    main()

