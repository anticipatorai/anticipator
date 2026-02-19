import click

@click.group()
@click.version_option(version="0.1.0")
def main():
    """Anticipator — Runtime threat detection for multi-agent AI systems."""
    pass


@main.command()
@click.argument("path")
@click.option("--graph", is_flag=True, help="Generate graph visualization.")
@click.option("--report", type=click.Choice(["json", "md"]), help="Export report format.")
def scan(path, graph, report):
    """Scan agent codebase for security vulnerabilities."""
    click.echo(f"Scanning {path}...")

    if graph:
        click.echo("Generating graph...")

    if report:
        click.echo(f"Exporting report as {report}...")


@main.command()
def monitor():
    """Monitor agent messages in real time."""
    click.echo("Monitoring agents...")


if __name__ == "__main__":
    main()
