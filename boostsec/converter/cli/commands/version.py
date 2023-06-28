"""Main app."""
from importlib import metadata

import typer

app = typer.Typer(
    add_completion=False,
)


@app.callback(invoke_without_command=True)
def version() -> None:
    """Display the app version."""
    value = metadata.version("boostsec-scanner-mobsfscan")
    typer.echo(value)
