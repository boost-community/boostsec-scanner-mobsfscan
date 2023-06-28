"""Main app."""
from typing import cast

from typer import Typer

from .commands import process, version

app = Typer(
    add_completion=False,
    no_args_is_help=True,
)


def prepare_app() -> Typer:
    """Populate app with subcommands."""
    app.add_typer(process.app)
    app.add_typer(version.app)
    return app


def create_app() -> Typer:  # pragma: nocover
    """Create an instance of the app."""
    app = prepare_app()
    return cast(Typer, app())
