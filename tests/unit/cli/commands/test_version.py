"""Test app.verion."""
from typer.testing import CliRunner

from boostsec.converter.cli.app import prepare_app


def test_version_returns() -> None:
    """Assert that "boostsec version" returns version."""
    app = prepare_app()
    result = CliRunner().invoke(app, ["version"])
    assert result.output == "1.0.0\n"
