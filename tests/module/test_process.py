"""Test app.verion."""
from pathlib import Path
from typing import Any, cast

import pytest
from python_on_whales.utils import run

from boostsec.converter.sarif.base import SarifLog


@pytest.fixture(params=["mobsfscan/mobsfscan.sarif"])
def mobsfscan_sarif_path(request: Any, data_path: str) -> Path:
    """Return mobsfscan test data file path."""
    path: Path = Path(data_path) / request.param
    return path


@pytest.mark.usefixtures("docker_image")
def test_pipe_stdin(docker_tag: str, mobsfscan_sarif_path: Path) -> None:
    """Assert that "boostsec process -" processes stdin."""
    input_data = mobsfscan_sarif_path.read_bytes()
    output = cast(
        bytes,
        run(
            args=["docker", "run", "--rm", "--interactive", docker_tag, "process", "-"],
            input=input_data,
        ),
    )

    SarifLog.parse_raw(output)
