"""Test."""

from pathlib import Path

import pytest

from boostsec.converter.sarif.base import SarifLog


@pytest.mark.parametrize(
    "data_name",
    ["mobsfscan/mobsfscan.sarif"],
)
def test_sarif_log_from_file(data_path: str, data_name: str) -> None:
    """Assert that SarifLog can parse the test data."""
    with (Path(data_path) / data_name).open() as data_file:
        SarifLog.parse_raw(data_file.read())
