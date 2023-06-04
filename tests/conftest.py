"""Dependencies."""

from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def git_project_root(request: pytest.FixtureRequest) -> str:
    """Path of the git project root."""
    return str(request.config.rootpath)


@pytest.fixture()
def data_path(git_project_root: str) -> str:
    """Path of the test data files."""
    return str(Path(git_project_root) / "tests" / "data")


@pytest.fixture()
def sarifs_path(git_project_root: str) -> Path:
    """Path of the test SARIF files."""
    return Path(git_project_root) / "tests" / "data" / "mobsfscan"
