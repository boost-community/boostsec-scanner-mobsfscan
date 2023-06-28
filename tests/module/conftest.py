"""Module test dependencies."""
from pathlib import Path

import pytest
from python_on_whales import Image, docker  # type: ignore[attr-defined]


@pytest.fixture(scope="session")
def docker_file(git_project_root: str) -> str:
    """Path of the project Dockerfile."""
    return str(Path(git_project_root) / "Dockerfile")


@pytest.fixture(scope="session")
def docker_tag() -> str:
    """Docker image tag."""
    return "boost-scanner-mobsfscan:latest"


@pytest.fixture(scope="session")
def docker_image(docker_file: str, docker_tag: str, git_project_root: str) -> Image:
    """Docker container image."""
    return docker.build(
        git_project_root,
        file=docker_file,
        tags=docker_tag,
    )
