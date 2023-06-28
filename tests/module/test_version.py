"""Test app.verion."""
import pytest
from python_on_whales import docker


@pytest.mark.usefixtures("docker_image")
def test_version_returns(docker_tag: str) -> None:
    """Assert that "boostsec version" returns version."""
    output = docker.run(docker_tag, command=["version"], remove=True)
    assert isinstance(output, str)
    lines = output.splitlines()

    assert lines == ["1.0.0"]
