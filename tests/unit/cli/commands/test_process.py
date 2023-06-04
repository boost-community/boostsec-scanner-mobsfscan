"""Test app.process."""
from pathlib import Path
from typing import Any, Optional

import pytest
from faker import Faker
from typer.testing import CliRunner

from boostsec.converter.cli.app import prepare_app
from boostsec.converter.cli.commands.process import (
    FIELDS_TO_KEEP,
    cleanup,
    memoize_cwe_for_rule,
    process_mobsfscan_sarif,
)
from boostsec.converter.sarif.base import (
    PropertyBag,
    ReportingDescriptor,
    ReportingDescriptorReference,
    ReportingDescriptorRelationship,
    SarifLog,
    Version,
)
from boostsec.converter.sarif.mobsfscan_sast import (
    BOOST_SAST_TAXONOMY_NAME,
    DEFAULT_RULE_KEY,
)

SnykDataT = dict[str, Any]

faker = Faker()


@pytest.fixture(params=["mobsfscan/mobsfscan.sarif"])
def mobsfscan_sarif_path(request: Any, data_path: str) -> Path:
    """Return mobsfscan test data file path."""
    path: Path = Path(data_path) / request.param
    return path


@pytest.fixture()
def mobsfscan_sarif_data(mobsfscan_sarif_path: Path) -> str:
    """Return mobsfscan test data."""
    return mobsfscan_sarif_path.read_text()


def test_cli_process_with_path_help() -> None:
    """Assert that "boostsec process" reads stdin."""
    app = prepare_app()
    result = CliRunner().invoke(app, ["process", "--help"])
    assert "Arguments:\n  [PATH]  Path of the mobsfscan SARIF file." in result.stdout


def test_cli_process_with_path_default(mobsfscan_sarif_data: str) -> None:
    """Assert that "boostsec process" reads stdin."""
    app = prepare_app()
    result = CliRunner().invoke(app, ["process"], input=mobsfscan_sarif_data)
    SarifLog.parse_raw(result.output)


def test_cli_process_with_path_returns(mobsfscan_sarif_path: Path) -> None:
    """Assert that "boostsec process PATH" returns sarif."""
    app = prepare_app()
    result = CliRunner().invoke(app, ["process", str(mobsfscan_sarif_path)])
    SarifLog.parse_raw(result.output)


def test_cli_process_with_stdin_returns(mobsfscan_sarif_path: Path) -> None:
    """Assert that "boostsec process -" returns sarif."""
    app = prepare_app()
    result = CliRunner().invoke(
        app, ["process", "-"], input=f"{mobsfscan_sarif_path.read_text()}\n"
    )
    SarifLog.parse_raw(result.output)


def test_cli_process_with_invalid_json() -> None:
    """Assert that invalid json reports an error."""
    app = prepare_app()
    document = '{"somekey": "somevalue"}'
    result = CliRunner().invoke(app, ["process", "-"], input=f"{document}\n")
    assert result.exit_code == 1
    assert "unsupported JSON document, 2 validation errors" in result.output
    assert document in result.output


def test_cli_process_with_cwe_tags_returns_expected(sarifs_path: Path) -> None:
    """Assert that "boostsec process PATH" returns sarif."""
    app = prepare_app()
    nodejsscan_path = sarifs_path / "nodejsscan.sarif"
    result = CliRunner().invoke(app, ["process", str(nodejsscan_path)])

    sarif_log = SarifLog.parse_raw(result.output)

    assert sarif_log.runs

    sarif_run = sarif_log.runs[0]

    assert sarif_run.taxonomies
    assert sarif_run.taxonomies[0].taxa

    cwes = [taxa.id for taxa in sarif_run.taxonomies[0].taxa]

    assert "CWE-614" in cwes
    assert "CWE-522" in cwes
    assert "CWE-1275" in cwes


def test_process_mobsfscan_sarif(mobsfscan_sarif_data: str) -> None:
    """Assert mobsfscan SARIF is processed to meet our SARIF profile."""
    data = mobsfscan_sarif_data

    sarif_log = process_mobsfscan_sarif(data)

    assert sarif_log.runs
    assert "sarif-schema-2.1.0.json" in str(sarif_log.schema_url)
    assert sarif_log.version == Version.field_2_1_0.value
    assert len(sarif_log.runs) == 1

    sarif_run = sarif_log.runs[0]
    assert sarif_run.taxonomies

    # assertions on the driver
    assert sarif_run.tool.driver.name == "mobsfscan"
    assert sarif_run.tool.driver.rules is not None
    assert sarif_run.tool.driver.supportedTaxonomies
    assert sarif_run.tool.driver.supportedTaxonomies[0].name == BOOST_SAST_TAXONOMY_NAME

    assert sarif_run.tool.driver.rules
    for rule in sarif_run.tool.driver.rules:
        assert rule.id
        assert rule.relationships
        assert rule.relationships[0].target.id
        assert "CWE" in rule.relationships[0].target.id
        assert rule.relationships[0].target.toolComponent
        assert rule.relationships[0].target.toolComponent.name
        assert (
            rule.relationships[0].target.toolComponent.name == BOOST_SAST_TAXONOMY_NAME
        )

    assert sarif_run.results
    for result in sarif_run.results:
        assert result.ruleId
        assert result.taxa
        assert result.taxa[0].id
        assert "CWE" in result.taxa[0].id
        assert result.taxa[0].toolComponent
        assert result.taxa[0].toolComponent.name
        assert result.taxa[0].toolComponent.name == BOOST_SAST_TAXONOMY_NAME


@pytest.mark.parametrize(
    "report",
    [
        ReportingDescriptor(
            id=faker.pystr(),
            relationships=[
                ReportingDescriptorRelationship(target=ReportingDescriptorReference())
            ],
        ),
        ReportingDescriptor(id=faker.pystr()),
    ],
)
def test_cleanup(report: ReportingDescriptor) -> None:
    """Test that cleanup keep the right fields."""
    original_fields = report.dict().keys()

    cleanup(report)

    fields = report.dict().keys()

    for field_name in FIELDS_TO_KEEP:
        assert field_name in fields

    for field_name in original_fields:
        if field_name not in FIELDS_TO_KEEP:
            assert field_name not in fields


@pytest.mark.parametrize(
    ("tags", "expected"),
    [
        (["cwe-327"], "CWE-327"),
        (["CWE-327: Use of a Broken or Risky Cryptographic Algorithm"], "CWE-327"),
        (
            [
                "OWASP-A1: Injection",
                "CWE-915: Improperly Controlled Modification",
            ],
            "CWE-915",
        ),
        (["OWASP-A1: Injection"], DEFAULT_RULE_KEY),
        ([], DEFAULT_RULE_KEY),
        (None, DEFAULT_RULE_KEY),
    ],
)
def test_memoize_cwe_for_rule(
    tags: Optional[list[str]], expected: Optional[str]
) -> None:
    """Test that memoize populate the map."""
    rule = ReportingDescriptor(
        id=faker.pystr(),
        properties=PropertyBag(tags=tags) if tags else None,
    )
    memo: dict[str, Optional[str]] = {}

    memoize_cwe_for_rule(rule, memo)

    assert len(memo) == 1
    assert memo.get(rule.id) == expected
