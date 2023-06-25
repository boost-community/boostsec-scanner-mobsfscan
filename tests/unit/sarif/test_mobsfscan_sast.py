"""Test."""

import random

import pytest
from faker import Faker

from boostsec.converter.sarif.boostsec import (
    BoostFindingConfidence,
    BoostFindingSeverity,
)
from boostsec.converter.sarif.mobsfscan_sast import (
    BOOST_SAST_TAXONOMY_NAME,
    UNKNOWN_CWE_ID,
    MobsfscanCweSastTaxa,
    MobsfscanCweType,
)

faker = Faker()


@pytest.mark.parametrize(
    ("cwe_id", "expected"),
    [
        (
            "CWE-22",
            {
                "cwe_id": "CWE-22",
                "confidence": BoostFindingConfidence.NOT_SET,
                "severity": BoostFindingSeverity.NOT_SET,
            },
        ),
        (
            "kartoffel",
            {
                "cwe_id": "kartoffel",
                "confidence": BoostFindingConfidence.NOT_SET,
                "severity": BoostFindingSeverity.NOT_SET,
            },
        ),
        (
            UNKNOWN_CWE_ID,
            {
                "cwe_id": UNKNOWN_CWE_ID,
                "confidence": BoostFindingConfidence.NOT_SET,
                "severity": BoostFindingSeverity.NOT_SET,
            },
        ),
    ],
)
def test_find_taxa_by_cwe_id(cwe_id: str, expected: MobsfscanCweType) -> None:
    """Assert that the right taxa is returned for a cwe_id."""
    result = MobsfscanCweSastTaxa.find_taxa_by_cwe_id(cwe_id)
    assert result.cwe == expected


def test_as_taxa() -> None:
    """Assert the correct reporting descriptor is generated."""
    sut = _mobsfscan_cwe_sast_taxa_factory()

    result = sut.as_taxa()

    assert result.id == sut.cwe.get("cwe_id")
    assert result.name is None


def test_as_reference() -> None:
    """Assert the correct reporting descriptor relationship is generated."""
    sut = _mobsfscan_cwe_sast_taxa_factory()

    result = sut.as_reference()

    assert result.id == sut.cwe.get("cwe_id")
    assert result.toolComponent
    assert result.toolComponent.name == BOOST_SAST_TAXONOMY_NAME


def test_as_relationship() -> None:
    """Assert the correct reporting descriptor reference is generated."""
    sut = _mobsfscan_cwe_sast_taxa_factory()

    result = sut.as_relationship()

    assert result.target.id == sut.cwe.get("cwe_id")
    assert result.target
    assert result.target.toolComponent
    assert result.target.toolComponent.name == BOOST_SAST_TAXONOMY_NAME


def test_hash() -> None:
    """Test the hash function."""
    sut = _mobsfscan_cwe_sast_taxa_factory()

    result = sut.__hash__()

    assert result == hash(sut.cwe["cwe_id"])


def test_equality() -> None:
    """Test that equality is based on the cwe_id."""
    sut1 = _mobsfscan_cwe_sast_taxa_factory()
    sut2 = _mobsfscan_cwe_sast_taxa_factory()

    assert sut1 != sut2

    sut2.cwe["cwe_id"] = sut1.cwe["cwe_id"]

    assert sut1 == sut2


def test_equality_not_implemented() -> None:
    """Test that equality is based on the cwe_id."""
    sut = _mobsfscan_cwe_sast_taxa_factory()
    other = "something"

    assert sut != other
    assert sut.__eq__(other) == NotImplemented


def _mobsfscan_cwe_sast_taxa_factory() -> MobsfscanCweSastTaxa:
    return MobsfscanCweSastTaxa(
        cwe=MobsfscanCweType(
            cwe_id=faker.pystr(),
            severity=random.choice(list(BoostFindingSeverity)),
            confidence=random.choice(list(BoostFindingConfidence)),
        )
    )
