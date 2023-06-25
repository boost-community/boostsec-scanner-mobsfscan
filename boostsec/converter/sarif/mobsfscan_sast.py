"""Boost SAST extensions."""
from typing import TypedDict

from .base import (
    ReportingDescriptor,
    ReportingDescriptorReference,
    ReportingDescriptorRelationship,
    Run,
    ToolComponent,
    ToolComponentReference,
)
from .boostsec import BoostFindingConfidence, BoostFindingSeverity

BOOST_SAST_TAXONOMY_NAME = "boost/sast"
BOOST_SAST_TAXONOMY_VERSION = "1.0.0"
BOOST_SAST_TAXONOMY_ORG = "boostsecurity"


class MobsfscanCweType(TypedDict):
    """Represents a typed dict for a given CWE."""

    cwe_id: str
    severity: BoostFindingSeverity
    confidence: BoostFindingConfidence


UNKNOWN_CWE_ID: str = "CWE-UNKNOWN"


class MobsfscanCweSastTaxa:
    """Represents a SAST Taxa for a CWE in our allow list."""

    cwe: MobsfscanCweType

    def __init__(self, cwe: MobsfscanCweType):
        """Create a MobsfscanCweSastTaxa."""
        self.cwe = cwe

    def __hash__(self) -> int:
        """Hash the object."""
        return hash(self.cwe["cwe_id"])

    def __eq__(self, other: object) -> bool:
        """Check equality between 2 instances of the class."""
        if not isinstance(other, MobsfscanCweSastTaxa):
            return NotImplemented
        return self.cwe["cwe_id"] == other.cwe["cwe_id"]

    @classmethod
    def find_taxa_by_cwe_id(cls, cwe_id: str) -> "MobsfscanCweSastTaxa":
        """Return a taxa based on the CWE id."""
        return cls(
            cwe={
                "cwe_id": cwe_id,
                "severity": BoostFindingSeverity.NOT_SET,
                "confidence": BoostFindingConfidence.NOT_SET,
            }
        )

    def as_reference(self) -> ReportingDescriptorReference:
        """Return as ReportingDescriptorReference."""
        return ReportingDescriptorReference(
            id=self.cwe["cwe_id"],
            toolComponent=ToolComponentReference(
                name=BOOST_SAST_TAXONOMY_NAME,
            ),
        )

    def as_relationship(self) -> ReportingDescriptorRelationship:
        """Return a ReportingDescriptorRelationship."""
        return ReportingDescriptorRelationship(target=self.as_reference())

    def as_taxa(self) -> ReportingDescriptor:
        """Return as ReportingDescriptor."""
        return ReportingDescriptor(
            id=self.cwe["cwe_id"],
        )


def create_sast_taxonomy(used_rules: set[MobsfscanCweSastTaxa]) -> ToolComponent:
    """Create a new ToolComponent representing the SAST taxonomy."""
    return ToolComponent(
        name=BOOST_SAST_TAXONOMY_NAME,
        version=BOOST_SAST_TAXONOMY_VERSION,
        organization=BOOST_SAST_TAXONOMY_ORG,
        taxa=[t.as_taxa() for t in used_rules],
    )


def append_sast_taxonomy(run: Run, used_rules: set[MobsfscanCweSastTaxa]) -> None:
    """Append SAST taxonomy to the run."""
    taxonomy = create_sast_taxonomy(used_rules)
    taxonomy_ref = ToolComponentReference(name=taxonomy.name)
    assert run.taxonomies is not None  # noqa: S101 # type-hint

    run.taxonomies.append(taxonomy)
    run.tool.driver.supportedTaxonomies = []
    run.tool.driver.supportedTaxonomies.append(taxonomy_ref)
