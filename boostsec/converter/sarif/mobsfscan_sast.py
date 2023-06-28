"""Boost SAST extensions."""
from typing import Optional, TypedDict

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
    cwe_title: str
    severity: BoostFindingSeverity
    confidence: BoostFindingConfidence


DEFAULT_RULE = MobsfscanCweType(
    confidence=BoostFindingConfidence.NOT_SET,
    cwe_id="CWE-UNKNOWN",
    cwe_title="CWE-UNKNOWN - Original rule did not map to a known rule",
    severity=BoostFindingSeverity.NOT_SET,
)

DEFAULT_RULE_KEY = DEFAULT_RULE.get("cwe_id")
assert DEFAULT_RULE_KEY  # noqa S101 # type hint

CWE_ALLOW_LIST: dict[str, MobsfscanCweType] = {
    "CWE-73": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-73",
        "cwe_title": "CWE-73 - External Control of File Name or Path",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-78": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-78",
        "cwe_title": "CWE-78 - Improper Neutralization of Special "
        "Elements used in an OS Command ('OS Command "
        "Injection')",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-95": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-95",
        "cwe_title": "CWE-95 - Improper Neutralization of Directives in "
        "Dynamically Evaluated Code ('Eval Injection')",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-200": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-200",
        "cwe_title": "CWE-200 - Exposure of Sensitive Information to "
        "an Unauthorized Actor",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-276": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-276",
        "cwe_title": "CWE-276 - Incorrect Default Permissions",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-295": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-295",
        "cwe_title": "CWE-295 - Improper Certificate Validation",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-311": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-311",
        "cwe_title": "CWE-311 - Missing Encryption of Sensitive Data",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-312": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-312",
        "cwe_title": "CWE-312 - Cleartext Storage of Sensitive Information",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-321": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-321",
        "cwe_title": "CWE-321 - Use of Hard-coded Cryptographic Key",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-326": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-326",
        "cwe_title": "CWE-326 - Inadequate Encryption Strength",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-327": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-327",
        "cwe_title": "CWE-327 - Use of a Broken or Risky Cryptographic "
        "Algorithm",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-329": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-329",
        "cwe_title": "CWE-329 - Generation of Predictable IV with CBC Mode",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-330": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-330",
        "cwe_title": "CWE-330 - Use of Insufficiently Random Values",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-353": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-353",
        "cwe_title": "CWE-353 - Missing Support for Integrity Check",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-489": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-489",
        "cwe_title": "CWE-489 - Active Debug Code",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-502": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-502",
        "cwe_title": "CWE-502 - Deserialization of Untrusted Data",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-532": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-532",
        "cwe_title": "CWE-532 - Insertion of Sensitive Information "
        "into Log File",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-611": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-611",
        "cwe_title": "CWE-611 - Improper Restriction of XML External "
        "Entity Reference",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-649": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-649",
        "cwe_title": "CWE-649 - Reliance on Obfuscation or Encryption "
        "of Security-Relevant Inputs without Integrity Checking",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-676": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-676",
        "cwe_title": "CWE-676 - Use of Potentially Dangerous Function",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-749": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-749",
        "cwe_title": "CWE-749 - Exposed Dangerous Method or Function",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-757": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-757",
        "cwe_title": "CWE-757 - Selection of Less-Secure Algorithm "
        "During Negotiation ('Algorithm Downgrade')",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-780": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-780",
        "cwe_title": "CWE-780 - Use of RSA Algorithm without OAEP",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-798": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-798",
        "cwe_title": "CWE-798 - Use of Hard-coded Credentials",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-919": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-919",
        "cwe_title": "CWE-919 - Weaknesses in Mobile Applications",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    "CWE-1204": {
        "confidence": BoostFindingConfidence.NOT_SET,
        "cwe_id": "CWE-1204",
        "cwe_title": "CWE-1204 - Generation of Weak Initialization "
        "Vector (IV)",
        "severity": BoostFindingSeverity.NOT_SET,
    },
    DEFAULT_RULE_KEY: DEFAULT_RULE,
}


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
    def find_taxa_by_cwe_id(cls, cwe_id: Optional[str]) -> "MobsfscanCweSastTaxa":
        """Return a taxa based on the CWE id."""
        cwe_id = cwe_id or ""
        cwe = CWE_ALLOW_LIST.get(cwe_id, DEFAULT_RULE)
        return cls(cwe)

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
