"""Boostsecurity SARIF utilities."""
from enum import Enum


class BoostFindingSeverity(str, Enum):
    """Severity levels defined for Findings."""

    MINOR = "minor"
    WARNING = "warning"
    CRITICAL = "critical"
    NOT_SET = "not_set"


class BoostFindingConfidence(str, Enum):
    """Confidence levels defined for Findings."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NOT_SET = "not_set"
