"""HermesShield Attack Path Correlation Engine.

Implements Nemotron 3 Ultra powered reasoning to correlate individual
security findings into multi-step attack paths with full evidence traceability.

Key Features:
- Correlates findings into multi-step attack paths
- Distinguishes: observed fact, inferred relationship, hypothesis, validated attack path
- Tracks evidence for each step
- Identifies missing evidence and validation tests
- Produces structured JSON output with confidence scores
- Never presents unverified attack paths as confirmed compromises
"""

from .correlation_engine import AttackPathCorrelator, AttackPath, AttackStep, EvidenceItem
from .validation import AttackPathValidator, ValidationResult

__all__ = [
    "AttackPathCorrelator",
    "AttackPath",
    "AttackStep",
    "EvidenceItem",
    "AttackPathValidator",
    "ValidationResult",
]

__version__ = "1.0.0"