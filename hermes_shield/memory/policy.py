"""HermesShield Memory Policy Enforcement.

Defines and enforces memory write/retrieval policies, secret handling,
and revalidation requirements.
"""

from typing import Dict, List, Optional, Any, Set
from enum import Enum

from hermes_shield.memory import MemoryState, MemoryCategory, MemoryEntry, MemoryStore


class PolicyViolation(Exception):
    """Raised when memory policy is violated."""
    pass


class MemoryPolicy:
    """Enforces memory write and retrieval policies."""

    # Secret patterns that MUST be redacted
    FORBIDDEN_PATTERNS = [
        r"(?i)['\"]?(api_key|apikey)['\"]?\s*:\s*['\"]\w+['\"]",
        r"(?i)['\"]?(password|passwd|pwd)['\"]?\s*:\s*['\"]\w+['\"]",
        r"(?i)['\"]?(secret[_-]?key)['\"]?\s*:\s*['\"]\w+['\"]",
        r"(?i)['\"]?(private_key|ssh_key)['\"]?\s*:\s*['\"]\w+['\"]",
        r"(?i)['\"]?(authorization|auth)['\"]?\s*:\s*['\"]?Bearer\s+['\"][^'\"]+['\"]",
        r"(?i)['\"]?(aws_secret_access_key|aws_access_key_id)['\"]?\s*:\s*['\"][A-Z0-9]{20,}['\"]",
        r"(?i)['\"]?(token|auth_token|api_token)['\"]?\s*:\s*['\"][A-Za-z0-9\-_\.]{16,}['\"]",
        r'-----BEGIN (RSA |EC |OPEN )?PRIVATE KEY-----',
    ]

    # State transition rules: from_state -> allowed to_states
    VALID_TRANSITIONS = {
        'HYPOTHESIS': {'VERIFIED', 'REJECTED', 'OUTDATED'},
        'VERIFIED': {'KNOWN', 'OUTDATED', 'REJECTED'},
        'KNOWN': {'OUTDATED', 'REJECTED'},
        'REJECTED': set(),  # Terminal state
        'OUTDATED': {'VERIFIED', 'REJECTED', 'HYPOTHESIS'},
    }

    # Required fields per category
    REQUIRED_FIELDS = {
        'findings': ['title', 'description', 'severity'],
        'hypotheses': ['title', 'description'],
        'attack_paths': ['title', 'description', 'chained_findings'],
        'tested_controls': ['control_name', 'control_type', 'status'],
        'remediation_state': ['finding_id', 'status'],
        'target_environment': [],
    }

    # State TTL overrides (seconds)
    STATE_TTL = {
        'HYPOTHESIS': 86400,      # 24h
        'VERIFIED': 7 * 86400,    # 7 days
        'KNOWN': 30 * 86400,      # 30 days
        'REJECTED': 30 * 86400,   # 30 days
        'OUTDATED': 0,            # Immediate revalidation needed
    }

    def __init__(self, store: 'MemoryStore'):
        self.store = store

    def validate_write(self, entry: 'MemoryEntry') -> List[str]:
        """Validate entry before write. Returns list of violations."""
        violations = []

        # Check for forbidden patterns in content
        content_str = str(entry.content)
        for pattern in self.FORBIDDEN_PATTERNS:
            import re
            if re.search(pattern, str(entry.content)):
                violations.append(f"Forbidden pattern detected in content: {pattern}")

        # Check state transition validity (if updating existing)
        if entry.id in self.store._index:
            existing = self.store._index[entry.id]
            existing_state = existing.state.value if hasattr(existing.state, 'value') else existing.state
            new_state = entry.state.value if hasattr(entry.state, 'value') else entry.state
            if existing_state not in self.VALID_TRANSITIONS:
                pass  # Terminal state
            elif new_state not in self.VALID_TRANSITIONS.get(existing_state, set()):
                violations.append(
                    f"Invalid state transition: {existing_state} -> {new_state}"
                )

        # Check required fields
        cat_value = entry.category.value if hasattr(entry.category, 'value') else entry.category
        if cat_value in self.REQUIRED_FIELDS:
            required = self.REQUIRED_FIELDS[cat_value]
            for field in required:
                if field not in entry.content:
                    violations.append(f"Missing required field: {field}")

        # TTL must be positive for non-OUTDATED states
        state_value = entry.state.value if hasattr(entry.state, 'value') else entry.state
        if state_value != 'OUTDATED' and entry.ttl_seconds <= 0:
            violations.append("TTL must be positive for non-OUTDATED states")

        # Confidence bounds
        if not (0.0 <= entry.confidence <= 1.0):
            violations.append("Confidence must be between 0.0 and 1.0")

        return violations

    def validate_retrieval(self, entries: List['MemoryEntry']) -> List[str]:
        """Validate entries on retrieval. Returns warnings."""
        warnings = []

        for entry in entries:
            # Check if entry needs revalidation
            if entry.should_revalidate():
                state_val = entry.state.value if hasattr(entry.state, 'value') else entry.state
                warnings.append(
                    f"Entry {entry.id} ({state_val}) requires revalidation before use"
                )

            # Check if expired
            if entry.is_expired() and entry.state != 'OUTDATED':
                warnings.append(
                    f"Entry {entry.id} has expired but not marked OUTDATED"
                )

            # Check confidence threshold for KNOWN/VERIFIED
            state_val = entry.state.value if hasattr(entry.state, 'value') else entry.state
            if state_val in ('KNOWN', 'VERIFIED') and entry.confidence < 0.7:
                warnings.append(
                    f"Entry {entry.id} has low confidence ({entry.confidence}) for {state_val} state"
                )

        return warnings

    def enforce_revalidation(self, entry: 'MemoryEntry') -> bool:
        """Check if entry requires revalidation before use."""
        return entry.should_revalidate()

    def get_allowed_transitions(self, current_state: str) -> Set[str]:
        """Get allowed next states."""
        return self.VALID_TRANSITIONS.get(current_state, set())

    def sanitize_before_write(self, entry: 'MemoryEntry') -> 'MemoryEntry':
        """Apply sanitization before write."""
        # Create copy with sanitized content
        from hermes_shield.memory import sanitize_dict
        entry.content = sanitize_dict(entry.content)
        return entry


class RetrievalPolicy:
    """Defines retrieval behavior for different query types."""

    @staticmethod
    def get_known_behavior(store: 'MemoryStore', target: str) -> List:
        """KNOW + VERIFIED only, no revalidation warnings."""
        return store.get_known(target)

    @staticmethod
    def get_hypotheses_behavior(store: 'MemoryStore', target: str) -> List:
        """HYPOTHESIS entries with revalidation warnings."""
        entries = store.get_hypotheses(target)
        # All hypotheses require revalidation
        return entries

    @staticmethod
    def get_outdated_behavior(store: 'MemoryStore', target: str) -> List:
        """OUTDATED entries marked for revalidation."""
        return store.get_outdated(target)

    @staticmethod
    def get_attack_paths_behavior(store: 'MemoryStore', target: str) -> List:
        """Only KNOWN/VERIFIED attack paths for safe chaining."""
        return store.get_attack_paths(target)

    @staticmethod
    def get_remediation_behavior(store: 'MemoryStore', target: str) -> List:
        """All remediation states."""
        return store.get_remediation(target)


# Default policy instance getter
def get_default_policy(store: 'MemoryStore') -> MemoryPolicy:
    """Get default memory policy for store."""
    return MemoryPolicy(store)