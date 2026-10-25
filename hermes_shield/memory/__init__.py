"""HermesShield Memory System - Core Implementation.

Persistent security memory with state classification, secret redaction,
TTL enforcement, and revalidation protocols.
"""

import json
import os
import re
import uuid
import time
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field, asdict
from pathlib import Path

from hermes_shield.config import agent_config
from hermes_shield.evidence import EvidenceCollector


class MemoryState(Enum):
    """Memory entry state classification."""
    KNOWN = "KNOWN"           # Verified true, high confidence
    HYPOTHESIS = "HYPOTHESIS" # Plausible but unverified
    VERIFIED = "VERIFIED"     # Recently confirmed
    REJECTED = "REJECTED"     # Proven false
    OUTDATED = "OUTDATED"     # TTL exceeded, needs refresh


class MemoryCategory(Enum):
    """Memory entry category."""
    TARGET_ENVIRONMENT = "target_environment"
    FINDINGS = "findings"
    TESTS_EXECUTED = "tests_executed"
    ATTACK_PATHS = "attack_paths"
    HYPOTHESES = "hypotheses"
    FALSE_POSITIVES = "false_positives"
    TESTED_CONTROLS = "tested_controls"
    REMEDIATION_STATE = "remediation_state"
    ASSESSMENT_HISTORY = "assessment_history"
    EVIDENCE_COLLECTION = "evidence_collection"


# Secret redaction patterns
SECRET_PATTERNS = [
    (r'(?i)(api_key|apikey|x_api_key)\s*[=:]\s*[\'"][^\'"]+[\'"]', 'api_key=****'),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*[\'"][^\'"]+[\'"]', 'password=****'),
    (r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*[\'"][^\'"]+[\'"]', 'secret_key=****'),
    (r'(?i)(authorization|auth)\s*[=:]\s*[\'"]?Bearer\s+[\'"][^\'"]+[\'"]', 'Authorization: Bearer ****'),
    (r'(?i)(aws_secret_access_key|aws_access_key_id)\s*[=:]\s*[\'"][A-Z0-9]{20,}[\'"]', 'aws_key=****'),
    (r'(?i)(private_key|ssh_key)\s*[=:]\s*[\'"][^\'"]+[\'"]', 'private_key=****'),
    (r'(?i)(token|auth_token|api_token)\s*[=:]\s*[\'"][A-Za-z0-9\-_\.]{16,}[\'"]', 'token=****'),
    (r'(?i)(token|auth_token|api_token)\s*[=:]\s*[A-Za-z0-9\-_\.]{16,}', 'token=****'),  # unquoted
    (r'(?i)(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\b)', '[REDACTED_IP_PORT]'),
    (r'(?:[0-9a-fA-F]{32,})', '****HASH****'),  # Potential hashes
    (r'-----BEGIN (RSA |EC |OPEN )?PRIVATE KEY-----', '[REDACTED_PRIVATE_KEY]'),
]

# TTL configuration (seconds)
DEFAULT_TTL = {
    MemoryCategory.FINDINGS: 7 * 86400,           # 7 days
    MemoryCategory.HYPOTHESES: 86400,              # 24 hours
    MemoryCategory.ATTACK_PATHS: 14 * 86400,      # 14 days
    MemoryCategory.TESTED_CONTROLS: 30 * 86400,   # 30 days
    MemoryCategory.REMEDIATION_STATE: 90 * 86400, # 90 days
    MemoryCategory.TARGET_ENVIRONMENT: 30 * 86400,
    MemoryCategory.TESTS_EXECUTED: 7 * 86400,
    MemoryCategory.FALSE_POSITIVES: 30 * 86400,
    MemoryCategory.ASSESSMENT_HISTORY: 365 * 86400,
}

MAX_TTL = {
    MemoryCategory.FINDINGS: 30 * 86400,
    MemoryCategory.HYPOTHESES: 3 * 86400,
    MemoryCategory.ATTACK_PATHS: 60 * 86400,
    MemoryCategory.TESTED_CONTROLS: 90 * 86400,
    MemoryCategory.REMEDIATION_STATE: 365 * 86400,
}


@dataclass
class MemoryEntry:
    """A single memory entry with state classification."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    category: MemoryCategory = MemoryCategory.FINDINGS
    state: MemoryState = MemoryState.HYPOTHESIS
    content: Dict[str, Any] = field(default_factory=dict)
    target: str = ""
    session_id: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ttl_seconds: int = 86400
    confidence: float = 0.5
    tags: List[str] = field(default_factory=list)
    source_tool: str = ""
    revalidation_required: bool = True
    evidence_refs: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Convert string inputs to enums."""
        if isinstance(self.category, str):
            self.category = MemoryCategory(self.category)
        if isinstance(self.state, str):
            self.state = MemoryState(self.state)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        d = asdict(self)
        d['category'] = self.category.value
        d['state'] = self.state.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MemoryEntry':
        """Create entry from dictionary."""
        entry = cls(
            id=data.get('id', str(uuid.uuid4())),
            category=MemoryCategory(data.get('category', 'findings')),
            state=MemoryState(data.get('state', 'HYPOTHESIS')),
            content=data.get('content', {}),
            target=data.get('target', ''),
            session_id=data.get('session_id', ''),
            created_at=data.get('created_at', datetime.now(timezone.utc).isoformat()),
            updated_at=data.get('updated_at', datetime.now(timezone.utc).isoformat()),
            ttl_seconds=data.get('ttl_seconds', 86400),
            confidence=data.get('confidence', 0.5),
            tags=data.get('tags', []),
            source_tool=data.get('source_tool', ''),
            revalidation_required=data.get('revalidation_required', True),
            evidence_refs=data.get('evidence_refs', []),
            metadata=data.get('metadata', {}),
        )
        return entry

    def is_expired(self) -> bool:
        """Check if entry has exceeded TTL."""
        created = datetime.fromisoformat(self.created_at.replace('Z', '+00:00'))
        expiry = created + timedelta(seconds=self.ttl_seconds)
        return datetime.now(timezone.utc) > expiry

    def should_revalidate(self) -> bool:
        """Check if entry needs revalidation."""
        return self.revalidation_required and self.state in (MemoryState.HYPOTHESIS, MemoryState.OUTDATED)


def redact_secrets(text: str) -> str:
    """Apply secret redaction patterns to text."""
    if not isinstance(text, str):
        text = str(text)
    redacted = text
    for pattern, replacement in SECRET_PATTERNS:
        redacted = re.sub(pattern, replacement, redacted)
    return redacted


def sanitize_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively sanitize dictionary values.

    Redacts secrets based on:
    1. Key names that suggest secret content (api_key, password, token, secret, etc.)
    2. Value patterns that match secret formats (key=value, key: value, etc.)
    """
    # Key names that indicate secret values
    secret_keys = {
        'api_key', 'apikey', 'x_api_key',
        'password', 'passwd', 'pwd',
        'secret', 'secret_key', 'secretkey',
        'token', 'auth_token', 'api_token', 'access_token',
        'private_key', 'ssh_key',
        'aws_secret_access_key', 'aws_access_key_id',
        'authorization', 'auth',
        'client_secret', 'client_id',
    }

    def is_secret_key(key: str) -> bool:
        key_lower = key.lower()
        return any(sk in key_lower for sk in secret_keys)

    sanitized = {}
    for key, value in data.items():
        if isinstance(value, str):
            # Redact if key suggests secret, or if value matches secret patterns
            if is_secret_key(key):
                sanitized[key] = '****'
            else:
                sanitized[key] = redact_secrets(value)
        elif isinstance(value, dict):
            sanitized[key] = sanitize_dict(value)
        elif isinstance(value, list):
            sanitized[key] = [
                redact_secrets(v) if isinstance(v, str) else
                sanitize_dict(v) if isinstance(v, dict) else v
                for v in value
            ]
        else:
            sanitized[key] = value
    return sanitized


class MemoryStore:
    """Persistent memory store with state management."""

    def __init__(
        self,
        target: str,
        session_id: Optional[str] = None,
        audit_root: Optional[str] = None
    ):
        self.target = target
        self.session_id = session_id or f"hermes_{int(time.time())}"
        self.audit_root = audit_root or agent_config.audit_root
        self.memory_root = Path(self.audit_root) / "memory" / self.target
        self.memory_root.mkdir(parents=True, exist_ok=True)

        # In-memory index for fast queries
        self._index: Dict[str, MemoryEntry] = {}
        self._load_all()

    def _get_category_path(self, category: MemoryCategory) -> Path:
        """Get file path for category."""
        return self.memory_root / f"{category.value}.jsonl"

    def _load_all(self) -> None:
        """Load all memory entries from disk."""
        self._index.clear()
        for category in MemoryCategory:
            path = self._get_category_path(category)
            if path.exists():
                with open(path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            entry = MemoryEntry.from_dict(data)
                            self._index[entry.id] = entry
                        except json.JSONDecodeError:
                            continue

    def _write_entry(self, entry: MemoryEntry) -> None:
        """Write single entry to category file."""
        path = self._get_category_path(entry.category)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'a') as f:
            f.write(json.dumps(entry.to_dict()) + '\n')

    def _update_index(self, entry: MemoryEntry) -> None:
        """Update in-memory index."""
        self._index[entry.id] = entry

    def _get_ttl(self, category: MemoryCategory) -> int:
        """Get TTL for category."""
        return DEFAULT_TTL.get(category, 86400)

    # --- Write Operations ---

    def record_finding(
        self,
        title: str,
        description: str,
        severity: str,
        evidence: List[str],
        target: Optional[str] = None,
        state: MemoryState = MemoryState.VERIFIED,
        confidence: float = 0.9,
        tags: Optional[List[str]] = None,
        source_tool: str = "",
        content_extra: Optional[Dict[str, Any]] = None
    ) -> str:
        """Record a security finding."""
        target = target or self.target
        content = {
            'title': title,
            'description': description,
            'severity': severity,
        }
        if content_extra:
            content.update(content_extra)

        entry = MemoryEntry(
            category=MemoryCategory.FINDINGS,
            state=state,
            content=content,
            target=target,
            session_id=self.session_id,
            ttl_seconds=self._get_ttl(MemoryCategory.FINDINGS),
            confidence=confidence,
            tags=tags or [],
            source_tool=content_extra.get('source_tool', '') if content_extra else '',
            evidence_refs=evidence,
            revalidation_required=(state == MemoryState.HYPOTHESIS),
        )
        self._write_entry(entry)
        self._update_index(entry)
        return entry.id

    def record_hypothesis(
        self,
        title: str,
        description: str,
        target: Optional[str] = None,
        confidence: float = 0.5,
        tags: Optional[List[str]] = None,
        source_tool: str = "",
        evidence: Optional[List[str]] = None
    ) -> str:
        """Record a hypothesis for later validation."""
        target = target or self.target
        entry = MemoryEntry(
            category=MemoryCategory.HYPOTHESES,
            state=MemoryState.HYPOTHESIS,
            content={
                'title': title,
                'description': description,
            },
            target=target or self.target,
            session_id=self.session_id,
            ttl_seconds=self._get_ttl(MemoryCategory.HYPOTHESES),
            confidence=confidence,
            tags=tags or [],
            source_tool=source_tool,
            evidence_refs=evidence or [],
            revalidation_required=True,
        )
        self._write_entry(entry)
        self._update_index(entry)
        return entry.id

    def record_test_execution(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        result_summary: str,
        target: Optional[str] = None,
        success: bool = True
    ) -> str:
        """Record a tool execution."""
        target = target or self.target
        entry = MemoryEntry(
            category=MemoryCategory.TESTS_EXECUTED,
            state=MemoryState.KNOWN,
            content={
                'tool': tool_name,
                'parameters': parameters,
                'result_summary': result_summary,
                'success': success,
            },
            target=target or self.target,
            session_id=self.session_id,
            ttl_seconds=self._get_ttl(MemoryCategory.TESTS_EXECUTED),
            confidence=1.0,
            tags=['tool_execution', tool_name],
            source_tool=tool_name,
            revalidation_required=False,
        )
        self._write_entry(entry)
        self._update_index(entry)
        return entry.id

    def record_attack_path(
        self,
        title: str,
        description: str,
        chained_findings: List[str],
        target: Optional[str] = None,
        state: MemoryState = MemoryState.HYPOTHESIS,
        confidence: float = 0.6
    ) -> str:
        """Record an attack path (chained vulnerabilities)."""
        target = target or self.target
        entry = MemoryEntry(
            category=MemoryCategory.ATTACK_PATHS,
            state=state,
            content={
                'title': title,
                'description': description,
                'chained_findings': chained_findings,
            },
            target=target or self.target,
            session_id=self.session_id,
            ttl_seconds=self._get_ttl(MemoryCategory.ATTACK_PATHS),
            confidence=confidence,
            tags=['attack_path'],
            source_tool='attack_chaining',
            evidence_refs=chained_findings,
            revalidation_required=(state == MemoryState.HYPOTHESIS),
        )
        self._write_entry(entry)
        self._update_index(entry)
        return entry.id

    def record_tested_control(
        self,
        control_name: str,
        control_type: str,
        status: str,  # bypassed, detected, blocked, unknown
        target: Optional[str] = None,
        details: str = ""
    ) -> str:
        """Record a tested security control."""
        target = target or self.target
        entry = MemoryEntry(
            category=MemoryCategory.TESTED_CONTROLS,
            state=MemoryState.KNOWN,
            content={
                'control_name': control_name,
                'control_type': control_type,
                'status': status,
                'details': details,
            },
            target=target or self.target,
            session_id=self.session_id,
            ttl_seconds=self._get_ttl(MemoryCategory.TESTED_CONTROLS),
            confidence=0.9,
            tags=['control', control_type],
            source_tool='control_testing',
            revalidation_required=False,
        )
        self._write_entry(entry)
        self._update_index(entry)
        return entry.id

    def record_remediation(
        self,
        finding_id: str,
        status: str,  # open, in_progress, fixed, wont_fix
        notes: str = "",
        target: Optional[str] = None
    ) -> str:
        """Record remediation state for a finding."""
        target = target or self.target
        entry = MemoryEntry(
            category=MemoryCategory.REMEDIATION_STATE,
            state=MemoryState.KNOWN,
            content={
                'finding_id': finding_id,
                'status': status,
                'notes': notes,
            },
            target=target or self.target,
            session_id=self.session_id,
            ttl_seconds=self._get_ttl(MemoryCategory.REMEDIATION_STATE),
            confidence=1.0,
            tags=['remediation', status],
            source_tool='remediation_tracking',
            revalidation_required=False,
        )
        self._write_entry(entry)
        self._update_index(entry)
        return entry.id

    def record_assessment(
        self,
        scope: str,
        tools_used: List[str],
        duration_seconds: float,
        findings_count: int,
        target: Optional[str] = None
    ) -> str:
        """Record assessment session metadata."""
        target = target or self.target
        entry = MemoryEntry(
            category=MemoryCategory.ASSESSMENT_HISTORY,
            state=MemoryState.KNOWN,
            content={
                'scope': scope,
                'tools_used': tools_used,
                'duration_seconds': duration_seconds,
                'findings_count': findings_count,
            },
            target=target or self.target,
            session_id=self.session_id,
            ttl_seconds=self._get_ttl(MemoryCategory.ASSESSMENT_HISTORY),
            confidence=1.0,
            tags=['assessment'],
            source_tool='agent',
            revalidation_required=False,
        )
        self._write_entry(entry)
        self._update_index(entry)
        return entry.id

    def record_target_environment(
        self,
        env_data: Dict[str, Any],
        target: Optional[str] = None
    ) -> str:
        """Record target environment information."""
        target = target or self.target
        entry = MemoryEntry(
            category=MemoryCategory.TARGET_ENVIRONMENT,
            state=MemoryState.KNOWN,
            content=sanitize_dict(env_data),
            target=target or self.target,
            session_id=self.session_id,
            ttl_seconds=self._get_ttl(MemoryCategory.TARGET_ENVIRONMENT),
            confidence=0.9,
            tags=['environment'],
            source_tool='reconnaissance',
            revalidation_required=False,
        )
        self._write_entry(entry)
        self._update_index(entry)
        return entry.id

    def mark_false_positive(self, finding_id: str, reason: str) -> str:
        """Mark a finding as false positive."""
        target = self.target
        entry = MemoryEntry(
            category=MemoryCategory.FALSE_POSITIVES,
            state=MemoryState.REJECTED,
            content={
                'original_finding_id': finding_id,
                'reason': reason,
            },
            target=self.target,
            session_id=self.session_id,
            ttl_seconds=self._get_ttl(MemoryCategory.FALSE_POSITIVES),
            confidence=1.0,
            tags=['false_positive'],
            source_tool='validation',
            revalidation_required=False,
        )
        self._write_entry(entry)
        self._update_index(entry)
        return entry.id

    # --- Retrieval Operations ---

    def get_entry(self, entry_id: str) -> Optional[MemoryEntry]:
        """Get entry by ID."""
        return self._index.get(entry_id)

    def get_known(self, target: Optional[str] = None) -> List[MemoryEntry]:
        """Get KNOWN and VERIFIED entries for target."""
        target = target or self.target
        return [
            e for e in self._index.values()
            if e.target == target and e.state in (MemoryState.KNOWN, MemoryState.VERIFIED)
        ]

    def get_hypotheses(self, target: Optional[str] = None) -> List[MemoryEntry]:
        """Get HYPOTHESIS entries for target."""
        target = target or self.target
        return [
            e for e in self._index.values()
            if e.target == target and e.state == MemoryState.HYPOTHESIS
        ]

    def get_outdated(self, target: Optional[str] = None) -> List[MemoryEntry]:
        """Get OUTDATED entries for target."""
        target = target or self.target
        return [
            e for e in self._index.values()
            if e.target == target and e.state == MemoryState.OUTDATED
        ]

    def get_rejected(self, target: Optional[str] = None) -> List[MemoryEntry]:
        """Get REJECTED entries for target."""
        target = target or self.target
        return [
            e for e in self._index.values()
            if e.target == target and e.state == MemoryState.REJECTED
        ]

    def get_by_category(
        self,
        category: MemoryCategory | str,
        target: Optional[str] = None
    ) -> List[MemoryEntry]:
        """Get all entries for category and target."""
        target = target or self.target
        if isinstance(category, str):
            category = MemoryCategory(category)
        return [
            e for e in self._index.values()
            if e.target == target and e.category == category
        ]

    def get_by_state(self, state: MemoryState | str, target: Optional[str] = None) -> List[MemoryEntry]:
        """Get entries by state."""
        target = target or self.target
        if isinstance(state, str):
            state = MemoryState(state)
        return [
            e for e in self._index.values()
            if e.target == target and e.state == state
        ]

    def get_attack_paths(self, target: Optional[str] = None) -> List[MemoryEntry]:
        """Get attack path entries (KNOWN/VERIFIED only for chaining)."""
        target = target or self.target
        return [
            e for e in self._index.values()
            if e.target == target
            and e.category == MemoryCategory.ATTACK_PATHS
            and e.state in (MemoryState.KNOWN, MemoryState.VERIFIED)
        ]

    def get_remediation(self, target: Optional[str] = None) -> List[MemoryEntry]:
        """Get remediation tracking entries."""
        target = target or self.target
        return [
            e for e in self._index.values()
            if e.target == target and e.category == MemoryCategory.REMEDIATION_STATE
        ]

    def get_all_for_target(self, target: Optional[str] = None) -> List[MemoryEntry]:
        """Get all entries for target."""
        target = target or self.target
        return [e for e in self._index.values() if e.target == target]

    def search(self, query: str, target: Optional[str] = None) -> List[MemoryEntry]:
        """Full-text search across content."""
        target = target or self.target
        query_lower = query.lower()
        results = []
        for entry in self._index.values():
            if entry.target != target:
                continue
            # Search in content fields
            content_str = json.dumps(entry.content).lower()
            if query_lower in content_str:
                results.append(entry)
        return results

    # --- State Management ---

    def update_state(self, entry_id: str, new_state: MemoryState | str, evidence: Optional[List[str]] = None) -> bool:
        """Update entry state with transition validation."""
        entry = self._index.get(entry_id)
        if not entry:
            return False

        if isinstance(new_state, str):
            new_state = MemoryState(new_state)

        # Validate transition using policy
        old_state = entry.state
        old_state_val = old_state.value if hasattr(old_state, 'value') else old_state
        new_state_val = new_state.value if hasattr(new_state, 'value') else new_state

        # Check valid transitions
        VALID_TRANSITIONS = {
            'HYPOTHESIS': {'VERIFIED', 'REJECTED', 'OUTDATED'},
            'VERIFIED': {'KNOWN', 'OUTDATED', 'REJECTED'},
            'KNOWN': {'OUTDATED', 'REJECTED'},
            'REJECTED': set(),
            'OUTDATED': {'VERIFIED', 'REJECTED', 'HYPOTHESIS'},
        }

        if old_state_val in VALID_TRANSITIONS:
            if new_state_val not in VALID_TRANSITIONS[old_state_val]:
                return False

        entry.state = new_state
        entry.updated_at = datetime.now(timezone.utc).isoformat()

        if new_state in (MemoryState.VERIFIED, MemoryState.KNOWN):
            entry.revalidation_required = False
        elif new_state == MemoryState.OUTDATED:
            entry.revalidation_required = True

        if evidence:
            entry.evidence_refs.extend(evidence)

        # Write updated entry
        self._write_entry(entry)
        self._update_index(entry)
        return True

    def update_confidence(self, entry_id: str, confidence: float) -> bool:
        """Update entry confidence."""
        entry = self._index.get(entry_id)
        if not entry:
            return False
        entry.confidence = max(0.0, min(1.0, confidence))
        entry.updated_at = datetime.now(timezone.utc).isoformat()
        self._write_entry(entry)
        self._update_index(entry)
        return True

    def add_evidence(self, entry_id: str, evidence_ref: str) -> bool:
        """Add evidence reference to entry."""
        entry = self._index.get(entry_id)
        if not entry:
            return False
        if evidence_ref not in entry.evidence_refs:
            entry.evidence_refs.append(evidence_ref)
            entry.updated_at = datetime.now(timezone.utc).isoformat()
            self._write_entry(entry)
            self._update_index(entry)
        return True

    def revalidate(self, entry_id: str, confirmed: bool, evidence: Optional[List[str]] = None) -> bool:
        """Revalidate a HYPOTHESIS or OUTDATED entry."""
        entry = self._index.get(entry_id)
        if not entry:
            return False

        if confirmed:
            if entry.state == MemoryState.HYPOTHESIS:
                entry.state = MemoryState.VERIFIED
            elif entry.state == MemoryState.OUTDATED:
                entry.state = MemoryState.VERIFIED
            entry.revalidation_required = False
        else:
            entry.state = MemoryState.REJECTED
            entry.revalidation_required = False

        entry.updated_at = datetime.now(timezone.utc).isoformat()
        if evidence:
            entry.evidence_refs.extend(evidence)

        self._write_entry(entry)
        self._update_index(entry)
        return True

    def check_and_expire(self) -> int:
        """Check all entries for expiry, mark OUTDATED. Returns count expired."""
        expired = 0
        for entry in self._index.values():
            if entry.target == self.target and entry.is_expired():
                if entry.state not in (MemoryState.OUTDATED, MemoryState.REJECTED):
                    entry.state = MemoryState.OUTDATED
                    entry.revalidation_required = True
                    entry.updated_at = datetime.now(timezone.utc).isoformat()
                    self._write_entry(entry)
                    expired += 1
        return expired

    def get_stats(self) -> Dict[str, Any]:
        """Get memory statistics."""
        target_entries = [e for e in self._index.values() if e.target == self.target]
        stats = {
            'total_entries': len(target_entries),
            'by_state': {},
            'by_category': {},
            'expired_count': sum(1 for e in target_entries if e.is_expired()),
            'revalidation_needed': sum(1 for e in target_entries if e.should_revalidate()),
        }
        for state in MemoryState:
            stats['by_state'][state.value] = sum(
                1 for e in target_entries if e.state == state
            )
        for cat in MemoryCategory:
            stats['by_category'][cat.value] = sum(
                1 for e in target_entries if e.category == cat
            )
        return stats

    def export(self, target: Optional[str] = None) -> List[Dict[str, Any]]:
        """Export all entries for target as dicts."""
        target = target or self.target
        return [e.to_dict() for e in self._index.values() if e.target == target]

    def clear_target(self, target: Optional[str] = None) -> int:
        """Clear all entries for target (use with caution)."""
        target = target or self.target
        removed = 0
        to_remove = [eid for eid, e in self._index.items() if e.target == target]
        for eid in to_remove:
            del self._index[eid]
            removed += 1
        # Rewrite files
        for cat in MemoryCategory:
            path = self._get_category_path(cat)
            if path.exists():
                with open(path, 'w') as f:
                    for e in self._index.values():
                        if e.category == cat and e.target == self.target:
                            f.write(json.dumps(e.to_dict()) + '\n')
        return removed


# Convenience function for quick access
def create_memory_store(target: str, session_id: Optional[str] = None) -> MemoryStore:
    """Create a new memory store for target."""
    return MemoryStore(target=target, session_id=session_id)


# Import policy classes for external use
from hermes_shield.memory.policy import MemoryPolicy, RetrievalPolicy