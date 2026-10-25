"""Tests for HermesShield Memory System."""

import pytest
import tempfile
import json
import time
from datetime import datetime, timezone, timedelta

from hermes_shield.memory import (
    MemoryStore,
    MemoryEntry,
    MemoryState,
    MemoryCategory,
    MemoryPolicy,
    RetrievalPolicy,
    redact_secrets,
    sanitize_dict,
    create_memory_store,
)


class TestMemoryEntry:
    """Tests for MemoryEntry dataclass."""

    def test_entry_creation(self):
        """Test basic entry creation."""
        entry = MemoryEntry(
            category="findings",
            state="VERIFIED",
            content={"title": "Test Finding"},
            target="192.168.1.100",
            session_id="test_session"
        )
        assert entry.id is not None
        assert entry.category == MemoryCategory.FINDINGS
        assert entry.state == MemoryState.VERIFIED
        assert entry.target == "192.168.1.100"

    def test_entry_serialization(self):
        """Test entry to_dict and from_dict."""
        entry = MemoryEntry(
            id="test-id-123",
            category="findings",
            state="KNOWN",
            content={"title": "Test"},
            target="192.168.1.1",
            session_id="session_1",
            confidence=0.9
        )
        d = entry.to_dict()
        assert d['id'] == "test-id-123"
        assert d['category'] == "findings"
        assert d['state'] == "KNOWN"

        restored = MemoryEntry.from_dict(d)
        assert restored.id == entry.id
        assert restored.content == entry.content

    def test_expiry_check(self):
        """Test TTL expiry detection."""
        # Expired entry
        old_time = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        entry = MemoryEntry(
            created_at=old_time,
            ttl_seconds=86400,  # 1 day
        )
        assert entry.is_expired() is True

        # Non-expired entry
        new_time = datetime.now(timezone.utc).isoformat()
        entry = MemoryEntry(
            created_at=new_time,
            ttl_seconds=86400,
        )
        assert entry.is_expired() is False


class TestSecretRedaction:
    """Tests for secret redaction."""

    def test_api_key_redaction(self):
        """Test API key redaction."""
        text = 'api_key="sk-1234567890abcdef"'
        redacted = redact_secrets(text)
        assert 'sk-1234567890abcdef' not in redacted
        assert '****' in redacted

    def test_password_redaction(self):
        """Test password redaction."""
        text = 'password="supersecret123"'
        redacted = redact_secrets(text)
        assert 'supersecret123' not in redacted
        assert '****' in redacted

    def test_private_key_redaction(self):
        """Test private key redaction."""
        text = '-----BEGIN PRIVATE KEY-----\nMIIE...'
        redacted = redact_secrets(text)
        assert 'PRIVATE KEY' not in redacted or 'REDACTED' in redacted

    def test_dict_sanitization(self):
        """Test dictionary sanitization."""
        data = {
            'api_key': 'secret123',
            'nested': {'password': 'secret123'},
            'list': ['token=abc12345678901234', 'normal_value']  # 16+ chars for token pattern
        }
        sanitized = sanitize_dict(data)
        # Check that secret values are redacted
        assert 'secret123' not in str(sanitized)
        assert 'token=abc12345678901234' not in str(sanitized)
        # Values should be redacted
        assert '****' in str(sanitized)
        assert '****' in str(sanitized)


class TestMemoryStore:
    """Tests for MemoryStore operations."""

    @pytest.fixture
    def temp_store(self):
        """Create a temporary memory store."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = MemoryStore(
                target="192.168.1.100",
                session_id="test_session_001",
                audit_root=tmpdir
            )
            yield store

    def test_store_creation(self, temp_store):
        """Test store initialization."""
        assert temp_store.target == "192.168.1.100"
        assert temp_store.session_id == "test_session_001"
        assert temp_store.memory_root.exists()

    def test_record_finding(self, temp_store):
        """Test recording a finding."""
        entry_id = temp_store.record_finding(
            title="SQL Injection",
            description="Union-based SQLi in search",
            severity="HIGH",
            evidence=["tool_out_1"],
            target="192.168.1.100",
            state=MemoryState.VERIFIED,
            confidence=0.95,
            tags=["sql_injection", "web"],
            source_tool="vulnerability_validation"
        )
        assert entry_id is not None
        entry = temp_store.get_entry(entry_id)
        assert entry is not None
        assert entry.content['title'] == "SQL Injection"
        assert entry.state == MemoryState.VERIFIED
        assert entry.confidence == 0.95

    def test_record_hypothesis(self, temp_store):
        """Test recording a hypothesis."""
        entry_id = temp_store.record_hypothesis(
            title="Potential RCE via deserialization",
            description="Java deserialization gadget chain possible",
            target="192.168.1.100",
            confidence=0.4,
            tags=["rce", "deserialization"],
            source_tool="service_enumeration"
        )
        assert entry_id is not None
        entry = temp_store.get_entry(entry_id)
        assert entry.state == MemoryState.HYPOTHESIS
        assert entry.revalidation_required is True
        assert entry.category == MemoryCategory.HYPOTHESES

    def test_record_attack_path(self, temp_store):
        """Test recording attack path."""
        # First create a finding
        finding_id = temp_store.record_finding(
            title="Path Traversal",
            description="CVE-2021-41773",
            severity="HIGH",
            evidence=["evidence_1"],
            state=MemoryState.VERIFIED
        )

        # Create attack path chaining it
        path_id = temp_store.record_attack_path(
            title="Path Traversal -> RCE",
            description="Chain path traversal with log poisoning",
            chained_findings=[finding_id],
            state=MemoryState.HYPOTHESIS,
            confidence=0.6
        )
        entry = temp_store.get_entry(path_id)
        assert entry.content['chained_findings'] == [finding_id]
        assert entry.state == MemoryState.HYPOTHESIS

    def test_retrieve_known(self, temp_store):
        """Test retrieving KNOWN/VERIFIED entries."""
        # Add KNOWN finding
        temp_store.record_finding(
            title="Known Vuln",
            description="Test",
            severity="MEDIUM",
            evidence=[],
            state=MemoryState.KNOWN
        )
        # Add VERIFIED finding
        temp_store.record_finding(
            title="Verified Vuln",
            description="Test",
            severity="HIGH",
            evidence=[],
            state=MemoryState.VERIFIED
        )
        # Add HYPOTHESIS (should not appear)
        temp_store.record_hypothesis(
            title="Hypothesis",
            description="Test"
        )

        known = temp_store.get_known()
        assert len(known) == 2
        for entry in known:
            assert entry.state in (MemoryState.KNOWN, MemoryState.VERIFIED)

    def test_retrieve_hypotheses(self, temp_store):
        """Test retrieving hypotheses."""
        temp_store.record_hypothesis(
            title="Hypothesis 1",
            description="Test"
        )
        temp_store.record_hypothesis(
            title="Hypothesis 2",
            description="Test"
        )

        hyps = temp_store.get_hypotheses()
        assert len(hyps) == 2
        for entry in hyps:
            assert entry.state == MemoryState.HYPOTHESIS
            assert entry.revalidation_required is True

    def test_state_update(self, temp_store):
        """Test state transitions."""
        entry_id = temp_store.record_hypothesis(
            title="Test Hypothesis",
            description="Test"
        )

        # Valid transition: HYPOTHESIS -> VERIFIED
        result = temp_store.update_state(entry_id, MemoryState.VERIFIED, ["new_evidence"])
        assert result is True

        entry = temp_store.get_entry(entry_id)
        assert entry.state == MemoryState.VERIFIED
        assert entry.revalidation_required is False
        assert "new_evidence" in entry.evidence_refs

    def test_invalid_state_transition(self, temp_store):
        """Test invalid state transitions are rejected."""
        entry_id = temp_store.record_finding(
            title="Test",
            description="Test",
            severity="LOW",
            evidence=[],
            state=MemoryState.KNOWN
        )

        # KNOWN -> HYPOTHESIS should fail (not in valid transitions)
        result = temp_store.update_state(entry_id, MemoryState.HYPOTHESIS)
        assert result is False  # Should fail

    def test_revalidation(self, temp_store):
        """Test hypothesis revalidation."""
        entry_id = temp_store.record_hypothesis(
            title="Test Hypothesis",
            description="Test",
            confidence=0.5
        )

        # Confirm hypothesis
        result = temp_store.revalidate(entry_id, confirmed=True, evidence=["confirmation_1"])
        assert result is True

        entry = temp_store.get_entry(entry_id)
        assert entry.state == MemoryState.VERIFIED
        assert entry.revalidation_required is False
        assert "confirmation_1" in entry.evidence_refs

        # Test rejection
        entry_id2 = temp_store.record_hypothesis(
            title="Hypothesis 2",
            description="Test"
        )
        result = temp_store.revalidate(entry_id2, confirmed=False)
        entry2 = temp_store.get_entry(entry_id2)
        assert entry2.state == MemoryState.REJECTED

    def test_evidence_refs(self, temp_store):
        """Test evidence reference tracking."""
        entry_id = temp_store.record_finding(
            title="Test",
            description="Test",
            severity="LOW",
            evidence=["evidence_1"]
        )

        temp_store.add_evidence(entry_id, "evidence_2")
        entry = temp_store.get_entry(entry_id)
        assert "evidence_2" in entry.evidence_refs

    def test_confidence_update(self, temp_store):
        """Test confidence updates."""
        entry_id = temp_store.record_hypothesis(
            title="Test",
            description="Test",
            confidence=0.5
        )

        temp_store.update_confidence(entry_id, 0.9)
        entry = temp_store.get_entry(entry_id)
        assert entry.confidence == 0.9

        # Test bounds
        temp_store.update_confidence(entry_id, 1.5)
        entry = temp_store.get_entry(entry_id)
        assert entry.confidence == 1.0  # Capped at 1.0

    def test_get_by_category(self, temp_store):
        """Test category-based retrieval."""
        temp_store.record_finding(
            title="Finding 1",
            description="Test",
            severity="LOW",
            evidence=[]
        )
        temp_store.record_hypothesis(
            title="Hypothesis 1",
            description="Test"
        )

        findings = temp_store.get_by_category("findings")
        assert len(findings) == 1
        assert findings[0].category == MemoryCategory.FINDINGS

        hypotheses = temp_store.get_by_category("hypotheses")
        assert len(hypotheses) == 1
        assert hypotheses[0].category == MemoryCategory.HYPOTHESES

    def test_search(self, temp_store):
        """Test full-text search."""
        temp_store.record_finding(
            title="SQL Injection in login",
            description="Union-based injection",
            severity="HIGH",
            evidence=[]
        )
        temp_store.record_finding(
            title="XSS in comments",
            description="Stored XSS",
            severity="MEDIUM",
            evidence=[]
        )

        results = temp_store.search("SQL")
        assert len(results) == 1
        assert "SQL" in results[0].content['title']

    def test_stats(self, temp_store):
        """Test statistics."""
        temp_store.record_finding(
            title="Finding 1",
            description="Test",
            severity="LOW",
            evidence=[],
            state=MemoryState.KNOWN
        )
        temp_store.record_hypothesis(
            title="Hypothesis 1",
            description="Test"
        )

        stats = temp_store.get_stats()
        assert stats['total_entries'] == 2
        assert stats['by_state']['KNOWN'] == 1
        assert stats['by_state']['HYPOTHESIS'] == 1

    def test_export(self, temp_store):
        """Test export functionality."""
        temp_store.record_finding(
            title="Test",
            description="Test",
            severity="LOW",
            evidence=[]
        )

        exported = temp_store.export()
        assert len(exported) == 1
        assert exported[0]['content']['title'] == "Test"


class TestMemoryPolicy:
    """Tests for memory policy enforcement."""

    @pytest.fixture
    def store_with_policy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = MemoryStore(
                target="192.168.1.100",
                session_id="test_policy",
                audit_root=tmpdir
            )
            policy = MemoryPolicy(store)
            yield store, policy

    def test_valid_transition(self, store_with_policy):
        """Test valid state transitions."""
        store, policy = store_with_policy
        entry_id = store.record_hypothesis("Test", "Test")
        entry = store.get_entry(entry_id)

        allowed = policy.get_allowed_transitions("HYPOTHESIS")
        assert "VERIFIED" in allowed
        assert "REJECTED" in allowed
        assert "OUTDATED" in allowed

    def test_invalid_transition_rejected(self, store_with_policy):
        """Test invalid transitions are caught."""
        store, policy = store_with_policy
        entry_id = store.record_finding(
            title="Test",
            description="Test",
            severity="LOW",
            evidence=[],
            state=MemoryState.KNOWN
        )
        entry = store.get_entry(entry_id)

        allowed = policy.get_allowed_transitions("KNOWN")
        assert "HYPOTHESIS" not in allowed

    def test_secret_detection_in_write(self, store_with_policy):
        """Test secret detection prevents write."""
        store, policy = store_with_policy

        # Try to create entry with secret
        entry = MemoryEntry(
            category="findings",
            state=MemoryState.KNOWN,
            content={"title": "Test", "api_key": "secret123"},
            target="192.168.1.100",
            session_id="test"
        )

        violations = policy.validate_write(entry)
        assert len(violations) > 0
        assert any("Forbidden pattern" in v for v in violations)

    def test_retrieval_warnings(self, store_with_policy):
        """Test retrieval warnings for stale entries."""
        store, policy = store_with_policy

        # Create expired entry
        old_time = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        entry = MemoryEntry(
            category="findings",
            state="KNOWN",
            content={"title": "Old"},
            target="192.168.1.100",
            session_id="test",
            created_at=old_time,
            ttl_seconds=86400
        )
        store._index[entry.id] = entry

        warnings = policy.validate_retrieval([entry])
        assert len(warnings) > 0
        assert any("expired" in w.lower() for w in warnings)


class TestRetrievalPolicy:
    """Tests for retrieval behavior."""

    def test_known_behavior(self):
        """Test known retrieval behavior."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = MemoryStore(target="192.168.1.100", audit_root=tmpdir)
            store.record_finding("Known", "Test", "LOW", [], state=MemoryState.KNOWN)
            store.record_finding("Verified", "Test", "LOW", [], state=MemoryState.VERIFIED)
            store.record_hypothesis("Hypothesis", "Test")

            results = RetrievalPolicy.get_known_behavior(store, "192.168.1.100")
            assert len(results) == 2
            for r in results:
                assert r.state in (MemoryState.KNOWN, MemoryState.VERIFIED)

    def test_hypotheses_behavior(self):
        """Test hypotheses retrieval."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = MemoryStore(target="192.168.1.100", audit_root=tmpdir)
            store.record_hypothesis("H1", "Test")
            store.record_hypothesis("H2", "Test")

            results = RetrievalPolicy.get_hypotheses_behavior(store, "192.168.1.100")
            assert len(results) == 2
            for r in results:
                assert r.state == MemoryState.HYPOTHESIS
                assert r.should_revalidate() is True


class TestPersistence:
    """Tests for persistence across sessions."""

    def test_persistence_across_instances(self):
        """Test memory persists across store instances."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Session 1
            store1 = MemoryStore(
                target="192.168.1.100",
                session_id="session_1",
                audit_root=tmpdir
            )
            entry_id = store1.record_finding(
                title="Persistent Finding",
                description="Should survive restart",
                severity="HIGH",
                evidence=["ev_1"],
                state=MemoryState.VERIFIED
            )

            # Session 2 - new instance
            store2 = MemoryStore(
                target="192.168.1.100",
                session_id="session_2",
                audit_root=tmpdir
            )

            # Should retrieve the finding
            entry = store2.get_entry(entry_id)
            assert entry is not None
            assert entry.content['title'] == "Persistent Finding"
            assert entry.state == MemoryState.VERIFIED
            assert entry.session_id == "session_1"  # Original session preserved

    def test_session_isolation(self):
        """Test different targets don't share memory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store_a = MemoryStore(target="192.168.1.1", audit_root=tmpdir)
            store_b = MemoryStore(target="192.168.1.2", audit_root=tmpdir)

            store_a.record_finding("Target A Finding", "Test", "LOW", [], state=MemoryState.KNOWN)
            store_b.record_finding("Target B Finding", "Test", "LOW", [], state=MemoryState.KNOWN)

            a_findings = store_a.get_known()
            b_findings = store_b.get_known()

            assert len(a_findings) == 1
            assert len(b_findings) == 1
            assert a_findings[0].content['title'] == "Target A Finding"
            assert b_findings[0].content['title'] == "Target B Finding"


class TestDemonstration:
    """Integration test demonstrating SESSION 1 -> SESSION 2 flow."""

    def test_session_1_discovery(self):
        """SESSION 1: Discover controlled vulnerability."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = MemoryStore(
                target="192.168.1.100",
                session_id="hermes_session_001",
                audit_root=tmpdir
            )

            # Network recon
            store.record_test_execution(
                tool_name="network_reconnaissance",
                parameters={"target": "192.168.1.100", "scan_type": "quick"},
                result_summary="Open ports: 80, 443",
                target="192.168.1.100"
            )

            # HTTP recon
            store.record_test_execution(
                tool_name="http_reconnaissance",
                parameters={"target": "http://192.168.1.100"},
                result_summary="Apache 2.4.41 detected",
                target="192.168.1.100"
            )

            # Vulnerability validation
            finding_id = store.record_finding(
                title="Apache Path Traversal CVE-2021-41773",
                description="Path traversal in Apache 2.4.41 via URL encoding",
                severity="HIGH",
                evidence=["vuln_val_1", "vuln_val_2"],
                state=MemoryState.VERIFIED,
                confidence=0.95,
                tags=["cve-2021-41773", "apache", "path_traversal"],
                source_tool="vulnerability_validation"
            )

            # Hypothesis: chained attack
            attack_id = store.record_attack_path(
                title="Path Traversal -> Log Poisoning -> RCE",
                description="Chain path traversal with log poisoning for RCE",
                chained_findings=[finding_id],
                state=MemoryState.HYPOTHESIS,
                confidence=0.6
            )

            # Tested control
            store.record_tested_control(
                control_name="WAF",
                control_type="web_application_firewall",
                status="bypassed",
                details="Path traversal payloads bypassed WAF"
            )

            # Verify all stored
            stats = store.get_stats()
            assert stats['total_entries'] >= 4  # finding, attack_path, test_exec x2, control
            assert stats['by_state']['VERIFIED'] >= 1
            assert stats['by_state']['HYPOTHESIS'] >= 1

    def test_session_2_continuation(self):
        """SESSION 2: New agent continues investigation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # SESSION 1: Set up initial state
            store1 = MemoryStore(
                target="192.168.1.100",
                session_id="hermes_session_001",
                audit_root=tmpdir
            )

            finding_id = store1.record_finding(
                title="Apache Path Traversal CVE-2021-41773",
                description="Path traversal in Apache 2.4.41",
                severity="HIGH",
                evidence=["vuln_val_1"],
                state=MemoryState.VERIFIED,
                confidence=0.95
            )

            attack_id = store1.record_attack_path(
                title="Path Traversal -> Log Poisoning -> RCE",
                description="Chain path traversal with log poisoning",
                chained_findings=[finding_id],
                state=MemoryState.HYPOTHESIS,
                confidence=0.6
            )

            # SESSION 2: New agent instance
            store2 = MemoryStore(
                target="192.168.1.100",
                session_id="hermes_session_002",
                audit_root=tmpdir
            )

            # Retrieve context
            known_findings = store2.get_known()
            hypotheses = store2.get_hypotheses()

            assert len(known_findings) == 1
            assert known_findings[0].content['title'] == "Apache Path Traversal CVE-2021-41773"
            assert known_findings[0].state == MemoryState.VERIFIED

            assert len(hypotheses) == 1
            assert hypotheses[0].state == MemoryState.HYPOTHESIS

            # Agent revalidates hypothesis
            store2.revalidate(attack_id, confirmed=True, evidence=["manual_test_1"])

            # Verify state changed
            updated_attack = store2.get_entry(attack_id)
            assert updated_attack.state == MemoryState.VERIFIED
            assert updated_attack.revalidation_required is False

            # Record remediation
            remediation_id = store2.record_remediation(
                finding_id=finding_id,
                status="open",
                notes="Reported to vendor, awaiting patch"
            )

            remediation = store2.get_entry(remediation_id)
            assert remediation.content['status'] == "open"

            # Final stats
            stats = store2.get_stats()
            assert stats['by_state']['VERIFIED'] >= 2  # finding + attack path
            assert stats['by_category']['remediation_state'] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])