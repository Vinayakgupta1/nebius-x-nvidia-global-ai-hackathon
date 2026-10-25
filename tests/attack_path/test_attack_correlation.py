"""Tests for the HermesShield Attack Path Correlation Engine.

Tests cover:
- Hallucinated relationships (false connections)
- Unsupported conclusions (claims without evidence)
- Contradictory evidence
- Incomplete attack paths
- False positives
- Clear distinction between observed, inferred, hypothesis, and validated claims
"""

import sys
import os
from typing import Dict, List

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hermes_shield.attack_path.correlation_engine import (
    AttackPathCorrelator, AttackPath, AttackStep, EvidenceItem,
    ClaimStatus, StepStatus, CorrelateResult
)
from hermes_shield.attack_path.validation import (
    AttackPathValidator, ValidationResult
)
from hermes_shield.attack_path.correlation_engine import ClaimStatus as CS


def test_basic_correlation():
    """Test basic finding correlation into attack paths."""
    correlator = AttackPathCorrelator()
    
    findings = [
        {
            "id": "finding_1",
            "type": "vulnerability",
            "cve": "CVE-2024-1234",
            "severity": "high",
            "description": "SQL injection in web application"
        }
    ]
    
    vulnerabilities = [
        {
            "id": "vuln_1",
            "cve": "CVE-2024-1234",
            "type": "sql_injection",
            "severity": "high",
            "exploit_available": True,
            "target_reachable": True
        }
    ]
    
    evidence = [
        {
            "id": "ev_1",
            "source": "sql_injection_scan",
            "cve": "CVE-2024-1234",
            "status": "detected",
            "confidence": 0.9,
            "verified": True
        }
    ]
    
    result = correlator.correlate(
        findings=findings,
        vulnerabilities=vulnerabilities,
        evidence=evidence
    )
    
    assert result.success, "Correlation should succeed"
    assert len(result.attack_paths) > 0, "Should generate at least one attack path"
    assert result.hypotheses_generated > 0, "Should generate hypotheses"
    print("  PASS: test_basic_correlation")


def test_hallucinated_relationships():
    """Test that hallucinated (false) relationships are properly identified and rejected."""
    correlator = AttackPathCorrelator(confidence_threshold=0.5)
    
    # Findings with no actual connections
    findings = [
        {
            "id": "finding_1",
            "type": "service",
            "description": "SSH service running on port 22"
        },
        {
            "id": "finding_2", 
            "type": "web_server",
            "description": "Apache web server on port 80"
        }
    ]
    
    vulnerabilities = [
        {
            "id": "vuln_1",
            "type": "sql_injection",
            "cve": "UNRELATED-CVE",
            "severity": "high",
            "exploit_available": True
        }
    ]
    
    result = correlator.correlate(
        findings=findings,
        vulnerabilities=vulnerabilities
    )
    
    # Should either produce no paths or paths with low confidence due to lack of connections
    # Hallucinated relationships should not produce high-confidence paths
    for path in result.attack_paths:
        # If paths are generated, their confidence should be low due to lack of connections
        assert path.overall_confidence < 0.7, (
            f"Hallucinated path should not exceed confidence threshold, got {path.overall_confidence}"
        )
    
    print("  PASS: test_hallucinated_relationships")


def test_unsupported_conclusions():
    """Test that unsupported conclusions (claims without evidence) are flagged."""
    correlator = AttackPathCorrelator()
    
    findings = []
    vulnerabilities = [
        {
            "id": "vuln_1",
            "type": "remote_code_execution",
            "cve": "CVE-2024-5678",
            "severity": "critical",
            "exploit_available": True,
            "target_reachable": True
        }
    ]
    
    # No evidence provided
    result = correlator.correlate(
        findings=findings,
        vulnerabilities=vulnerabilities,
        evidence=[]
    )
    
    # Should generate hypotheses but flag them as unsupported
    assert result.hypotheses_generated > 0, "Should generate hypotheses from vulnerabilities"
    
    # Check that hypotheses are properly marked
    for path in result.attack_paths:
        for step in path.steps:
            if step.claim_status == CS.HYPOTHESIS:
                # Hypotheses should have missing_evidence identified
                assert len(step.missing_evidence) > 0, (
                    "Hypotheses should identify missing evidence"
                )
    
    print("  PASS: test_unsupported_conclusions")


def test_contradictory_evidence():
    """Test that contradictory evidence is properly detected and reduces confidence."""
    correlator = AttackPathCorrelator()
    
    findings = [
        {
            "id": "finding_1",
            "type": "vulnerability",
            "cve": "CVE-2024-9999",
            "severity": "high"
        }
    ]
    
    vulnerabilities = [
        {
            "id": "vuln_1",
            "cve": "CVE-2024-9999",
            "type": "buffer_overflow",
            "severity": "high",
            "exploit_available": True
        }
    ]
    
    # Evidence that contradicts the vulnerability
    evidence = [
        {
            "id": "ev_contradict_1",
            "source": "patch_audit",
            "cve": "CVE-2024-9999",
            "status": "patched",
            "confidence": 0.95,
            "verified": True
        }
    ]
    
    result = correlator.correlate(
        findings=findings,
        vulnerabilities=vulnerabilities,
        evidence=evidence
    )
    
    # Path should still be generated but with reduced confidence due to contradictory evidence
    for path in result.attack_paths:
        # Contradictory evidence should reduce confidence
        assert path.overall_confidence < 0.7, (
            f"Path with contradictory evidence should have reduced confidence, "
            f"got {path.overall_confidence}"
        )
        
        # Check steps for contradicting evidence
        for step in path.steps:
            assert len(step.contradicting_evidence) > 0, (
                "Steps should detect contradictory evidence"
            )
    
    print("  PASS: test_contradictory_evidence")


def test_incomplete_attack_paths():
    """Test that incomplete attack paths (missing prerequisites/evidence) are handled."""
    correlator = AttackPathCorrelator()
    
    findings = [
        {
            "id": "finding_1",
            "type": "open_port",
            "description": "Port 22 (SSH) open"
        }
    ]
    
    vulnerabilities = [
        {
            "id": "vuln_1",
            "type": "privilege_escalation",
            "cve": "CVE-2024-escal",
            "severity": "high",
            "exploit_available": True
        }
    ]
    
    result = correlator.correlate(
        findings=findings,
        vulnerabilities=vulnerabilities
    )
    
    # Should generate paths but mark them as incomplete
    for path in result.attack_paths:
        for step in path.steps:
            # Incomplete paths should have missing_evidence identified
            assert len(step.missing_evidence) > 0, (
                "Incomplete paths should identify missing evidence"
            )
            
            # Steps should have validation tests identified
            assert len(step.validation_tests) > 0, (
                "Steps should have validation tests"
            )
    
    print("  PASS: test_incomplete_attack_paths")


def test_false_positives():
    """Test that false positive findings are properly handled."""
    correlator = AttackPathCorrelator()
    
    # Finding that is a false positive
    findings = [
        {
            "id": "finding_fp_1",
            "type": "vulnerability",
            "cve": "CFAKE-0001",  # Fake/crafted CVE
            "severity": "critical",
            "description": "Non-existent vulnerability"
        }
    ]
    
    vulnerabilities = [
        {
            "id": "vuln_fp_1",
            "cve": "CFAKE-0001",
            "type": "remote_code_execution",
            "severity": "critical",
            "exploit_available": True,
            "target_reachable": True
        }
    ]
    
    # No evidence supporting the vulnerability
    evidence = []
    
    result = correlator.correlate(
        findings=findings,
        vulnerabilities=vulnerabilities,
        evidence=evidence
    )
    
    # Should either produce no paths or paths with very low confidence
    for path in result.attack_paths:
        assert path.overall_confidence < 0.5, (
            f"False positive path should have low confidence, got {path.overall_confidence}"
        )
    
    # Verify that the system doesn't present unverified paths as confirmed
    for path in result.attack_paths:
        validated_steps = [s for s in path.steps if s.claim_status == CS.VALIDATED]
        # No steps should be validated without evidence
        for step in validated_steps:
            assert len(step.supporting_evidence) > 0, (
                "Validated steps must have supporting evidence"
            )
    
    print("  PASS: test_false_positives")


def test_claim_classification():
    """Test that claims are properly classified as observed, inferred, hypothesis, or validated."""
    correlator = AttackPathCorrelator()
    
    findings = [
        {
            "id": "finding_1",
            "type": "vulnerability",
            "cve": "CVE-2024-class",
            "severity": "high"
        }
    ]
    
    vulnerabilities = [
        {
            "id": "vuln_1",
            "cve": "CVE-2024-class",
            "type": "sql_injection",
            "severity": "high"
        }
    ]
    
    # Test with no evidence -> hypotheses
    result = correlator.correlate(
        findings=findings,
        vulnerabilities=vulnerabilities,
        evidence=[]
    )
    
    for path in result.attack_paths:
        for step in path.steps:
            # Without evidence, claims should be hypotheses
            classification_result = classifier_classify(
                step.claim, step.supporting_evidence, step.claim_status
            )
            assert "classification" in classification_result
            assert classification_result["classification"] in [
                "hypothesis", "hypothesis_supported", "inferred"
            ], f"Expected hypothesis classification, got {classification_result['classification']}"
    
    # Test with verified evidence -> observed or validated
    verified_evidence = [
        {
            "id": "ev_verified_1",
            "source": "scan_tool",
            "cve": "CVE-2024-class",
            "status": "verified",
            "confidence": 0.95,
            "verified": True
        }
    ]
    
    result2 = correlator.correlate(
        findings=findings,
        vulnerabilities=vulnerabilities,
        evidence=verified_evidence
    )
    
    for path in result2.attack_paths:
        for step in path.steps:
            if step.supporting_evidence:
                classification_result = classifier_classify(
                    step.claim, step.supporting_evidence, step.claim_status
                )
                # With verified evidence, should not be raw hypothesis
                assert classification_result["classification"] != "hypothesis" or classification_result["justification"].startswith("Hypothesis supported"), (
                    f"Expected supported classification with verified evidence, got {classification_result}"
                )
    
    print("  PASS: test_claim_classification")


def classifier_classify(claim: str, evidence: List[EvidenceItem], claim_status: CS) -> Dict[str, str]:
    """Helper to classify claims (from validation module)."""
    from hermes_shield.attack_path.validation import AttackPathValidator
    
    validator = AttackPathValidator()
    return validator.classify_claim(claim, evidence, claim_status)


def test_confidence_tracking():
    """Test that confidence is properly tracked through the correlation pipeline."""
    correlator = AttackPathCorrelator(confidence_threshold=0.7)
    
    # Rich findings with evidence
    findings = [
        {
            "id": "finding_1",
            "type": "vulnerability",
            "cve": "CVE-2024-conf",
            "severity": "critical",
            "description": "Critical vulnerability with exploit"
        }
    ]
    
    vulnerabilities = [
        {
            "id": "vuln_1",
            "cve": "CVE-2024-conf",
            "type": "critical_vuln",
            "severity": "critical",
            "exploit_available": True,
            "target_reachable": True
        }
    ]
    
    # Verified evidence supporting the vulnerability
    evidence = [
        {
            "id": "ev_1",
            "source": "authenticated_scan",
            "cve": "CVE-2024-conf",
            "status": "verified",
            "confidence": 0.9,
            "verified": True
        },
        {
            "id": "ev_2",
            "source": "config_audit",
            "cve": "CVE-2024-conf",
            "status": "verified",
            "confidence": 0.85,
            "verified": True
        }
    ]
    
    result = correlator.correlate(
        findings=findings,
        vulnerabilities=vulnerabilities,
        evidence=evidence
    )
    
    assert result.success
    
    # Paths with good evidence should have higher confidence
    for path in result.attack_paths:
        # Should have reasonable confidence with verified evidence
        assert path.overall_confidence > 0.5, (
            f"Path with verified evidence should have >0.5 confidence, got {path.overall_confidence}"
        )
        
        # Track evidence items
        assert path.total_evidence_items > 0, (
            "Path should have evidence items"
        )
        assert path.verified_evidence_items > 0, (
            "Path should have verified evidence items"
        )
    
    print("  PASS: test_confidence_tracking")


def test_multi_step_path():
    """Test multi-step attack path building from correlated findings."""
    correlator = AttackPathCorrelator()
    
    # Multiple findings that could chain together
    findings = [
        {
            "id": "finding_1",
            "type": "open_port",
            "description": "Port 22 (SSH) open"
        },
        {
            "id": "finding_2",
            "type": "vulnerability",
            "cve": "CVE-2024-sshd",
            "severity": "high",
            "description": "SSH vulnerability"
        },
        {
            "id": "finding_3",
            "type": "service",
            "description": "Apache web server on port 80"
        }
    ]
    
    vulnerabilities = [
        {
            "id": "vuln_1",
            "cve": "CVE-2024-sshd",
            "type": "privilege_escalation",
            "severity": "high",
            "exploit_available": True
        }
    ]
    
    evidence = [
        {
            "id": "ev_ssh_1",
            "source": "port_scan",
            "description": "Port 22 open",
            "cve": "CVE-2024-sshd",
            "confidence": 0.9,
            "verified": True
        },
        {
            "id": "ev_vuln_1",
            "source": "ssh_audit",
            "cve": "CVE-2024-sshd",
            "status": "verified",
            "confidence": 0.85,
            "verified": True
        }
    ]
    
    result = correlator.correlate(
        findings=findings,
        vulnerabilities=vulnerabilities,
        evidence=evidence
    )
    
    assert result.success
    
    # Should generate attack paths
    assert len(result.attack_paths) > 0, "Should generate attack paths from multiple findings"
    
    # Verify multi-step paths have proper structure
    for path in result.attack_paths:
        assert len(path.steps) > 0, "Path should have steps"
        
        # Steps should be properly ordered with prerequisites
        for i, step in enumerate(path.steps):
            assert isinstance(step.step_id, int), f"Step {i} should have step_id"
            assert isinstance(step.claim_status, ClaimStatus), f"Step {i} should have claim_status"
            assert step.claim_status in [
                ClaimStatus.OBSERVED, 
                ClaimStatus.INFERRED, 
                ClaimStatus.HYPOTHESIS, 
                ClaimStatus.VALIDATED
            ], f"Invalid claim status: {step.claim_status}"
            
            # Each step should have confidence
            assert 0.0 <= step.confidence <= 1.0, f"Step {i} confidence out of range: {step.confidence}"
    
    print("  PASS: test_multi_step_path")


def test_empty_input():
    """Test handling of empty or minimal input."""
    correlator = AttackPathCorrelator()
    
    result = correlator.correlate(
        findings=[],
        vulnerabilities=[],
        evidence=[]
    )
    
    # Should handle gracefully
    assert result.success  # Even with empty input, should succeed (return empty result)
    assert isinstance(result, CorrelateResult)
    
    print("  PASS: test_empty_input")


def test_tool_output_integration():
    """Test that tool output formats are properly handled."""
    correlator = AttackPathCorrelator()
    
    # Simulate tool output formats
    findings = [
        {
            "id": "tool_finding_1",
            "type": "sql_injection",
            "cve": "CVE-2024-tool-test",
            "severity": "high",
            "raw_output": "[Boolean] True - SQL injection detectable"
        },
        {
            "id": "tool_finding_2",
            "type": "open_port",
            "description": "Port 8080 open",
            "raw_output": "8080/tcp open http-proxy"
        }
    ]
    
    vulnerabilities = [
        {
            "id": "vuln_tool_1",
            "cve": "CVE-2024-tool-test",
            "type": "sql_injection",
            "severity": "high",
            "exploit_available": True
        }
    ]
    
    evidence = [
        {
            "id": "ev_tool_1",
            "source": "sql_map",
            "cve": "CVE-2024-tool-test",
            "status": "verified",
            "confidence": 0.92,
            "verified": True,
            "payload": "' OR 1=1--"
        }
    ]
    
    result = correlator.correlate(
        findings=findings,
        vulnerabilities=vulnerabilities,
        evidence=evidence
    )
    
    assert result.success
    assert len(result.attack_paths) > 0, "Should process tool-format findings"
    
    # Verify the path incorporates tool evidence properly
    for path in result.attack_paths:
        total_ev = path.total_evidence_items
        verified_ev = path.verified_evidence_items
        assert total_ev > 0, "Should incorporate tool evidence"
    
    print("  PASS: test_tool_output_integration")


def run_all_tests():
    """Run all attack path correlation tests."""
    tests = [
        test_basic_correlation,
        test_hallucinated_relationships,
        test_unsupported_conclusions,
        test_contradictory_evidence,
        test_incomplete_attack_paths,
        test_false_positives,
        test_claim_classification,
        test_confidence_tracking,
        test_multi_step_path,
        test_empty_input,
        test_tool_output_integration,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"  FAIL: {test.__name__}: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    print(f"{'='*50}")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)