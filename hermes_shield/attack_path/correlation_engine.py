"""Core attack path correlation engine.

Correlates individual security findings into multi-step attack paths using
structured reasoning. Distinguishes between observed facts, inferred
relationships, hypotheses, and validated attack paths.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Tuple
from enum import Enum


class ClaimStatus(Enum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    HYPOTHESIS = "hypothesis"
    VALIDATED = "validated"


class StepStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"


@dataclass
class EvidenceItem:
    id: str
    source: str
    claim: str
    content: Dict[str, Any]
    confidence: float = 1.0
    tags: List[str] = field(default_factory=list)
    verified: bool = False


@dataclass
class AttackStep:
    step_id: int
    name: str
    description: str
    status: StepStatus
    claim_status: ClaimStatus
    claim: str
    supporting_evidence: List[EvidenceItem] = field(default_factory=list)
    contradicting_evidence: List[EvidenceItem] = field(default_factory=list)
    prerequisite_steps: List[int] = field(default_factory=list)
    success_probability: float = 0.5
    confidence: float = 0.5
    missing_evidence: List[str] = field(default_factory=list)
    validation_tests: List[str] = field(default_factory=list)


@dataclass
class AttackPath:
    path_id: str
    name: str
    description: str
    steps: List[AttackStep] = field(default_factory=list)
    overall_confidence: float = 0.0
    overall_impact: str = "medium"
    validated: bool = False
    total_evidence_items: int = 0
    verified_evidence_items: int = 0
    missing_evidence: List[str] = field(default_factory=list)
    validation_tests_required: List[str] = field(default_factory=list)


@dataclass
class ValidationResult:
    step_id: int
    valid: bool
    confidence_change: float
    reason: str
    evidence_added: List[EvidenceItem] = field(default_factory=list)


@dataclass
class CorrelateResult:
    success: bool
    attack_paths: List[AttackPath] = field(default_factory=list)
    rejected_paths: List[AttackPath] = field(default_factory=list)
    total_paths_considered: int = 0
    hypotheses_generated: int = 0
    paths_validated: int = 0
    confidence_threshold: float = 0.7


class AttackPathCorrelator:
    """Correlates security findings into multi-step attack paths."""

    def __init__(self, config=None,
                    confidence_threshold=None,
                    max_path_length=None,
                    require_validation=None):
        self.config = config or {}
        self.confidence_threshold = confidence_threshold or self.config.get("confidence_threshold", 0.7)
        self.max_path_length = max_path_length or self.config.get("max_path_length", 7)
        self.require_validation = require_validation if require_validation is not None else self.config.get("require_validation", True)

    def correlate(self, findings, identities=None, permissions=None,
                  vulnerabilities=None, network_relationships=None,
                  evidence=None, previous_findings=None):
        context = self._build_context(findings, identities, permissions,
                                      vulnerabilities, network_relationships,
                                      evidence, previous_findings)
        hypotheses = self._generate_hypotheses(context)
        attack_paths = self._build_attack_paths(hypotheses, context)
        validated_paths = self._validate_paths(attack_paths, context)
        accepted_paths = self._filter_by_confidence(validated_paths)
        accepted_paths.sort(key=lambda p: p.overall_confidence, reverse=True)
        return CorrelateResult(
            success=True,
            attack_paths=accepted_paths,
            total_paths_considered=len(attack_paths) + len(validated_paths),
            hypotheses_generated=len(hypotheses),
            paths_validated=len(validated_paths),
            confidence_threshold=self.confidence_threshold,
        )

    def _build_context(self, findings, identities, permissions,
                       vulnerabilities, network_relationships, evidence,
                       previous_findings):
        context = {"findings": findings or [],
                   "identities": identities or [],
                   "permissions": permissions or [],
                   "vulnerabilities": vulnerabilities or [],
                   "network_relationships": network_relationships or [],
                   "evidence": evidence or [],
                   "previous_findings": previous_findings or []}
        indexed = {"vuln_by_cve": {}, "vuln_by_type": {},
                   "evidence_by_source": {}}
        for finding in context["findings"]:
            cve = finding.get("cve", finding.get("id", ""))
            indexed["vuln_by_cve"][cve] = finding
        for ev in context["evidence"]:
            source = ev.get("source", "unknown")
            indexed["evidence_by_source"].setdefault(source, []).append(ev)
        context["indexed"] = indexed
        return context

    def _generate_hypotheses(self, context):
        hypotheses = []
        indexed = context["indexed"]
        vulnerabilities = context["vulnerabilities"]

        # Always generate at least one hypothesis per vulnerability
        for vuln in vulnerabilities or []:
            cve = vuln.get("cve", vuln.get("id", ""))
            if not cve:
                continue
            vuln_type = vuln.get("type", "unknown")
            related_findings = indexed["vuln_by_cve"].get(cve, [])
            hyp = {"id": "hyp_" + cve + "_0",
                   "type": "vulnerability_exploitation",
                   "claim": "Exploit " + vuln_type + " (" + cve + ") to gain initial access",
                   "claim_status": "hypothesis",
                   "confidence": 0.5,
                   "prerequisites": [],
                   "supporting_evidence": [],
                   "contradicting_evidence": [],
                   "metadata": {"vulnerability_type": vuln_type,
                                "related_findings_count": len(related_findings)}}
            hypotheses.append(hyp)

        # Generate hypotheses from identities (privilege escalation)
        identities = context.get("identities", [])
        for ident in identities:
            ident_id = ident.get("id", "unknown")
            ident_perms = ident.get("permissions", [])
            for i, perm in enumerate(ident_perms):
                escalation_candidates = [p for p in ident_perms[i+1:]
                                         if perm.lower() in p.lower()]
                if escalation_candidates:
                    hypotheses.append({"id": "hyp_" + ident_id + "_0",
                                       "type": "privilege_escalation",
                                       "claim": "Escalate from " + perm + " to elevated permissions",
                                       "claim_status": "hypothesis",
                                       "confidence": 0.6,
                                       "prerequisites": [perm],
                                       "supporting_evidence": [],
                                       "contradicting_evidence": []})

        # Generate hypotheses from findings
        for finding in context["findings"] or []:
            finding_type = finding.get("type", "").lower()
            if "data" in finding_type or "exfil" in finding_type:
                hypotheses.append({"id": "hyp_data_0",
                                   "type": "data_exfiltration",
                                   "claim": "Exfiltrate data via " + finding.get("method", ""),
                                   "claim_status": "hypothesis",
                                   "confidence": 0.55,
                                   "prerequisites": [finding.get("id", "")],
                                   "supporting_evidence": [],
                                   "contradicting_evidence": []})

        # Deduplicate by claim
        unique = []
        seen = set()
        for hyp in hypotheses:
            claim = hyp.get("claim", "")
            if claim not in seen:
                seen.add(claim)
                unique.append(hyp)
            else:
                for existing in unique:
                    if existing.get("claim") == claim:
                        if hyp.get("confidence", 0) > existing.get("confidence", 0):
                            existing.update(hyp)
                        break
        return unique

    def _can_escalate(self, current, target):
        current_lower = current.lower()
        target_lower = target.lower()
        if current_lower in target_lower:
            return True
        return False

    def _build_attack_paths(self, hypotheses, context):
        attack_paths = []
        for hyp in hypotheses:
            path = AttackPath(path_id="path_" + hyp["id"],
                              name="Attack path: " + hyp.get("type", "unknown"),
                              description="Exploit " + hyp.get("type", "unknown"),
                              steps=[],
                              overall_confidence=hyp.get("confidence", 0.5))
            # Add supporting evidence from context
            supporting_ev = []
            contradicting_ev = []
            hyp_type = hyp.get("type", "")
            # Simple evidence matching: match by CVE if available
            for source, ev_list in context.get("indexed", {}).get("evidence_by_source", {}).items():
                for ev in ev_list:
                    ev_cve = ev.get("cve", "")
                    if hyp_type == "vulnerability_exploitation" and ev_cve:
                        if ev_cve in hyp["id"]:
                            if ev.get("status") in ["verified", "detected"]:
                                supporting_ev.append(ev)
                            if ev.get("status") == "patched":
                                contradicting_ev.append(ev)
            step = AttackStep(step_id=1,
                              name=hyp.get("type", "unknown"),
                              description=hyp.get("claim", ""),
                              status=StepStatus.PENDING,
                              claim_status=ClaimStatus.HYPOTHESIS,
                              claim=hyp.get("claim", ""),
                              supporting_evidence=supporting_ev,
                              contradicting_evidence=contradicting_ev,
                              prerequisite_steps=[],
                              success_probability=hyp.get("confidence", 0.5),
                              confidence=hyp.get("confidence", 0.5),
                              missing_evidence=self._identify_missing_evidence(hyp),
                              validation_tests=self._identify_validation_tests(hyp))
            path.steps.append(step)
            path.total_evidence_items = len(supporting_ev)
            path.verified_evidence_items = len([e for e in supporting_ev if e.get("verified", False)])
            attack_paths.append(path)
        return attack_paths

    def _identify_missing_evidence(self, hyp):
        missing = []
        claim_status = hyp.get("claim_status", "")
        is_hyp = isinstance(claim_status, ClaimStatus) and claim_status == ClaimStatus.HYPOTHESIS
        if not isinstance(claim_status, ClaimStatus) and claim_status == "hypothesis":
            is_hyp = True
        if is_hyp:
            missing.append("supporting_evidence")
        return missing

    def _identify_validation_tests(self, hyp):
        hyp_type = hyp.get("type", "")
        tests = []
        if hyp_type == "vulnerability_exploitation":
            tests = ["Verify exploit works", "Confirm no side effects"]
        elif hyp_type == "privilege_escalation":
            tests = ["Attempt escalation", "Audit permission changes"]
        elif hyp_type == "data_exfiltration":
            tests = ["Identify data assets", "Verify exfiltration method"]
        if not tests:
            tests = ["General verification"]
        return tests

    def _validate_paths(self, attack_paths, context):
        validated = []
        for path in attack_paths:
            if path.steps:
                step_confidences = [s.confidence for s in path.steps]
                path.overall_confidence = sum(step_confidences) / len(step_confidences)
            else:
                path.overall_confidence = 0.0
            total_ev = path.total_evidence_items
            verified_ev = path.verified_evidence_items
            total_contradicting = 0  # Simplified
            if total_ev > 0:
                evidence_ratio = verified_ev / total_ev
                path.overall_confidence *= (1.0 + 0.1 * evidence_ratio)
            if path.overall_confidence > 0.5:  # Simple threshold
                validated.append(path)
        return validated

    def _filter_by_confidence(self, attack_paths):
        return [path for path in attack_paths
                if path.overall_confidence >= self.confidence_threshold
                or path.overall_confidence >= 0.3]


class AttackPathValidator:
    """Validates individual steps and overall attack paths."""

    def __init__(self, correlator=None):
        self.correlator = correlator

    def validate_step(self, step, available_evidence, test_results=None):
        reasons = []
        evidence_added = []
        confidence_change = 0.0
        valid = True
        available_ids = {e.id for e in available_evidence}
        available_by_claim = {}
        for e in available_evidence:
            claim = e.claim.lower()
            available_by_claim.setdefault(claim, []).append(e)
        for contradict in step.contradicting_evidence:
            if contradict.id in available_ids:
                valid = False
                reasons.append("Contradicted by observed evidence")
                confidence_change -= 0.35
                evidence_added.append(contradict)
        supporting_claim = step.claim.lower()
        supporting_matches = available_by_claim.get(supporting_claim, [])
        if not supporting_matches and step.claim_status == "hypothesis":
            valid = False
            reasons.append("No supporting evidence for hypothesis")
            confidence_change -= 0.4
        if supporting_matches:
            verified_ratio = len([e for e in supporting_matches if e.get("verified", False)]) / len(supporting_matches)
            if verified_ratio >= 0.7:
                confidence_change += 0.2
            elif verified_ratio >= 0.3:
                confidence_change += 0.05
            else:
                confidence_change -= 0.1
            evidence_added.extend(supporting_matches)
        else:
            if step.claim_status == "observed":
                valid = False
                reasons.append("Observed claim lacks supporting evidence")
                confidence_change -= 0.2
        if test_results:
            test_valid = test_results.get("valid", True)
            test_impact = test_results.get("confidence_impact", 0.0)
            if not test_valid:
                valid = False
                reasons.append("Empirical test failed")
            confidence_change += test_impact
        new_confidence = max(0.0, min(1.0, step.confidence + confidence_change))
        if new_confidence < 0.3 and step.claim_status == "hypothesis":
            valid = False
            reasons.append("Confidence too low for hypothesis")
        if step.claim_status == "observed" and valid:
            pass
        from hermes_shield.attack_path.correlation_engine import ValidationResult
        return ValidationResult(step_id=step.step_id,
                                valid=valid,
                                confidence_change=confidence_change,
                                reason="; ".join(reasons) if reasons else "Step validated",
                                evidence_added=evidence_added)

    def validate_path(self, path):
        all_step_results = []
        overall_valid = True
        total_confidence_change = 0.0
        for step in path.steps:
            step_evidence = step.supporting_evidence + step.contradicting_evidence
            result = self.validate_step(step, step_evidence)
            all_step_results.append(result)
            if not result.valid:
                overall_valid = False
            total_confidence_change += result.confidence_change
        if overall_valid:
            path.validated = True
        else:
            path.validated = False
        return ValidationResult(step_id=path.steps[0].step_id if path.steps else 0,
                                valid=overall_valid,
                                confidence_change=total_confidence_change,
                                reason="Path validated" if overall_valid else "Path failed validation",
                                evidence_added=[])