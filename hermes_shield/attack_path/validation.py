"""Attack path validation module.

Validates individual attack path steps and overall paths with evidence tracking,
confidence adjustment, and clear distinction between observed facts and inferred claims.
"""

from typing import List, Optional, Dict, Any
from .correlation_engine import (
    EvidenceItem, AttackStep, AttackPath, ClaimStatus, StepStatus,
    ValidationResult, ClaimStatus as CS
)


class AttackPathValidator:
    """Validates individual steps and overall attack paths.
    
    Tracks evidence, adjusts confidence, and ensures claims are properly
    classified as observed, inferred, hypothesis, or validated.
    """
    
    def __init__(self, correlator=None):
        self.correlator = correlator
    
    def validate_step(
        self, 
        step: AttackStep, 
        available_evidence: List[EvidenceItem],
        test_results: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Validate a single attack step against available evidence.
        
        Returns ValidationResult with validity status, confidence change,
        and reason explaining the determination.
        """
        reasons = []
        evidence_added = []
        confidence_change = 0.0
        valid = True
        
        # Normalize available evidence IDs for comparison
        available_ids = {e.id for e in available_evidence}
        available_by_claim = {}
        for e in available_evidence:
            claim = e.claim.lower()
            available_by_claim.setdefault(claim, []).append(e)
        
        # 1. Check for contradicting evidence
        for contradict in step.contradicting_evidence:
            if contradict.id in available_ids:
                valid = False
                reasons.append(
                    f"Contradicted by observed evidence: {contradict.claim}"
                )
                confidence_change -= 0.35
                evidence_added.append(contradict)
        
        # 2. Check supporting evidence sufficiency
        supporting_claim = step.claim.lower()
        supporting_matches = available_by_claim.get(supporting_claim, [])
        
        if not supporting_matches and step.claim_status == ClaimStatus.HYPOTHESIS:
            valid = False
            reasons.append(
                "No supporting evidence for hypothesis - cannot proceed without verification"
            )
            confidence_change -= 0.4
        
        # 3. Check for missing evidence requirements
        missing_ids = {m for m in step.missing_evidence}
        found_missing = missing_ids & available_ids
        still_missing = missing_ids - available_ids
        
        if still_missing and step.clime_status == ClaimStatus.HYPOTHESIS:
            valid = False
            reasons.append(
                f"Missing required evidence: {', '.join(list(still_missing)[:3])}"
            )
            confidence_change -= len(still_missing) * 0.15
        
        # 4. Evaluate evidence quality and relevance
        if supporting_matches:
            verified_ratio = len(
                [e for e in supporting_matches if e.get("verified", False)]
            ) / len(supporting_matches)
            
            if verified_ratio >= 0.7:
                # Good evidence - boost confidence
                confidence_change += 0.2
            elif verified_ratio >= 0.3:
                # Partial evidence - neutral
                confidence_change += 0.05
            else:
                # Weak evidence - reduce confidence
                confidence_change -= 0.1
            
            # Track which evidence supports this step
            evidence_added.extend(supporting_matches)
        else:
            # No matching evidence found - depends on claim status
            if step.claim_status == ClaimStatus.OBSERVED:
                # Observed claims should have evidence; if not, questionable
                valid = False
                reasons.append("Observed claim lacks supporting evidence")
                confidence_change -= 0.2
            # For hypotheses, we'll handle in step 2
        
        # 5. Apply test results if provided
        if test_results:
            test_valid = test_results.get("valid", True)
            test_confidence_impact = test_results.get("confidence_impact", 0.0)
            
            if not test_valid:
                valid = False
                reasons.append(f"Empirical test failed: {test_results.get('reason', 'unknown')}")
            
            confidence_change += test_confidence_impact
        
        # 6. Final confidence adjustment and validity determination
        new_confidence = max(0.0, min(1.0, step.confidence + confidence_change))
        
        # If confidence drops below viability threshold, invalidate
        if new_confidence < 0.3 and step.claim_status == ClaimStatus.HYPOTHESIS:
            valid = False
            reasons.append(
                f"Confidence too low for hypothesis: {new_confidence:.2f}"
            )
        
        # Step with OBSERVED status that passes evidence check retains validity
        if step.claim_status == ClaimStatus.OBSERVED and valid:
            # Observed claims are treated as provisionally valid
            pass
        
        return ValidationResult(
            step_id=step.step_id,
            valid=valid,
            confidence_change=confidence_change,
            reason="; ".join(reasons) if reasons else "Step validated",
            evidence_added=evidence_added,
        )
    
    def validate_path(self, path: AttackPath) -> ValidationResult:
        """Validate an entire multi-step attack path.
        
        Validates each step sequentially, tracking cumulative confidence
        changes and evidence integrity.
        """
        all_step_results = []
        overall_valid = True
        total_confidence_change = 0.0
        cumulative_evidence = []
        
        for step in path.steps:
            # Collect all evidence related to this step
            step_evidence = step.supporting_evidence + step.contradicting_evidence
            cumulative_evidence.extend(step_evidence)
            
            # Validate step
            result = self.validate_step(step, step_evidence)
            all_step_results.append(result)
            
            if not result.valid:
                overall_valid = False
            
            total_confidence_change += result.confidence_change
        
        # Determine overall path validity
        if overall_valid and path.overall_confidence >= (self.correlator.confidence_threshold 
                                                         if self.correlator else 0.7):
            path.validated = True
        else:
            path.validated = False
        
        # Calculate average confidence change
        avg_confidence_change = (
            total_confidence_change / len(path.steps) 
            if path.steps else 0.0
        )
        
        # Build reason summary
        reason_parts = []
        if overall_valid:
            valid_count = sum(1 for r in all_step_results if r.valid)
            reason_parts.append(
                f"{valid_count}/{len(all_step_results)} steps validated"
            )
        else:
            invalid_count = sum(1 for r in all_step_results if not r.valid)
            reason_parts.append(
                f"{invalid_count}/{len(all_step_results)} step(s) failed validation"
            )
        
        if path.overall_confidence >= 0.7:
            reason_parts.append(
                f"Overall path confidence {path.overall_confidence:.2f} meets threshold"
            )
        else:
            reason_parts.append(
                f"Overall path confidence {path.overall_confidence:.2f} below threshold"
            )
        
        if path.validated:
            reason_parts.append("Path fully validated - ready for remediation planning")
        else:
            reason_parts.append("Path requires additional evidence or modification")
        
        return ValidationResult(
            step_id=path.steps[0].step_id if path.steps else 0,
            valid=overall_valid,
            confidence_change=total_confidence_change,
            reason="; ".join(reason_parts),
            evidence_added=cumulative_evidence,
        )
    
    def classify_claim(self, claim: str, evidence: List[EvidenceItem], 
                       claim_status: ClaimStatus = ClaimStatus.HYPOTHESIS) -> Dict[str, str]:
        """Classify a claim as observed, inferred, hypothesis, or validated.
        
        Returns dict with classification and justification.
        """
        if not evidence:
            return {
                "classification": claim_status.value,
                "justification": f"No evidence found for claim: {claim[:80]}..."
            }
        
        verified_evidence = [e for e in evidence if e.get("verified", False)]
        unverified_evidence = [e for e in evidence if not e.get("verified", False)]
        
        if claim_status == ClaimStatus.OBSERVED:
            if verified_evidence and len(verified_evidence) >= len(evidence) * 0.8:
                return {
                    "classification": "observed_verified",
                    "justification": f"Claim supported by {len(verified_evidence)} verified evidence items"
                }
            elif unverified_evidence:
                return {
                    "classification": "observed_unverified",
                    "justification": f"Claim has {len(unverified_evidence)} unverified evidence items"
                }
            else:
                return {
                    "classification": "observed",
                    "justification": "Claim marked observed but no evidence available"
                }
        
        if claim_status == ClaimStatus.VALIDATED:
            if verified_evidence and all(e.get("verified", False) for e in evidence):
                return {
                    "classification": "validated_verified",
                    "justification": f"Claim validated by {len(evidence)} pieces of verified evidence"
                }
            else:
                return {
                    "classification": "validated_unverified",
                    "justification": f"Claim marked validated but evidence mixed: {len(verified_evidence)}/{len(evidence)} verified"
                }
        
        if claim_status == ClaimStatus.INFERRED:
            if verified_evidence:
                inferred_from = [e.claim for e in verified_evidence[:3]]
                return {
                    "classification": "inferred_supported",
                    "justification": f"Inferred from: {'; '.join(inferred_from)}"
                }
            else:
                return {
                    "classification": "inferred_unverified",
                    "justification": "Inferred claim without verified supporting evidence"
                }
        
        # Default: HYPOTHESIS
        if verified_evidence and len(verified_evidence) >= len(evidence) * 0.5:
            return {
                "classification": "hypothesis_ supported",
                "justification": f"Hypothesis supported by {len(verified_evidence)} verified evidence items out of {len(evidence)} total"
            }
        
        return {
            "classification": "hypothesis",
            "justification": f"Unverified hypothesis: {claim[:60]}..."
        }