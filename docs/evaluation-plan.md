# HermesShield Evaluation Plan

## Overview
This document defines how HermesShield will be evaluated for the hackathon demonstration. Evaluation focuses on reliability, correctness of architecture, and demonstrable capabilities.

## Evaluation Dimensions

### 1. Functional Correctness
Criteria: Does each component perform its intended function as documented?

| Dimension | Test | Pass Condition |
|-----------|------|----------------|
| Hermes Agent | Audit cycle completes from plan to report | All steps execute without unhandled exceptions; report is generated |
| Nemotron 3 Ultra 550B | Model inference via Nebius returns valid responses | API call succeeds; response is parseable JSON or text |
| Nebius Token Factory | Request routing and token tracking | Request completes; token count reported; no rate limit errors on demo suite |
| NemoClaw | Subprocess isolation enforcement | Commands outside allowlist are rejected; sandboxed commands execute |
| OpenShell | Session containment | Session terminates after audit cycle; no lingering processes |
| Tool Execution | Command output capture | stdout/stderr captured; exit code recorded; timeout enforced |
| Evidence Collector | JSON evidence format | Every tool output produces valid JSON with required fields |
| Reporting Engine | Markdown report generation | Report contains executive summary, findings, evidence references |
| Skills Registry | Capability-to-tool mapping | Skill name resolves to correct tool set; precondition check passes |

### 2. Security Boundary Evaluation
Criteria: Are security controls present and effective at documented boundaries?

| Boundary | Test | Pass Condition |
|----------|------|----------------|
| Subprocess Isolation | Tool process cannot access parent process memory | Tool subprocess exits cleanly; no shared memory regions |
| Command Allowlisting | Disallowed commands are rejected | Command not in allowlist returns policy violation error |
| Environment Filtering | Only allowed env vars are passed to tools | Process environment subset of ALLOWED_ENV |
| Evidence Redaction | Sensitive data is masked before persistence | Evidence file contains no raw secrets, passwords, or PII |
| File Permissions | Evidence files have restricted access | `chmod 600` or equivalent on evidence files |
| API Key Management | No hardcoded credentials in source | API keys loaded from environment at runtime only |
| Network Enforcement | Tool subprocesses have no unintended outbound access | Network connections from tool processes are blocked or allowlisted |

### 3. Architecture Adherence
Criteria: Does the implemented system match the documented architecture?

| Aspect | Verification Method |
|--------|---------------------|
| Component layout | Component names and roles match architecture.md |
| Data flow paths | Observed flows follow described sequences |
| Status markings | Every component marked IMPLEMENTED/TO BUILD/OPTIONAL |
| Boundary definitions | Trust boundaries and security controls match security-model.md |
| Scope consistency | Out-of-scope items not attempted in demo |

### 4. Demo Reliability
Criteria: Can the system be reliably demonstrated without manual intervention?

| Metric | Target | Measurement |
|--------|--------|-------------|
| Startup time | < 30 seconds | From `hermes shield start` to ready state |
| Audit cycle time | < 2 minutes | From audit request to report generation |
| Failure recovery | No manual state reset required | Failed audit can be re-run automatically |
| Deterministic output | Same inputs produce same report structure | Re-running same audit on same target produces consistent format |
| Error handling | Graceful degradation | Missing tool or API key produces clear error, not crash |

## Test Suites

### Suite A: Unit Tests (Python/pytest)

```python
# test_unit.py
def test_evidence_format():
    """Evidence items have required fields."""
    evidence = EvidenceCollector.collect({
        "command": "nmap -sV target",
        "stdout": "",
        "stderr": "",
        "exit_code": 0
    })
    assert "timestamp" in evidence
    assert "skill" in evidence
    assert "tool" in evidence
    assert "target" in evidence
    assert "command" in evidence

def test_redaction():
    """Sensitive data is redacted before evidence persistence."""
    result = EvidenceCollector.collect({
        "command": "echo 'password=secret123'",
        "stdout": "password=secret123",
        "stderr": "",
        "exit_code": 0
    })
    redacted = EvidenceCollector.redact(result)
    assert "secret123" not in redacted["stdout"]