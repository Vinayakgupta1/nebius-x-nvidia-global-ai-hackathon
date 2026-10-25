# HermesShield Memory Architecture

## Overview

The HermesShield memory system provides persistent security context across agent sessions while enforcing strict secret handling policies. Memory is organized as structured, typed entries with explicit state classification and revalidation requirements.

## Memory Categories

| Category | Description | Retention |
|----------|-------------|-----------|
| `target_environment` | Target IP ranges, domains, network topology, services discovered | Long-term |
| `findings` | Vulnerabilities, misconfigurations, exposed services | Long-term |
| `tests_executed` | Tools run, parameters used, results summary | Medium-term |
| `attack_paths` | Chained vulnerabilities, lateral movement possibilities | Long-term |
| `hypotheses` | Unverified assumptions about target state | Short-term |
| `false_positives` | Findings invalidated on revalidation | Long-term |
| `tested_controls` | Security controls tested (WAF, IPS, auth mechanisms) | Medium-term |
| `remediation_state` | Tracking of reported issues (open, in-progress, fixed) | Long-term |
| `assessment_history` | Session metadata, timestamps, operator, scope | Long-term |

## Memory State Classification

Every memory entry MUST have exactly one state:

| State | Meaning | Action Required |
|-------|---------|-----------------|
| `KNOWN` | Verified true, high confidence | Use directly, cite as evidence |
| `HYPOTHESIS` | Plausible but unverified | Must revalidate before use |
| `VERIFIED` | Recently confirmed (within TTL) | Use directly, cite with timestamp |
| `REJECTED` | Proven false or invalid | Do not use; cite as negative evidence |
| `OUTDATED` | Exceeded TTL, needs refresh | Must revalidate before use |

## Memory Entry Schema

```json
{
  "id": "uuid",
  "category": "findings",
  "state": "KNOWN",
  "content": {
    "title": "SQL Injection in /api/search",
    "description": "Unsanitized input in search parameter",
    "severity": "HIGH",
    "evidence": ["tool_output_id_1", "tool_output_id_2"]
  },
  "target": "192.168.1.100",
  "session_id": "hermes_2026_001",
  "created_at": "2026-10-03T10:00:00Z",
  "updated_at": "2026-10-03T10:00:00Z",
  "ttl_seconds": 86400,
  "confidence": 0.95,
  "tags": ["sql_injection", "web_app"],
  "source_tool": "vulnerability_validation",
  "revalidation_required": false
}
```

## Secret Handling Policy

**NEVER persist:**
- API keys (any format)
- Passwords / passphrases
- Private keys (SSH, TLS, PGP)
- Session tokens / JWTs / cookies
- Raw credentials from tool output
- Database connection strings with credentials
- Cloud provider secrets

**Redaction rules applied before persistence:**
- Regex patterns for common secret formats
- Entropy-based detection for high-entropy strings
- Context-aware redaction (password=, api_key=, token=, etc.)

## Memory Write Policy

| Operation | Conditions |
|-----------|------------|
| `CREATE` | New finding, hypothesis, or test result |
| `UPDATE` | State change, confidence adjustment, evidence added |
| `MERGE` | Duplicate finding consolidation |
| `EXPIRE` | TTL exceeded → state → OUTDATED |
| `REDACT` | Secret detection → automatic redaction |

## Memory Retrieval Policy

| Query Type | Behavior |
|------------|----------|
| `get_known(target)` | Returns only KNOWN/VERIFIED entries |
| `get_hypotheses(target)` | Returns HYPOTHESIS entries for revalidation |
| `get_outdated(target)` | Returns OUTDATED entries needing refresh |
| `get_by_state(state)` | Filter by single state |
| `get_attack_paths(target)` | Returns chained findings with KNOWN/VERIFIED states |
| `get_remediation(target)` | Returns remediation tracking entries |

## Revalidation Protocol

When retrieving `HYPOTHESIS` or `OUTDATED` entries:

1. Agent MUST invoke appropriate validation tool
2. On confirmation: state → `VERIFIED` (or `KNOWN`)
3. On rejection: state → `REJECTED` with evidence
4. On timeout/error: state → `HYPOTHESIS` (preserve for retry)

## TTL Configuration

| Category | Default TTL | Max TTL |
|----------|-------------|---------|
| findings | 7 days | 30 days |
| hypotheses | 24 hours | 72 hours |
| attack_paths | 14 days | 60 days |
| tested_controls | 30 days | 90 days |
| remediation_state | 90 days | 365 days |

## Storage

- File-based: JSON Lines (`.jsonl`) per category per target
- Index: SQLite for fast querying
- Encryption: Optional AES-256 at rest (not implemented in demo)

## Demonstration Flow

### SESSION 1 - Discovery
1. Agent starts with target `192.168.1.100`
2. Runs network_reconnaissance → discovers port 80, 443
3. Runs http_reconnaissance → identifies Apache 2.4.41
4. Runs vulnerability_validation → finds CVE-2021-41773 (path traversal)
5. Memory stores: finding (VERIFIED), attack_path (HYPOTHESIS), tested_control (KNOWN)

### SESSION 2 - Continuation
1. New agent instance starts with same target
2. Retrieves memory: finds VERIFIED finding, HYPOTHESIS attack path
3. Agent revalidates HYPOTHESIS attack path → confirms exploit chain
4. Updates: attack_path state → VERIFIED, adds remediation tracking
5. Memory now has complete attack chain with remediation tracking

## Integration Points

- Agent initialization: `memory = MemoryStore(target="192.168.1.100")`
- Tool execution: `memory.record(tool_name, result)`
- Retrieval: `memory.get_known("192.168.1.100")`
- Revalidation: `memory.revalidate(entry_id, validation_result)`

## API Reference

### MemoryStore

```python
from hermes_shield.memory import MemoryStore

store = MemoryStore(target="192.168.1.100", session_id="hermes_001")

# Record finding
entry_id = store.record_finding(
    title="Path Traversal",
    description="CVE-2021-41773 in Apache",
    severity="HIGH",
    evidence=["tool_output_1"],
    state="VERIFIED"
)

# Retrieve known findings
findings = store.get_known(target="192.168.1.100")

# Revalidate hypothesis
store.revalidate(entry_id, confirmed=True, evidence=["new_evidence"])
```

### Query Methods

- `get_known(target)` - KNOWN + VERIFIED entries
- `get_hypotheses(target)` - HYPOTHESIS entries
- `get_outdated(target)` - OUTDATED entries
- `get_by_category(category, target)` - All states for category
- `get_attack_paths(target)` - Chained findings
- `get_remediation(target)` - Remediation tracking
- `search(query, target=None)` - Full-text search

## Security Guarantees

1. **No secret persistence** - Automated redaction before write
2. **State integrity** - State transitions logged and validated
3. **Audit trail** - All write operations logged with session ID
4. **TTL enforcement** - Automatic OUTDATED transition
5. **Revalidation enforcement** - HYPOTHESIS/OUTDATED flagged on retrieval