# HermesShield Security Tools Documentation

## Tool Abstraction Framework

All security tools in HermesShield extend `BaseTool` from `tools/__init__.py`. This framework enforces security guarantees across all implementations:

### Security Guarantees (Enforced by BaseClass)

| Control | Mechanism |
|---------|-----------|
| Input validation | JSON Schema validation via `INPUT_SCHEMA` |
| Timeout enforcement | `subprocess.Popen.communicate(timeout=X)` in `_execute_subprocess` |
| Output sanitization | `_sanitize_output()` applies regex redaction patterns |
| Structured return | Always returns `ToolResult` (never raw shell access) |
| Audit logging | `_log_audit()` records every action with timestamp |
| No host secret exposure | `ALLOWED_ENV` filtering; redaction before persistence |
| No privilege escalation | Subprocess execution with sandboxed `cwd` and filtered env |

### Tool Registration

Tools are registered in the global `tool_registry` and discoverable by name:

```python
from tools import tool_registry
tool_instance = tool_registry.create_instance("network_reconnaissance")
```

### Tool Execution Flow

```text
[Input] -> validate_input_schema -> get_target -> execute -> sanitize_output
     --> generate_evidence -> _log_audit -> return ToolResult
```

---

## Implemented Tools

### 1. network_reconnaissance

| Field | Value |
|-------|-------|
| **Tool Name** | `network_reconnaissance` |
| **Purpose** | Network reconnaissance using nmap for port scanning and service detection |
| **Input Schema** | `{ "target": "string", "scan_type": "quick|full|service", "ports": "range" }` |
| **Output Schema** | `{ "target": "string", "open_ports": [int], "services": [{port, service, version}], "os_family": "string" }` |
| **Permissions** | filesystem: `read_only`, network: `target_only` |
| **Timeout** | 60 seconds |
| **Risk Classification** | `LOW` |
| **Evidence Generated** | `nmap_output` (sanitized stdout, parsed services) |
| **Failure Behavior** | Returns `success=False` with error string; never exposes host secrets |
| **Allowed Commands** | `nmap -sS -T4 -p <ports> <target>`, `nmap -sV -T4 -p <ports> <target>` |
| **Blocked Arguments** | `-A` (OS detection), `--script` (arbitrary scripts), `-e` (interface spec) |

### 2. http_reconnaissance

| Field | Value |
|-------|-------|
| **Tool Name** | `http_reconnaissance` |
| **Purpose** | HTTP reconnaissance for technology fingerprinting and URL discovery |
| **Input Schema** | `{ "target": "http://url or https://url", "check_tech": "boolean", "discover_urls": "boolean" }` |
| **Output Schema** | `{ "target": "string", "technology_fingerprint": {cms, framework, web_server}, "discovered_urls": [string] }` |
| **Permissions** | filesystem: `read_only`, network: `target_only` |
| **Timeout** | 30 seconds |
| **Risk Classification** | `LOW` |
| **Evidence Generated** | `whatweb_output`, `gau_output` (both sanitized) |
| **Failure Behavior** | Returns partial results if one tool fails; never exposes credentials in stdout |
| **Allowed Tools** | `whatweb -v -a 0 <target>`, `gau <target>` |
| **Blocked** | Arbitrary HTTP GET/POST; no cookie manipulation; no header injection |

### 3. service_enumeration

| Field | Value |
|-------|-------|
| **Tool Name** | `service_enumeration` |
| **Purpose** | Service enumeration and version detection on target ports |
| **Input Schema** | `{ "target": "string", "ports": "range", "include_banner": "boolean" }` |
| **Output Schema** | `{ "target": "string", "services": [{port, service, version, banner}] }` |
| **Permissions** | filesystem: `read_only`, network: `target_only` |
| **Timeout** | 60 seconds |
| **Risk Classification** | `LOW` |
| **Evidence Generated** | `nmap_service_output` (parsed nmap -sV output) |
| **Failure Behavior** | Returns empty services list; exit code indicates scan success/failure |
| **nmap Flags** | `-sV` (service version detection only); `--script banner` only |
| **Blocked** | No arbitrary banner grabbing; no port scanning beyond specified ports |

### 4. configuration_auditing

| Field | Value |
|-------|-------|
| **Tool Name** | `configuration_auditing` |
| **Purpose** | Audit configuration files for security misconfigurations |
| **Input Schema** | `{ "target": "string", "config_path": "relative/path", "check_default_credentials": "boolean", "check_sensitive_exposure": "boolean" }` |
| **Output Schema** | `{ "target": "string", "config_path": "string", "findings": [{category, severity, title, description, affected_setting, recommendation}] }` |
| **Permissions** | filesystem: `read_only`, network: `none` |
| **Timeout** | 30 seconds |
| **Risk Classification** | `LOW` |
| **Evidence Generated** | `audit_findings` (structured list of misconfiguration findings) |
| **Failure Behavior** | Returns findings list (may be empty); never writes outside audit_root |
| **Check Types** | Default credentials; sensitive data exposure (API keys, passwords) |
| **Redaction** | All findings have `affected_setting` masked; `secret_value` always `****` |

### 5. secret_detection

| Field | Value |
|-------|-------|
| **Tool Name** | `secret_detection` |
| **Purpose** | Detect secrets, credentials, and sensitive data in target files |
| **Input Schema** | `{ "target": "string", "search_paths": ["path1", "path2"], "include_entropy": "boolean" }` |
| **Output Schema** | `{ "target": "string", "search_paths": ["path1", "path2"], "secrets_found": [{file_path, line_number, secret_type, entropy, recommendation}] }` |
| **Permissions** | filesystem: `read_only`, network: `none` |
| **Timeout** | 30 seconds |
| **Risk Classification** | `LOW` |
| **Evidence Generated** | `secret_detection_output` (list of detected secret types with file paths) |
| **Failure Behavior** | Returns empty secrets list; file paths are relative to audit_root only |
| **Pattern Matching** | Regex-based: api_key, password, token, private_key, credit_card numbers |
| **Entropy Scoring** | Optional (`include_entropy:true`); calculates Shannon entropy for assessed secret likelihood |
| **Redaction** | `secret_value` always `**REDACTED**` in findings; never persists raw secrets |

### 6. vulnerability_validation

| Field | Value |
|-------|-------|
| **Tool Name** | `vulnerability_validation` |
| **Purpose** | Safe verification of identified vulnerabilities (no exploitation) |
| **Input Schema** | `{ "target": "string", "vulnerability_id": "string", "check_type": "config|header|page" }` |
| **Output Schema** | `{ "target": "string", "vulnerability_id": "string", "validated": "boolean", "details": {confirmed, evidence, risk_rating} }` |
| **Permissions** | filesystem: `read_only`, network: `target_only` |
| **Timeout** | 30 seconds |
| **Risk Classification** | `LOW` |
| **Evidence Generated** | `validation_results` (validation result with evidence and risk rating) |
| **Failure Behavior** | `validated=False` if safe check does not confirm; never implies exploitability |
| **Check Types** | `config`: Configuration checks (default pages, version headers); `header`: Security header presence; `page`: Test page detection |
| **Verification Method** | Uses `curl` for header/page checks only; no exploit payloads sent |
| **Output Guarantee** | Never reports a vulnerability as "exploitable"; only reports "identified via safe check" |

### 7. evidence_collection

| Field | Value |
|-------|-------|
| **Tool Name** | `evidence_collection` |
| **Purpose** | Centralized evidence collection, formatting, and persistence |
| **Input Schema** | `{ "action": "collect|save|merge|list", "data": {key: value}}` |
| **Output Schema** | `{ "action": "string", "result": "boolean", "evidence_path": "string" }` |
| **Permissions** | filesystem: `write_restricted` (chmod 600), network: `none` |
| **Timeout** | 10 seconds |
| **Risk Classification** | `LOW` |
| **Evidence Generated** | JSON evidence files in `audit_data/evidence/` with restricted permissions |
| **Failure Behavior** | Graceful degradation: `list` returns empty if no files; `save` validates permissions |
| **Supported Actions** | `collect`: Add evidence item to in-memory store; `save`: Write to JSON file; `merge`: Combine multiple evidence files; `list`: Enumerate evidence files |
| **File Permissions** | All evidence files written with `chmod 600` (owner read/write only) |
| **Redaction** | Applied before persistence via `BaseTool._sanitize_output()` |

---

## Tool Execution Example

```python
from tools import tool_registry
from hermes_shield.tool_execution import default_executor

# Create instance
tool = tool_registry.create_instance("network_reconnaissance")

# Execute with validated input
result = tool.run({
    "target": "192.168.1.1",
    "scan_type": "quick",
    "ports": "1-100"
})

# Result is a ToolResult with:
# - result.success (bool)
# - result.stdout (sanitized)
# - result.evidence (structured)
# - result.exit_code (int)

# Never execute arbitrary commands:
# ❌ tool.run({"command": "rm -rf /", "args": "..."})  -- WILL FAIL validation
# ✅ tool.run({"target": "192.168.1.1", "scan_type": "quick"})  -- VALID
```

---

## Negative Security Tests

Each tool must pass these security tests:

| Test | Objective | Expected |
|------|-----------|----------|
| **Input rejection** | Provide invalid input (missing required fields, wrong types) | `ToolResult.success=False`; no crash |
| **Path traversal rejection** | Provide `config_path` or `search_paths` with `../` or absolute paths | `InputValidationError` raised |
| **Tool output redaction** | Tool outputs contain API keys/passwords; redaction runs | Sanitized output; `****` masks in stdout/stderr |
| **Timeout enforcement** | Tool execution hangs; verify timeout kills process | `TimeoutError` raised; `success=False` |
| **No host secret exposure** | Tool runs against target; check stdout/stderr for host credentials | No API keys, passwords, or PII in output |
| **Sandbox boundary** | Tool attempts to escape (e.g., `; rm -rf /` appended) | Command blocked by allowlisting; `TOOL_BLOCKED` in stderr |
| **Evidence file permissions** | Evidence saved to disk | `chmod 600` on evidence files |
| **Evidence redaction before persist** | Secret data in evidence item | Redacted before JSON write; raw secrets never to disk |

---

## Adding New Tools

To add a new tool:

1. Create a new file in `tools/` following the pattern of existing tools
2. Define class attributes:
   - `TOOL_NAME`: Unique string identifier
   - `PURPOSE`: Human-readable description
   - `INPUT_SCHEMA`: JSON-schema-compatible dict
   - `OUTPUT_SCHEMA`: JSON-schema-compatible dict
   - `PERMISSIONS`: `{"filesystem": "read_only"|"write_restricted", "network": "target_only"|"none"}`
   - `TIMEOUT`: int (seconds)
   - `RISK_CLASSIFICATION`: `"LOW"` `"MEDIUM"` `"HIGH"`
   - `EVIDENCE_ITEMS`: list of evidence key names
   - `ALLOWED_ENV`: list of permitted env var names
3. Implement abstract methods:
   - `validate_input(input_data)`: Return True or raise `InputValidationError`
   - `execute(input_data)`: Return `ToolResult`
   - `get_target(input_data)`: Return target string
4. Register tool: `tool_registry.register(YourToolClass)`
5. Add unit tests in `tests/tools/`
6. Add negative security tests (see table above)

### Minimum Unit Test Requirements

Each tool must have unit tests covering:

1. **Import and instantiation**: `from tools.<name> import <ToolClass>`; `instance = <ToolClass>()`
2. **Valid input execution**: Tool runs successfully with correct input
3. **Invalid input rejection**: Tool raises `InputValidationError` or returns `success=False`
4. **Timeout behavior**: Tool execution is terminated within specified timeout
5. **Output sanitization**: Tool output does not contain raw secrets after redaction

### Negative Security Test Requirements

Each tool must pass these security tests:

1. **Path traversal attempt**: `config_path="../../../etc/passwd"` → `InputValidationError`
2. **Command injection attempt**: Input contains shell metacharacters (`;`, `|`, `&`) → Command blocked
3. **Credential leakage check**: Tool stdout/stderr inspected for `api_key=`, `password=`, `secret=`
4. **Evidence file permission check**: Evidence file inspected for `chmod 600`
5. **Redaction run**: Regex patterns applied to output; sensitive values masked

---

## Hackathon Usage Notes

- **Isolated targets only**: All tools use `127.0.0.1`, `localhost`, or `10.0.0.1` synthetic targets
- **No real network scanning**: Tools are designed for synthetic/demo targets only
- **Credential never hardcoded**: All API keys and secrets come from `.env` environment variables
- **Evidence persistence**: Evidence files stored in `./audit_data/evidence/` with restricted permissions
- **Tool allowlisting**: Only tools in the `tools/` directory with registered `TOOL_NAME` are executable
- **No arbitrary command execution**: The Hermes Agent's only interface to tools is through the registered tool set; arbitrary `cmd` execution is blocked at the framework level