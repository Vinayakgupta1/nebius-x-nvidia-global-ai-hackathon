# HermesShield Security Model

## Overview
This document defines the security model for HermesShield, including trust boundaries, access controls, and security mechanisms.

## Core Principles

### 1. Least Privilege
- Hermes Agent operates with minimum necessary permissions for audit tasks
- Tool execution processes have restricted filesystem and network access
- Model API credentials are not embedded; injected at runtime via environment

### 2. Defense in Depth
- Multiple independent security layers: subprocess isolation, policy enforcement, evidence redaction
- No single point of failure; bypassing one layer does not grant full access
- Default-deny policy for all tool commands and network connections

### 3. Explicit Trust Boundaries
- Trust is not implicitly granted across boundaries
- Each boundary crossing validates data and intent
- Cross-boundary communication logged and auditable

### 4. Fail-Safe Defaults
- Command execution fails by default; must explicitly allow
- Model output is validated before use; unvalidated data is rejected
- Evidence collection continues even on individual tool failures

## Trust Boundaries

### Boundary 1: Agent-to-Model
- **Direction**: Hermes Agent -> Nemotron 3 Ultra 550B (via Nebius)
- **Data Flow**: Planning prompts sent to model; analysis responses received
- **Trust Assumption**: Model output is "best effort" but not implicitly trusted
- **Validation**: Each model claim must be supported by evidence from tool outputs
- **Enforcement**: Prompt templates prevent unbounded data injection

### Boundary 2: Agent-to-API
- **Direction**: Hermes Agent -> Nebius Token Factory
- **Data Flow**: API requests with authentication tokens; inference responses
- **Trust Assumption**: API responses are authentic but subject to rate limiting
- **Validation**: Response format validation; error handling for malformed responses
- **Enforcement**: API key rotation, usage monitoring, budget caps

### Boundary 3: Tool Execution-to-Host
- **Direction**: Tool subprocess -> Host system
- **Data Flow**: Commands and arguments sent; stdout/stderr captured
- **Trust Assumption**: Subprocess is isolated; no automatic host access
- **Validation**: Exit code checking; output size limits; stderr content review
- **Enforcement**: Policy-based allowlisting, cwd restriction, environment filtering

### Boundary 4: Evidence Persistence
- **Direction**: Evidence Collector -> Disk
- **Data Flow**: JSON evidence objects written to evidence files
- **Trust Assumption**: Evidence may contain sensitive data; must be redacted
- **Validation**: Redaction rules applied before write; integrity hashes optional
- **Enforcement**: File permissions (600), sensitive field masking, rotation policy

### Boundary 5: Reporting-to-User
- **Direction**: Reporting Engine -> Human Operator
- **Data Flow**: Markdown/HTML reports viewed/exported
- **Trust Assumption**: User is authorized; report may contain sensitive findings
- **Validation**: Report sanitization; no raw credentials in output
- **Enforcement**: Template-driven output, redaction before formatting

## Access Control Model

### Component Permissions

| Component | Read | Write | Execute | Network |
|-----------|------|-------|---------|---------|
| Hermes Agent | All evidence | Audit state | Plan generation | Nebius API only |
| Nemotron (via Nebius) | Audit context | None | Model inference | - |
| Nebius Token Factory | Request metadata | Token registry | Inference service | - |
| NemoClaw | Configuration | Policy rules | Subprocess spawning | - |
| OpenShell | Session state | History | Command execution | Target network only |
| Tool Execution | Evidence store | Temp files | Command runner | Target only |
| Evidence Collector | All evidence | Evidence files | None | - |
| Reporting Engine | Evidence files | Report output | None | - |

### Policy Enforcement Points

1. **Hermes Agent Planning**: Every test plan step is validated against Skills Registry before execution
2. **NemoClaw Policy Layer**: Command allowlisting runs before subprocess spawn
3. **OpenShell Session**: Each session has explicit duration and allowed command set
4. **Evidence Redaction**: Regex-based and keyword-based redaction runs on every write
5. **Report Templates**: Fixed format; no dynamic insertion of unvalidated data

## Sandsecurity Controls

### Subprocess Isolation
- Tool commands are spawned as child processes with no parent-child shared state
- Environment variables are filtered; only those in `ALLOWED_ENV` are passed
- Working directory is restricted to `WORK_ROOT/<audit_id>/sandbox/<tmp_dir>`
- Process group ID is set to isolate from parent process tree

### Resource Limits
- CPU time: configurable limit per command
- Memory: maximum RSS per subprocess
- Timeout: hard timeout after which process is killed
- Output size: stdout+stderr capped at 1MB per command

### Network Enforcement
- Tool subprocesses have no outbound network access by default
- If network is required, egress is restricted to DNS allowlist and target endpoint
- No outbound connections from evidence collection or reporting processes

### Filesystem Scoping
- Tool sandboxes have read-only access to audit root directory
- Write access is limited to a temporary directory with auto-cleanup
- No access to home directory or system paths outside scope
- Evidence files are the only persistent output, written with strict permissions

## Credential Management

### API Credentials
- Nebius API key: injected via environment variable `NEBIUS_API_KEY` at process start
- Never hardcoded in source; loaded at runtime from secure env
- Key rotation supported via environment update; no persistent storage

### Agent Credentials
- Hermes Agent identity: determined by process startup context
- No credential material stored in evidence or reports
- Session tokens have short TTL; refreshed on each audit cycle

### Target Credentials
- Target system credentials: never collected by default
- If authentication is required for a test, credentials are provided via secure config
- Collected credentials are immediately redacted from evidence

## Logging and Auditing

### Required Log Entries


[TIMESTAMP] ACTION: <description>

COMPONENT: <component_name>
AUDIT_ID: <uuid>
USER: <operator_id>
DETAILS: <key-value pairs>

### Audit Log Categories
1. **Agent Actions**: Plan generation, skill invocation, audit start/end
2. **Model Calls**: Request/response metadata (tokens used, latency, errors)
3. **Tool Execution**: Command, arguments, exit code, output size, success/failure
4. **Security Events**: Policy violations, sandbox attempts, redaction events
5. **Credential Access**: Any API key or secret references (masked in logs)

### Log Integrity
- Logs are append-only; each entry has a timestamp and audit ID
- Tamper-evident: log rotation with signed checksums (optional for hackathon)
- Sensitive data is redacted before log persistence

## Security Assumptions

1. The host operating system is trusted (no rootkit/BIOS-level attacks)
2. The Nemotron 3 Ultra 550B API returns output consistent with the prompt
3. Nebius Token Factory enforces API key authentication and rate limits
4. The target systems being audited are within controlled scope and consent to testing
5. Human operators act in good faith and do not subvert security controls intentionally
6. No physical access to running systems by adversaries during audit cycles
7. Network infrastructure between components is trusted (intra-process, same-host)
8. Evidence storage directory has adequate filesystem permissions for the process user

## Security Requirements Checklist

- [ ] Subprocess isolation for all tool execution
- [ ] Policy-based command allowlisting
- [ ] Environment variable filtering
- [ ] Evidence redaction before persistence
- [ ] File permissions (600) on evidence files
- [ ] Audit ID tracking across all components
- [ ] Nebius API key via environment variable only
- [ ] No hardcoded credentials in source
- [ ] Report template prevents raw data insertion
- [ ] Human review step before report export