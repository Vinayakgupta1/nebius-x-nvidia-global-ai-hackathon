# HermesShield Architecture

## Overview
HermesShield is an autonomous AI security auditing and red-team simulation platform. The system is designed for hackathon demonstration with a focus on clear architecture and demonstrable components.

## System Architecture


+-----------------------------------------------------------+
| HermesShield Platform |
| |
| +----------------------+ +----------------------+ |
| | Hermes Agent | | Nemotron 3 Ultra | |
| | (autonomous agent)| | 550B (reasoning) | |
| +----------------------+ +----------------------+ |
| | | |
| | | |
| +------v-------+ +-----v-----+ |
| | Nebius Token | | NemoClaw | |
| | Factory | | (security) | |
| +-------+--------+ +-----+-----+ |
| | | | |
| | | | |
| +-------v-------+ +-----v-----+ |
| | OpenShell | |isolated | |
| | (containment) | |sandbox(s) | |
| +----------------+ +-----------+ |
+-----------------------------------------------------------+

+----------------------+ +----------------------+
| Tool Execution Layer | | Memory Architecture |
| (sandboxed processes) | | (agent memory, |
+----------------------+ | session state) |
+----------------------+

+----------------------+ +----------------------+
| Evidence Collector | | Skills Registry |
| (JSON reports) | | (capability map) |
+----------------------+ +----------------------+

+----------------------+
| Reporting Engine |
| (markdown/HTML) |
+----------------------+


## Component Responsibilities

| Component | Role | Status |
|-----------|------|--------|
| **Hermes Agent** | Autonomous security auditing agent that plans and executes security tests. Coordinates the entire audit flow. | TO BUILD - orchestration logic, API integration with Nemotron |
| **Nemotron 3 Ultra 550B** | Primary reasoning model for vulnerability analysis, test case generation, and report synthesis. Provides the "intelligence" for security decisions. | TO BUILD - model inference via Nebius API |
| **Nebius Token Factory** | Inference provider that serves Nemotron 3 Ultra 550B requests. Handles token pricing, rate limiting, and model routing within Nebius infrastructure. | TO BUILD - API integration with Nebius |
| **NemoClaw** | Security containment layer that enforces boundaries for agent execution. Provides syscall filtering and process isolation for red-team activities. | TO BUILD - sandbox enforcement logic |
| **OpenShell** | Agent containment and session management. Provides restricted shell access for command execution within controlled environments. | TO BUILD - session sandboxing |
| **Isolated Testing Environments** | Pre-configured VM/containers for running security tests against target systems. Network-isolated, snapshot-capable environments. | TO BUILD - Docker/VM setup |
| **Tool Execution Layer** | Sandboxed process execution for command-line tools (nmap, nikto, etc.). Commands run in isolated subprocesses with resource limits. | TO BUILD - subprocess sandboxing |
| **Evidence Collector** | Collects and formats audit evidence from tool outputs, model responses, and session state. Produces structured JSON evidence. | TO BUILD - evidence aggregation |
| **Reporting Engine** | Converts evidence into human-readable markdown/HTML reports. Supports template-driven report generation. | TO BUILD - report templating |
| **Memory Architecture** | Stores agent session state, conversation history, and persistent audit data. Key-value store for interim results. | TO BUILD - state persistence |
| **Skills Registry** | Maps agent capabilities to available tools and models. Declares what each skill can do and under what conditions. | TO BUILD - capability mapping |

## Data Flow

1. **Audit Initiation**: Hermes Agent receives audit target and objectives
2. **Planning**: Nemotron 3 Ultra 550B (via Nebius Token Factory) generates test plan
3. **Execution**: Hermes Agent runs tests in isolated environments
4. **Tool Execution**: Commands run in Tool Execution Layer sandboxs
5. **Evidence Collection**: Outputs captured and structured by Evidence Collector
6. **Analysis**: Nemotron 3 Ultra 550B analyzes tool outputs
7. **Reporting**: Evidence converted to reports by Reporting Engine

## Agent Execution Flow


[Audit Request]
|
v
[Hermes Agent - Plan Generation]
|
v
[Nemotron 3 Ultra 550B - via Nebius Token Factory]
|
v
[Test Plan] -> [Skills Registry lookup]
|
v
[Isolated Environment Setup]
|
v
[Tool Execution Layer - sandboxed commands]
|
v [Tool Outputs]
|
v
[Evidence Collector - capture output]
|
v
[Nemotron 3 Ultra 550B - analysis]
|
v
[Reporting Engine - format output]


## Security Boundary

- **Process Isolation**: Tool execution processes are spawned as isolated subprocesses with no shared memory
- **Network Enforcement**: Outbound network from tool sandboxes is controlled via firewall rules
- **Filesystem Scoping**: Tool sandboxes have read-only access to specified directories; write access is temp-only
- **Session Containment**: OpenShell sessions are terminated after each audit cycle

_Note: These boundaries are TO BUILD. Basic subprocess isolation can be demonstrated; full security boundaries require additional implementation._

## Tool Execution Model

- Commands are specified as JSON objects with `command`, `args`, `cwd`, `timeout`, and `allowed_env` fields
- Execution occurs in sandboxed subprocesses
- Output is captured stdout/stderr with size limits
- Exit codes are checked; non-zero results are flagged as evidence
- Commands beyond the allowed set are rejected at the policy level

_Allowed tools for hackathon demo: nmap,nikto,whatweb,dirb,gau,waybackurls,ffuf (limited flags)_

## Memory Architecture

| Layer | Content | Persistence |
|-------|---------|-------------|
| **Session State** | Current audit context, target, status | In-process (reset each cycle) |
| **Conversation History** | Prompt/response pairs with Nemotron | In-process |
| **Evidence Store** | Collected tool outputs, model responses | JSON files on disk |
| **Skill Cache** | Mapped capabilities and tool mappings | JSON file on disk |

## Skills Architecture

Skills are declared as capabilities with preconditions and postconditions:

| Skill | Description | Required Tools | Status |
|-------|-------------|----------------|--------|
| `reconnaissance` | Gather target information (domains, IP ranges) | gau, waybackurls, assetfinder | TO BUILD |
| `vulnerability_scan` | Run scanner tools against target | nmap, nikto | TO BUILD |
| `web_analysis` | Analyze web endpoints and headers | whatweb, custom checks | TO BUILD |
| `report_synthesize` | Generate final audit report | Evidence store, templates | TO BUILD |

Each skill is registered in the Skills Registry and can be looked up by the Hermes Agent during planning.

## Sandbox Architecture

- **Docker-based sandboxes** for isolated target interaction
- Each audit gets a fresh container with minimal base image
- Container network is restricted to the target endpoint only
- Container filesystem is read-only except `/tmp` for tool outputs
- Containers are snapshotted before/after each test cycle for rollback demonstration

_Note: Docker sandboxing is TO BUILD. A basic subprocess sandbox can be demonstrated without Docker for the hackathon._

## Evidence Collection Architecture

Evidence is collected as structured JSON objects:

```json
{
  "timestamp": "2026-01-01T00:00:00Z",
  "skill": "vulnerability_scan",
  "tool": "nmap",
  "target": "192.168.1.1",
  "command": "nmap -sV -T4 target",
  "stdout": "...",
  "stderr": "",
  "exit_code": 0,
  "status": "completed"
}

Evidence items are appended to a per-audit JSON file and used as input for the Reporting Engine.

Reporting Architecture
Reports are generated in markdown format
Template contains: executive summary, findings, evidence, risk rating
Each finding references evidence items by ID
Risk rating is determined by Nemotron 3 Ultra 550B analysis
Output can be exported to HTML for sharing
Threat Model
Threat Actor	Capability	Target	Mitigation
Malicious Agent	Override Hermes Agent objectives	Audit targets outside scope	Objective framing, capability limits
Poisoned Model Output	Nemotron generates incorrect findings	Vulnerability analysis	Evidence validation, human review
Tool Escape	Sandboxed command executes host commands	Host system	Subprocess isolation, policy rules
Data Leakage	Evidence contains sensitive data	Credentials, PII	Redaction rules, evidence sanitization
Network Exfiltration	Tool sandbox sends data externally	External servers	Network egress filtering, DNS allowlist
Trust Boundaries
Hermes Agent <=> Nemotron 3 Ultra 550B: Model output is trusted but validated. Evidence cross-checks model claims with tool outputs.
Hermes Agent <=> Nebius Token Factory: API calls are authenticated; token usage is monitored for anomalies.
Tool Execution <=> Host: Subprocess is isolated; no automatic propagation of environment variables or filesystem access.
Evidence Store <=> Disk: Evidence files are written with restricted permissions; sensitive fields are redacted before disk persistence.
Failure Modes
Failure	Symptom	Recovery
Nemotron API timeout	Planning step stalls	Cancel audit, retry with simplified plan
Tool sandbox failure	Commands fail to execute	Fallback to limited tool set, mark as evidence gap
Docker unavailable	Sandbox cannot start	Fallback to subprocess-only mode
Evidence JSON corruption	Report generation fails	Validation on write, rebuild from raw outputs
Hermes Agent crash	Audit in progress	Session state saved, can be resumed
Rate limit exceeded	Nebius requests throttled	Backoff and retry, prioritize critical tests
Security Assumptions
The Nemotron 3 Ultra 550B API via Nebius returns correct, unpoisoned outputs for in-scope queries
Tool sandboxes prevent accidental host system interaction (basic subprocess isolation)
Audit targets are within controlled scope (no live production systems)
API keys and credentials are managed externally and not hardcoded
The Hermes Agent follows objectives faithfully without adversarial prompt injection
Out-of-Scope Capabilities
❌ Real-time exploit delivery (vulnerability discovery only)
❌ Credential brute-forcing or password cracking
❌ Lateral movement across networks
❌ Persistence installation on target systems
❌ Binary exploitation or shellcode generation
❌ Cryptographic attack beyond hash lookup
❌ Zero-day discovery with exploit generation
❌ Continuous monitoring or long-term deployment
❌ Custom tool development beyond the allowed set
❌ Model training or fine-tuning
❌ Real network infrastructure management