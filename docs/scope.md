# HermesShield Scope Document

## In-Scope Capabilities

### 1. Security Reconnaissance
- Domain and subdomain enumeration using gau, waybackurls, assetfinder
- IP range discovery and host discovery
- HTTP header analysis and fingerprinting (whatweb, custom checks)
- TLS certificate information collection
- DNS record enumeration

### 2. Vulnerability Scanning
- Port scanning and service version detection (nmap -sV)
- Common vulnerability scanner integration (nikto for web targets)
- Directory/file discovery on web servers (dirb, ffuf)
- Technology stack identification
- Open redirect and CRLF basic checks

### 3. Agent-Mediated Security Auditing
- Hermes Agent orchestrates multi-step audit workflows
- Test plan generation using Nemotron 3 Ultra 550B
- Skill-based task execution with precondition checking
- Audit cycle management (start, execute, collect, report)

### 4. Evidence Collection and Format
- Structured JSON evidence with timestamps, commands, outputs
- Tool exit code tracking and status reporting
- Evidence linking to findings in reports
- Evidence redaction for sensitive data

### 5. Report Generation
- Markdown-formatted executive summaries
- Findings list with risk ratings
- Evidence item references (by ID)
- Risk assessment based on Nemotron analysis
- Exportable format for sharing

### 6. Isolated Test Environments
- Docker/containers for target interaction (TO BUILD - subprocess fallback available)
- Network isolation for target communication
- Snapshot-based test state management
- Container cleanup after each audit cycle

### 7. Memory and State Management
- Session state tracking per audit cycle
- Conversation history with Nemotron model
- Evidence store persistence across cycles
- Skill cache for capability mapping

## Out-of-Scope Capabilities

### 1. Exploit Delivery
- ❌ Binary exploitation or chain construction
- ❌ Payload delivery and execution
- ❌ Privilege escalation on target systems
- ❌ Shellcode generation or assembly

### 2. Credential Attacks
- ❌ Password brute-forcing
- ❌ Dictionary attacks on authentication
- ❌ Credential stuffing
- ❌ Keylogging or screen scraping

### 3. Lateral Movement
- ❌ Pivoting from compromised host to other systems
- ❌ Trust relationship exploitation
- ❌ Network propagation

### 4. Persistence Installation
- ❌ Scheduled task creation
- ❌ Registry run key modification
- ❌ Service installation
- ❌ Bootkit or firmware-level persistence

### 5. Cryptanalysis
- ❌ Custom hash cracking beyond dictionary lookup
- ❌ Cryptographic protocol exploitation
- ❌ Key recovery from implementations

### 6. Zero-Day Discovery with Exploits
- ❌ Novel vulnerability discovery
- ❌ Exploit generation for found vulnerabilities
- ❌ Weaponization of discoveries

### 7. Continuous Monitoring
- ❌ Long-running agent loops
- ❌ Scheduled recurring audits
- ❌ Real-time alerting
- ❌ Dashboard or monitoring infrastructure

### 8. Custom Tool Development
- ❌ Adding new command-line tools beyond the allowed set
- ❌ Framework integration beyond configured scanners
- ❌ Custom API development

### 9. Model Capabilities Beyond Reasoning
- ❌ Real-time learning or adaptation during operation
- ❌ Fine-tuning or model customization
- ❌ Multi-model orchestration (beyond Nemotron)
- ❌ Autonomous code generation execution

### 10. Infrastructure Management
- ❌ Target system provisioning or management
- ❌ Cloud resource allocation
- ❌ Network topology management
- ❌ DNS configuration or manipulation

## Skill Scope Map

| Skill | In-Scope | Out-of-Scope |
|-------|----------|--------------|
| `reconnaissance` | Domain enumeration, subdomain discovery, HTTP fingerprinting | Credential extraction, password cracking, lateral movement |
| `vulnerability_scan` | Port scanning, service detection, known vulnerability checks | Exploit development, payload delivery |
| `web_analysis` | Header analysis, technology fingerprinting, basic XSS/SQLi checks | Full exploit chain, authentication bypass |
| `report_synthesize` | Markdown report generation, finding summarization, evidence linking | Custom report formatting, data visualization beyond markdown |

## Component Scope Matrix

| Component | Within Scope | Requires Configuration | Out of Scope |
|-----------|-------------|----------------------|--------------|
| Hermes Agent | Audit orchestration, skill coordination | Target selection, objective framing | Objective override, unbounded autonomy |
| Nemotron 3 Ultra 550B | Reasoning, analysis, report synthesis | Prompt engineering, temperature control | Model training, custom architecture |
| Nebius Token Factory | Inference service access | API key management, budget tracking | Model hosting, infrastructure management |
| NemoClaw | Subprocess isolation, policy enforcement | Allowlist configuration, resource limits | Full OS virtualization, hardware isolation |
| OpenShell | Restricted command execution | Session duration, allowed commands | Unrestricted shell access, host interaction |
| Tool Execution | Sandboxed command running | Command allowlisting, timeout settings | Unconstrained process execution |
| Evidence Collector | JSON capture, redaction | Redaction rules, storage path | Real-time correlation, predictive analytics |
| Reporting Engine | Markdown generation, template rendering | Finding categorization, risk levels | HTML customization, UI generation |

## Hackathon Demonstration Scope

For the hackathon demonstration, the following limited scope is recommended:

### Demonstrated Capabilities
1. **Basic reconnaissance**: Domain enumeration with gau and waybackurls
2. **Vulnerability scanning**: nmap service detection on local/controlled target
3. **Agent planning**: Hermes Agent generates a test plan using Nemotron
4. **Evidence collection**: Tool outputs captured as structured JSON
5. **Report generation**: Markdown report with findings summary
6. **Skill coordination**: Hermes Agent routes between reconnaissance and scanning skills

### Limited Scope Constraints
- Targets must be controlled/local (127.0.0.1, localhost, or explicitly authorized)
- No network egress from tool sandboxes beyond DNS allowlist
- No credential collection or display in reports
- Single-audit cycle only (no accumulation across runs)
- Pre-defined skill set; no new tool addition

### Not Demonstrated (explicitly)
- Multi-cycle accumulation
- Custom tool integration
- Credential handling
- Long-running agent processes
- External network access from tool processes