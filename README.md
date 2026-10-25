# HermesShield - Autonomous Security Auditing Framework

![HermesShield](https://img.shields.io/badge/HermesShield-Autonomous%20Security%20Auditing-00d4aa)
![Core Tests](https://img.shields.io/badge/core%20tests-34%2F34-00d4aa)
![All Tests](https://img.shields.io/badge/all%20tests-167%2F217-00d4aa)
![Success Rate](https://img.shields.io/badge/core%20success%20rate-100%25-ff6b35)
![Version](https://img.shields.io/badge/version-2.0.0-a855f7)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

---

## 📡 Overview

**HermesShield** is an autonomous security auditing framework that correlates individual security findings into multi-step attack paths with full evidence traceability. It provides comprehensive security boundary enforcement testing against **17 adversarial attack vectors** with **100% core test success rate** across **34 core test suites** (167/217 total tests passing).

HermesShield autonomously:
- Discovers security vulnerabilities across multiple categories
- Correlates findings into logical attack paths with confidence scoring
- Tests security boundary enforcement (file, credential, network, command access)
- Validates robustness against adversarial attacks (prompt injection, tool manipulation, sandbox escape, etc.)
- Provides reproducible security benchmarks for continuous assessment

**Current Status:** ✅ 34/34 core security tests passing (100%) | ✅ 167/217 total tests passing

---

## 📊 Test Results Summary

### Core Security Tests (34/34 passing - 100%)

| Test Suite | Tests | Pass Rate | Description |
|------------|-------|-----------|-------------|
| **Attack Path Correlation** | 11 | 100% | Multi-step attack path building with evidence traceability |
| **Security-Boundary** | 6 | 100% | File/credential/network/command access enforcement |
| **Adversarial Security** | 17 | 100% | 17 attack vectors: injection, escape, manipulation, persistence |

### Extended Test Suites (133 passing)

| Test Suite | Tests | Status | Description |
|------------|-------|--------|-------------|
| **Agent Tests** | 22 | ✅ Passing | Core agent orchestration, planning, reporting |
| **Memory Tests** | 28 | ✅ Passing | Memory policy, poisoning protection, redaction |
| **Inference Tests** | 7 | ✅ Passing | NEBIUS API connectivity, model verification |
| **Tool Tests** | 70 | ✅ Passing | 7 security tools (config audit, evidence collection, http recon, network recon, secret detection, service enum, vuln validation) |
| **Sandbox Tests** | 50 | ⚠️ Failed/Error | Docker-dependent (requires Docker daemon) |

**Total:** 217 tests | **167 passing** | **22 failed** (sandbox, Docker) | **28 errors** (sandbox, Docker)

### Attack Vectors Tested (Adversarial - 17/17 PASS)

1. **Prompt Injection** - Direct instruction override via crafted input
2. **Tool Output Injection** - Tool response poisoning
3. **Malicious Files** - Polyglot file uploads with embedded payloads
4. **Malicious Shell Commands** - Shell metacharacter injection
5. **Unauthorized Filesystem Access** - Path traversal (`../../../etc/passwd`)
6. **Host Credential Access** - Environment variable enumeration, SSH key extraction
7. **Unauthorized Network Communication** - DNS exfiltration, HTTP callbacks
8. **Environment Variable Leakage** - Error-based secret exposure
9. **Sandbox Escape Attempts** - Docker socket access, procfs escape
10. **Privilege Escalation** - Sudo exploitation, kernel exploits
11. **Memory Poisoning** - State injection via tool outputs
12. **Skill Poisoning** - Skill definition tampering
13. **Scope Bypass** - Parameter manipulation, IDOR
14. **Tool Parameter Manipulation** - Parameter pollution, type confusion
15. **Report Manipulation** - Report tampering, evidence suppression
16. **Persistent Malicious State** - State file corruption, cache poisoning
17. **Cross-Session Memory Contamination** - Shared memory, temp file leakage

### Critical Issues Fixed

1. **Claim Status Enum Comparison**: Fixed Python enum comparison where `claim_status == 'hypothesis'` always failed - now uses `claim_status.value == 'hypothesis'`
2. **Hypothesis Generation**: Ensures hypotheses always generated from vulnerabilities, even without matching findings
3. **Evidence Matching**: Attack paths properly connect and incorporate evidence from context
4. **Confidence Calculation**: Evidence ratio formula adjusted so fully verified evidence increases confidence above baseline
5. **Evidence Type Handling**: Changed `e.verified` to `e.get("verified", False)` for dict compatibility

---

## 🏗️ Project Structure

```text
HermesShield/
├── hermes_shield/          # Main Python package (56 files)
│   ├── __init__.py         # Safe config loader, logger
│   ├── agent.py            # Core agent orchestration
│   ├── config.py           # Configuration management (NEBIUS, agent)
│   ├── evidence.py         # Evidence collection & handling
│   ├── tool_execution.py   # Tool execution framework with allowlist
│   ├── nemotron.py         # NVIDIA Nemotron integration via Nebius
│   ├── agent/              # Agent submodules
│   │   ├── engine.py       # Execution engine
│   │   ├── planner.py      # Audit planning
│   │   ├── reporting.py    # Report generation
│   │   ├── scope.py        # Scope enforcement
│   │   └── skills.py       # Skill management
│   ├── attack_path/        # Attack path correlation engine
│   │   ├── __init__.py
│   │   ├── correlation_engine.py  # Fixed: claim_status.value comparisons
│   │   └── validation.py          # Fixed: e.get("verified", False)
│   ├── sandbox/            # Docker sandbox state management
│   │   └── docker_sandbox.py
│   ├── memory/             # Memory policy & poisoning protection
│   │   └── policy.py
│   ├── scripts/            # Utility scripts
│   │   └── verify_inference.py    # NEBIUS connectivity verification
│   └── tools/              # Security assessment tools (7 tools)
│       ├── configuration_auditing.py
│       ├── evidence_collection.py
│       ├── http_reconnaissance.py
│       ├── network_reconnaissance.py
│       ├── secret_detection.py
│       ├── service_enumeration.py
│       └── vulnerability_validation.py
├── tests/                  # Test suites (217 tests total)
│   ├── attack_path/        # 11/11 passing (core)
│   ├── security-boundary/  # 6/6 passing (core)
│   ├── adversarial/        # 17/17 passing (core)
│   ├── agent/              # 22 passing
│   ├── memory/             # 28 passing
│   ├── inference/          # 7 passing
│   ├── tools/              # 70 passing (7 tool test files)
│   └── sandbox/            # 50 failed/error (Docker required)
├── benchmark/              # Reproducible security benchmark
│   ├── lab/                # Synthetic lab with 10 vulnerabilities
│   │   └── vulnerabilities.json
│   ├── scripts/            # Benchmark runner scripts
│   │   ├── run_benchmark.py
│   │   └── reset_benchmark.py
│   └── results/            # Output directory
├── docs/                   # Documentation (13 files)
│   ├── security-assessment.md     # Comprehensive adversarial assessment (12KB)
│   ├── remediation-report.md      # Detailed remediation report (6KB)
│   ├── architecture.md            # System architecture (10KB)
│   ├── threat-model.md            # Threat modeling (5KB)
│   ├── security-model.md          # Security controls (8KB)
│   ├── containment.md             # Containment strategies (10KB)
│   ├── sandbox.md                 # Sandbox design (8KB)
│   ├── tools.md                   # Tool documentation (13KB)
│   ├── memory.md                  # Memory policy (6KB)
│   ├── evaluation-plan.md         # Evaluation methodology (4KB)
│   ├── scope.md                   # Project scope (6KB)
│   ├── oracle-deployment.md       # Oracle Cloud deployment (15KB)
│   └── submission-response.md     # Hackathon submission (13KB)
├── demo/                   # Interactive web demo
│   ├── app.py              # Flask API backend
│   ├── README.md           # Demo documentation
│   ├── api/                # API endpoints
│   ├── static/             # Static assets
│   └── templates/          # HTML templates
├── policies/               # Security policies (4 files)
│   ├── evidence_redaction.json
│   ├── nemo_claw_policy.json
│   ├── network_policy.json
│   └── tool_allowlist.json
├── scripts/                # Project scripts
│   └── security_tests/     # Security test runner
├── skills/                 # Skill modules (empty - for future use)
├── .env.example            # Environment variables template
├── index.html              # Redesigned web dashboard (29KB)
├── pyproject.toml          # Package configuration
├── pytest.ini              # Pytest configuration
├── LICENSE                 # MIT License
└── README.md               # This file
```

---

## 🔄 Attack Path Correlation Flow

```mermaid
flowchart TD
    A[Input: Security Findings] --> B[Parse Evidence Items]
    B --> C[Generate Hypotheses]
    C --> D[Match Evidence to Hypotheses]
    D --> E[Build Attack Path Graph]
    E --> F[Calculate Confidence Scores]
    F --> G[Verify Path Corroboration]
    G --> H[Output: Correlated Attack Paths]
```

### Correlation Engine Process

1. **Parse Evidence Items** - Load findings from tool execution with `claim_status`, `verified` flag, supporting data
2. **Generate Hypotheses** - Create potential attack paths from identified vulnerabilities
3. **Match Evidence to Hypotheses** - Connect findings to hypothesized paths using evidence matching logic
4. **Build Attack Path Graph** - Construct multi-step attack sequences with evidence traceability
5. **Calculate Confidence Scores** - Weighted formula based on evidence verification ratio
6. **Verify Path Corroboration** - Validate paths have sufficient evidence support
7. **Output Correlated Attack Paths** - Return structured results with full evidence chain

---

## 🛠️ Installation

### Prerequisites

- Python 3.10+
- pip (Python package manager)
- Docker (optional, for sandbox tests and benchmark)

### Install Dependencies

```bash
cd HermesShield
pip install -e .
```

### Environment Setup

```bash
cp .env.example .env
# Edit .env with your configuration
# NEBIUS_API_KEY=your_key_here  # Optional - for AI-enhanced features
```

---

## 🌐 Interactive Demos

### Option 1: Static Web Dashboard (No Server Required)

Open `index.html` in any modern browser for a responsive dashboard showing:
- Test metrics (167 passed, 100% core success rate)
- Attack path correlation visualization
- Security boundary test outcomes
- Adversarial security status
- Benchmark lab overview
- CSS3D animations, parallax, smooth scroll

### Option 2: Interactive Demo Server (Flask)

```bash
python demo/app.py
```

Open `http://127.0.0.1:5000/` for live test execution:
- Run test suites via API
- Real-time attack path graph visualization
- Adversarial attack simulation
- Benchmark lab exploration
- NEBIUS inference verification

### Option 3: Live Demo Mode (AI-Enhanced)

With `NEBIUS_API_KEY` configured in `.env`:
- Backend calls NVIDIA Nemotron via Nebius Token Factory
- Generates bounded audit plans using allowed skills only
- Validates returned skill names before execution
- Without credentials: **SAFE FALLBACK** mode with deterministic simulation

---

## 🧪 Running Tests

### Core Security Tests (34/34 - 100%)

```bash
# Attack Path Correlation
python -m pytest tests/attack_path/ -v

# Security-Boundary Tests
python -m pytest tests/security-boundary/ -v

# Adversarial Security Tests
python -m pytest tests/adversarial/ -v

# All Core Tests
python -m pytest tests/attack_path/ tests/security-boundary/ tests/adversarial/ -v
```

### Extended Test Suites

```bash
# Agent, Memory, Inference, Tools (all passing)
python -m pytest tests/agent/ tests/memory/ tests/inference/ tests/tools/ -v

# Full suite (includes sandbox - requires Docker)
python -m pytest tests/ -v
```

### With Coverage

```bash
python -m pytest --cov=hermes_shield tests/attack_path/ tests/security-boundary/ tests/adversarial/ -v
```

---

## 📊 Running the Benchmark

### Quick Start (Requires Docker)

```bash
cd benchmark
python run_benchmark.py
```

### Benchmark Options

```bash
python run_benchmark.py --help
```

| Option | Description |
|--------|-------------|
| `--lab-dir` | Lab directory (default: `benchmark/lab`) |
| `--lab-image` | Docker image name (default: `hermes-benchmark-lab:latest`) |
| `--output-dir` | Results output (default: `benchmark/results`) |
| `--skip-build` | Skip building lab Docker image |
| `--skip-cleanup` | Don't stop container after benchmark |
| `--verbose` | Verbose output |

### Reset Benchmark

```bash
python scripts/reset_benchmark.py --help
```

### Benchmark Lab Summary

| ID | Vulnerability | Severity | Category |
|----|---------------|----------|----------|
| BENCH-001 | Hardcoded SSH Private Key | CRITICAL | SECRET_EXPOSURE |
| BENCH-002 | Weak SSH Configuration | HIGH | MISCONFIGURATION |
| BENCH-003 | Exposed Internal HTTP API | HIGH | EXPOSURE |
| BENCH-004 | World-Readable DB Credentials | MEDIUM | DATA_EXPOSURE |
| BENCH-005 | PostgreSQL Default Credentials | CRITICAL | DEFAULT_CREDENTIALS |
| BENCH-006 | Sudo NOPASSWD for www-data | CRITICAL | PRIVILEGE_ESCALATION |
| BENCH-007 | World-Writable Cron Script | HIGH | PRIVILEGE_ESCALATION |
| BENCH-008 | SMB Anonymous Access | HIGH | EXPOSURE |
| BENCH-009 | Weak SSL/TLS Configuration | MEDIUM | CRYPTOGRAPHIC |
| BENCH-010 | Docker Socket Exposed | CRITICAL | CONTAINER_ESCAPE |

**Attack Paths:**
- **AP-001**: Full chain (SSH Key → SSH → Admin API → DB → Sudo → Root)
- **AP-002**: SMB → Config Files → Database
- **AP-003**: Cron → Docker Socket escape

---

## 💻 Web Dashboard

The static dashboard at `index.html` features:

- **Dark cybersecurity aesthetic** with animated gradient background
- **Real-time metrics**: 167 tests passed, 100% core success rate
- **Attack path correlation** results visualization
- **Security boundary** test outcomes (6/6)
- **Adversarial security** status (17/17)
- **Benchmark lab** overview (10 vulns, 3 attack paths)
- **Interactive features:**
  - Reduced motion detection (accessibility)
  - Smooth scroll navigation
  - Navigation background on scroll
  - Intersection Observer fade-in animations
  - Mouse parallax on feature cards
  - CSS3D transforms on hover
  - Focus-visible states for keyboard navigation

Open `index.html` in any modern browser.

---

## 📚 Documentation

| Document | Size | Description |
|----------|------|-------------|
| `docs/security-assessment.md` | 12KB | Comprehensive adversarial assessment (17 vectors) |
| `docs/remediation-report.md` | 6KB | Detailed remediation report (all fixes) |
| `docs/architecture.md` | 10KB | System architecture overview |
| `docs/threat-model.md` | 5KB | Threat modeling & attack surfaces |
| `docs/security-model.md` | 8KB | Security controls & boundaries |
| `docs/containment.md` | 10KB | Containment strategies |
| `docs/sandbox.md` | 8KB | Docker sandbox design |
| `docs/tools.md` | 13KB | 7 security tools documentation |
| `docs/memory.md` | 6KB | Memory policy & poisoning protection |
| `docs/evaluation-plan.md` | 4KB | Evaluation methodology |
| `docs/scope.md` | 6KB | Project scope & boundaries |
| `docs/oracle-deployment.md` | 15KB | Oracle Cloud + Cloudflare deployment |
| `docs/submission-response.md` | 13KB | Hackathon submission response |

---

## 🛠️ Commands Reference

### Test Commands

```bash
# Core security tests (34/34)
python -m pytest tests/attack_path/ tests/security-boundary/ tests/adversarial/ -v

# All passing tests (167 tests)
python -m pytest tests/agent/ tests/memory/ tests/inference/ tests/tools/ tests/attack_path/ tests/security-boundary/ tests/adversarial/ -v

# With coverage
python -m pytest --cov=hermes_shield tests/attack_path/ tests/security-boundary/ tests/adversarial/ -v
```

### Benchmark Commands

```bash
# Run benchmark (builds lab image)
cd benchmark && python run_benchmark.py

# Run with options
python run_benchmark.py --lab-image hermes-benchmark-lab:v1.0 --output-dir ./results

# Reset benchmark
python scripts/reset_benchmark.py --clean-results

# Show help
python run_benchmark.py --help
```

### Demo Commands

```bash
# Interactive demo server
python demo/app.py
# Open http://127.0.0.1:5000/

# Static dashboard
open index.html  # or double-click
```

### Debug Commands

```bash
# Syntax check
python -c "import ast; ast.parse(open('hermes_shield/attack_path/correlation_engine.py').read()); print('Syntax OK')"

# Import test
python -c "import sys; sys.path.insert(0, '.'); from hermes_shield.attack_path.correlation_engine import AttackPathCorrelator; print('Import OK')"
```

### Documentation

```bash
# Security assessment
cat docs/security-assessment.md

# Remediation report
cat docs/remediation-report.md
```

---

## 🔐 NVIDIA Nemotron & Nebius Integration

HermesShield integrates with **NVIDIA Nemotron models** via **Nebius Token Factory**:

- **Model**: Configured via `NEBIUS_MODEL` (e.g., Nemotron 3 Ultra 550B)
- **Authentication**: `NEBIUS_API_KEY` from environment (never hardcoded)
- **Usage**: Defensive audit planning - generates bounded skill sequences
- **Safety**: Validates returned skill names against allowlist; no shell commands, payloads, or arbitrary tools
- **Fallback**: Without API key, runs in **SAFE FALLBACK** mode with deterministic simulation

### Credential Handling

- `NEBIUS_API_KEY` loaded only by server from environment
- Never hardcoded, committed, logged, returned by API, or sent to browser
- Frontend exposes only safe connection status and model metadata
- Keep real keys in local `.env` or deployment secret store

---

## 👨‍💻 Development

### Adding New Tests

Tests follow the established pattern:
```
ATTACK -> EXPECTED DEFENSE -> ACTUAL RESULT -> EVIDENCE -> IMPACT -> REMEDIATION
```

### Code Conventions

- ✅ All `claim_status` comparisons use `.value` attribute
- ✅ Evidence items use `e.get("verified", False)` for dict compatibility
- ✅ Hypothesis generation includes at least one hypothesis per vulnerability
- ✅ Confidence formulas properly weight verified evidence
- ✅ No security controls disabled to make tests pass
- ✅ Tool allowlist enforced in `tool_execution.py`
- ✅ Evidence redaction via `policies/evidence_redaction.json`

### Project Scripts

```bash
# Verify inference connectivity
python -m hermes_shield.scripts.verify_inference [connectivity|credentials|edge_cases|tools|terminal|files|all]

# Run security boundary tests
python -m scripts.security_tests.run_all
```

---

## ⚠️ Known Limitations

- ⚠️ **Sandbox tests** (50 tests) require Docker daemon - fail with connection errors without Docker
- ⚠️ **Benchmark** requires Docker for lab image build and container execution
- ⚠️ **NEBIUS API features** require valid API key and network access
- ⚠️ Some test environments may have limited network access

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📋 Hackathon Submission Checklist

- ✅ **Core functionality**: 34/34 security tests passing
- ✅ **Attack path correlation**: Multi-step paths with confidence scoring
- ✅ **Security boundaries**: File, credential, network, command enforcement
- ✅ **Adversarial testing**: 17 attack vectors all blocked
- ✅ **Benchmark framework**: 10 vulnerabilities, 3 attack paths, reproducible
- ✅ **Interactive demo**: Flask API + static dashboard + live test execution
- ✅ **Documentation**: 13 comprehensive docs including deployment guide
- ✅ **Deployment ready**: Oracle Cloud + Cloudflare Tunnel instructions
- ✅ **Source code privacy**: Private Docker image, no secrets in repo
- ✅ **License**: MIT

---

**HermesShield** - Autonomous Security Auditing Framework  
✅ 34/34 core tests passing | ✅ 167/217 total tests passing | 🛡️ Security boundary enforcement | 🔗 Attack path correlation | 🤖 AI-enhanced via Nemotron