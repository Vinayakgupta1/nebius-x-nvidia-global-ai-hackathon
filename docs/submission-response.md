## Inspiration

Security tools can discover vulnerabilities, but raw findings are difficult to trust and prioritize. A scanner may identify an exposed service, a weak configuration, and a leaked secret without explaining whether those findings form a realistic attack path.

HermesShield was inspired by the need for security automation that is both useful and reviewable. We designed it around a controlled pipeline:

$$
\mathrm{Scope} \rightarrow \mathrm{Tool\ Execution} \rightarrow \mathrm{Evidence} \rightarrow \mathrm{Correlation} \rightarrow \mathrm{Remediation}
$$

The goal is not to give an AI agent unrestricted command access. The goal is to let Nemotron contribute security reasoning while HermesShield enforces the boundaries.

## What It Does

HermesShield creates bounded security assessment plans, executes approved security skills, collects redacted evidence, and correlates findings into confidence-aware attack paths.

The project provides:

- Explicit target and action scope enforcement
- Allowlisted security tools with timeouts and environment restrictions
- Safe vulnerability validation without exploitation
- Secret and credential redaction before persistence
- Persistent memory states such as `VERIFIED`, `KNOWN`, and `HYPOTHESIS`
- Attack-path correlation with evidence and confidence tracking
- Remediation and assessment reports
- A browser-based interactive demonstration for judges

The demo lets judges follow the audit lifecycle from target scoping through model planning, boundary blocking, evidence collection, correlation, and report generation without using the command line or scanning a live target.

## How We Built It

The core system is written in Python. `HermesAgent` coordinates scope validation, planning, execution, evidence collection, memory, and reporting.

Nemotron is accessed through Nebius Token Factory for bounded audit-plan generation. The model receives the target, objective, allowed skill names, and strict safety constraints. Its response must be structured JSON. HermesShield validates every returned skill against an allowlist, preserves plan dependencies, and prevents shell commands, credentials, arbitrary tools, and exploitation payloads from entering the plan.

The browser experience is powered by Flask and communicates with the backend through a JSON API. When Nebius credentials are unavailable, the interface clearly reports `SAFE FALLBACK` and runs a deterministic simulation so the demo remains reproducible.

## Challenges We Ran Into

The main challenges were:

1. Connecting model-generated planning to a deterministic execution engine.
2. Preventing arbitrary model output from becoming an executable tool request.
3. Preserving evidence while removing secrets and credentials.
4. Correlating findings without overstating unsupported relationships.
5. Turning a command-line security framework into a clear browser experience.
6. Designing a demo that is interactive without requiring judges to configure scanners or access a live target.

We addressed these challenges by treating Nemotron as a bounded planning component rather than an unrestricted command executor, and by validating every transition between model output, tools, evidence, and reports.

## Accomplishments That We're Proud Of

- Built an end-to-end browser demonstration instead of requiring judges to use the CLI.
- Added a real Nebius/Nemotron planning integration with structured output validation.
- Made model-generated skills influence the actual assessment plan while preserving dependencies.
- Implemented scope enforcement, tool allowlisting, timeout controls, and safe fallback behavior.
- Added evidence redaction and restricted evidence persistence.
- Built attack-path correlation that distinguishes observed facts, hypotheses, and validated relationships.
- Created a reproducible benchmark and adversarial security test suites.

## What We Learned

We learned that an AI security system needs more than a capable model. It needs strong boundaries around model actions, clear separation between facts and hypotheses, evidence validation before reasoning, secret redaction before persistence, confidence tracking, and human-readable explanations.

We also learned that a strong security demo should show both successful behavior and blocked behavior. Demonstrating a rejected path-traversal request is more informative than showing only a successful scan.

## What's Next for HermesShield

- Deploy the Flask demo to a public, judge-accessible URL.
- Add a richer live execution view for approved benchmark targets.
- Compare Nemotron deployments using a repeatable planning-quality benchmark.
- Add streaming model-plan explanations and execution progress to the UI.
- Expand scope and network policy enforcement across every tool input.
- Improve report export and remediation tracking.
- Add stronger integration tests for the full Nemotron-to-plan-to-report path.

---

## Built With

Suggested tags:

- NVIDIA Nemotron
- Nebius Token Factory
- Python
- Flask
- Security Automation
- Cybersecurity
- AI Agents
- Agentic AI
- Security Auditing
- Threat Detection
- Attack Path Analysis
- Vulnerability Assessment
- Evidence Redaction
- Prompt Engineering
- Structured Outputs
- JSON Schema
- Sandboxing
- Docker
- Network Security
- Secret Detection
- Risk Analysis
- Security Boundaries
- Automated Reporting
- Responsive Web UI
- Open Source

---

## Did You Fine-Tune, Prompt-Engineer, Or Use Nemotron Out Of The Box?

We used Nemotron without fine-tuning and focused on prompt engineering and output validation.

The model receives:

- The authorized target
- The assessment objective
- An allowlist of valid HermesShield skills
- A strict JSON response schema
- Constraints prohibiting shell commands, credentials, arbitrary tools, exploitation payloads, and unsupported actions

The model is asked to produce a bounded audit plan rather than execute commands directly. HermesShield then validates the response, removes unknown skills, limits the number of requested skills, and preserves required plan dependencies before execution.

This approach lets Nemotron contribute reasoning while keeping execution deterministic and policy-controlled.

---

## How Did Nemotron Compare To Other Models?

We did not perform a formal, statistically controlled benchmark across models, so we avoid claiming unsupported numerical performance differences.

For this project, we evaluated usefulness based on:

- Ability to produce structured audit plans
- Ability to follow strict output constraints
- Quality of security reasoning
- Relevance of selected assessment skills
- Ease of integration through Nebius
- Reliability of JSON output after validation

Nemotron was a strong fit because the task required structured reasoning over security objectives rather than open-ended text generation. The most important result was not simply producing a plausible answer; it was producing a plan that could be validated and safely connected to the HermesShield execution pipeline.

---

## Which Nebius Platform Capabilities Were Most Valuable?

The most valuable capability was hosted access to NVIDIA Nemotron through the Nebius Token Factory API.

We used:

- API-based model access
- Environment-based credential configuration
- Configurable model selection through `NEBIUS_MODEL`
- Configurable endpoint, timeout, and token limits
- JSON-compatible chat completion requests
- A lightweight integration that did not require managing GPU servers directly

The application sends a constrained planning request to the Nebius-compatible chat completion endpoint. The response is parsed, validated, and converted into a HermesShield plan.

Security was a deliberate part of the integration: the Nebius API key is loaded only from a local server-side environment variable, is never hardcoded or committed, and is never sent to the browser. The demo exposes only connection status and model metadata, never the credential itself.

We used hosted API access rather than manually provisioning GPU servers or managing a custom inference cluster. This reduced infrastructure overhead and allowed us to focus on security orchestration, evidence handling, and the interactive demonstration.

The integration is designed so the model can be changed between supported Nemotron deployments, including our Nemotron 3.5 Lightning 30B and Nemotron 3 Ultra 550B configurations.

For production deployment, the Flask demo can be hosted behind a public web URL while keeping `NEBIUS_API_KEY` server-side and inaccessible to the browser.

---

## Which AI Tools Did You Use?

- **NVIDIA Nemotron 3.5 Lightning 30B** for security-planning experiments and model evaluation
- **NVIDIA Nemotron 3 Ultra 550B** for larger reasoning and planning experiments
- **Nebius Token Factory** for hosted model access
- **OpenCode** for AI-assisted software development, debugging, refactoring, and implementation
- **GitHub Copilot** for code navigation, review, and development assistance

OpenCode and GitHub Copilot were used as development tools. Nemotron through Nebius is the model integration intended to power the submitted application’s bounded audit-plan generation.

---

## What Do You Most Hope To See From The Nemotron Team Next?

I would like to see more structured-output and tool-use guidance for security and agentic applications, especially best practices for reliable JSON generation, plan validation, and safe tool orchestration.

Longer context windows, improved reasoning transparency, and better support for streaming structured responses would also help security workflows. These capabilities would make it easier to show how the model reached a planning decision while keeping execution constrained.

## What Additional Features Or Improvements Would Have Made The Nemotron On Nebius Experience More Effective?

The most useful improvements would be:

- Clearer model-specific examples for structured JSON planning
- Built-in schema-constrained generation
- Easier request tracing and inference logs
- Latency and token-usage dashboards
- Simple model comparison tools
- More detailed error messages for endpoint and model configuration issues
- A lightweight local development mode that mirrors the hosted API

These features would make it easier to evaluate model behavior, diagnose failed requests, and compare Nemotron deployments during development.

## How Would You Rate Your Experience Running Nemotron Inference On Nebius?

**Rating: 7/10**

Nebius Token Factory provides a convenient way to access Nemotron without provisioning or managing GPU infrastructure. The API-based integration allowed us to focus on the application’s security controls, evidence pipeline, and browser demonstration.

The main areas for improvement are clearer deployment guidance, stronger observability, and easier validation of model availability before running an application. Our project also uses a safe fallback when credentials or inference are unavailable, which makes local development reliable but means live inference still needs separate validation.

## How Likely Are You To Recommend Running Nemotron On Nebius To Other Developers?

**Rating: 8/10**

I would recommend it to developers who want hosted access to NVIDIA Nemotron without operating their own GPU infrastructure. The API model works well for structured planning tasks and allowed us to integrate Nemotron into a Python and Flask application with minimal infrastructure overhead.

I would especially recommend it for teams building agentic applications that need a hosted reasoning model combined with application-level safety controls. More detailed observability, model comparison, and schema-constrained output features would make the experience even stronger.

## How Would You Rate Nemotron's Output Quality For Your Use Case?

**Rating: 8/10**

Nemotron produced useful, structured output for security audit planning. Its strongest qualities were instruction-following, the ability to work within explicit constraints, and suitability for converting an assessment objective into a bounded set of approved security skills.

What worked well:

- Followed structured JSON output requirements
- Respected the provided skill allowlist
- Supported clear security-planning prompts
- Produced reasoning that could be validated before execution
- Worked well with constraints prohibiting shell commands, credentials, payloads, and arbitrary tools
- Provided useful summaries and reasons for selected audit skills

What fell short:

- Model output still required strict schema and allowlist validation
- Some responses may require retry or fallback handling if the JSON format is malformed
- More transparent reasoning would help judges and security reviewers understand planning decisions
- We did not perform a formal multilingual evaluation, so multilingual quality was not measured

For this use case, Nemotron was a strong fit because the project prioritizes bounded, structured reasoning over unrestricted text generation.
