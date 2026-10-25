# HermesShield Browser Demo

This is the hackathon-facing browser demo. It serves the project page and exposes a safe, deterministic simulation over HTTP so judges can see the assessment lifecycle without using the CLI or touching a live target.

## Start

From the project root:

```powershell
python -m pip install -e .
python demo/app.py
```

Open <http://127.0.0.1:5000/> in a browser and select **Live demo** or **Explore live report**.

## What The Demo Shows

1. Scope is accepted before any tool runs.
2. A structured, allowlisted tool request is prepared.
3. An unsafe path traversal request is blocked at the boundary.
4. Evidence is redacted and marked for restricted persistence.
5. Findings are correlated only when evidence supports the relationship.
6. A report separates verified facts, hypotheses, and remediation priorities.

The browser calls `POST /api/demo/run`. The endpoint returns the stage data and a demo audit ID. It does not execute shell commands, scan visitor-provided targets, or access credentials.

## Source Review Notes

- The browser demo server intentionally does not use the previous `shell=True` test runner.
- The full project still contains separate runtime issues outside this demo path, including an undefined `agent_cfg` reference in `hermes_shield/agent.py` and permissive `extra_env` handling in `hermes_shield/tool_execution.py`. Those should be addressed before presenting a real-target execution mode.
