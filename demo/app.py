"""Browser-facing hackathon demo for HermesShield.

This server exposes a bounded, deterministic simulation over HTTP. It does
not execute arbitrary commands or run a real scan against a visitor-provided
target. The response mirrors the project's real assessment stages so judges
can see the control flow without using the CLI or touching a live system.
"""

from datetime import datetime, timezone
from pathlib import Path
import sys

from flask import Flask, jsonify, request, send_file

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from hermes_shield.nemotron import generate_audit_plan

app = Flask(__name__)

DEMO_STAGES = [
    {
        "id": "scope",
        "title": "Scope target",
        "label": "AUTHORIZED SCOPE",
        "heading": "Start with a target, not a command.",
        "description": "The operator defines the approved target and audit boundaries before any tool is allowed to run.",
        "code": ["target: demo-web", "scope: approved", "network: target_only", "filesystem: read_only", "credentials: none"],
        "event": "scope accepted // policy loaded",
    },
    {
        "id": "tools",
        "title": "Run tools",
        "label": "STRUCTURED EXECUTION",
        "heading": "Use an allowlisted tool.",
        "description": "HermesShield validates the input schema, selects the approved tool, and enforces a timeout before execution.",
        "code": ["tool: network_reconnaissance", "scan: quick", "ports: 80,443", "timeout: 60s", "shell: disabled"],
        "event": "tool result // 2 services discovered",
    },
    {
        "id": "contain",
        "title": "Contain",
        "label": "BOUNDARY CHECK",
        "heading": "Stop unsafe requests at the edge.",
        "description": "Path traversal, unapproved destinations, shell operators, and credential access are rejected before they reach the host.",
        "code": ["request: ../etc/passwd", "normalized: outside root", "decision: BLOCK", "reason: path allowlist"],
        "event": "TOOL_BLOCKED // boundary held",
    },
    {
        "id": "evidence",
        "title": "Collect evidence",
        "label": "REDACTED EVIDENCE",
        "heading": "Keep proof without keeping secrets.",
        "description": "Results are sanitized, structured, timestamped, and written with restricted permissions for later review.",
        "code": ["finding: exposed header", "secret_value: [REDACTED]", "evidence: hash + timestamp", "permissions: 0600"],
        "event": "evidence saved // secret masked",
    },
    {
        "id": "correlate",
        "title": "Correlate path",
        "label": "SUPPORTED RELATIONSHIP",
        "heading": "Connect only what evidence supports.",
        "description": "Findings become an attack path only when their relationship is backed by compatible evidence and confidence.",
        "code": ["finding A: exposed service", "finding B: weak control", "confidence: 0.86", "status: hypothesis"],
        "event": "path built // confidence tracked",
    },
    {
        "id": "report",
        "title": "Generate report",
        "label": "DEFENSIBLE OUTPUT",
        "heading": "End with a decision people can act on.",
        "description": "The final report separates verified facts, hypotheses, and remediation priorities so nothing is overstated.",
        "code": ["status: 17 / 17 passed", "critical: 1", "high: 2", "next: remediate sandbox"],
        "event": "report ready // findings prioritized",
    },
]


@app.get("/")
def index():
    """Serve the browser demo from the project root."""
    return send_file(PROJECT_ROOT / "index.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "healthy", "demo": "ready"})


@app.get("/api/project/info")
def project_info():
    return jsonify({
        "name": "HermesShield",
        "description": "Autonomous Security Auditing Framework",
        "tests": {"attack_path": 11, "security_boundary": 6, "adversarial": 17, "total": 34},
        "features": ["Attack Path Correlation", "Security Boundary Enforcement", "Evidence Redaction", "Reproducible Benchmarks"],
    })


@app.post("/api/demo/run")
def run_demo():
    """Return one safe, browser-consumable assessment simulation."""
    payload = request.get_json(silent=True) or {}
    target = str(payload.get("target", "demo-web")).strip() or "demo-web"
    if len(target) > 80 or any(char in target for char in "\r\n\x00"):
        return jsonify({"error": "Invalid demo target"}), 400

    model_plan = generate_audit_plan(
        target,
        "Demonstrate a bounded security assessment with evidence and remediation",
    )

    return jsonify({
        "audit_id": "demo-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
        "target": target,
        "mode": "safe_simulation",
        "model": model_plan,
        "stages": DEMO_STAGES,
        "summary": {"status": "complete", "blocked_requests": 1, "evidence_items": 4, "confidence": 0.86},
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
