"""Small, dependency-light Nebius Token Factory client for audit planning.

The API key is read from server-side environment configuration, used only in
the outbound Authorization header, and never included in returned metadata.
"""

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List

from hermes_shield.config import nebius_config


ALLOWED_PLAN_SKILLS = {
    "network_reconnaissance",
    "http_reconnaissance",
    "service_enumeration",
    "configuration_auditing",
    "secret_detection",
    "vulnerability_validation",
    "attack_path_building",
    "impact_assessment",
    "evidence_collection",
    "remediation_planning",
    "report_generation",
}


def _endpoint() -> str:
    return nebius_config.endpoint.rstrip("/") + "/chat/completions"


def _extract_json(content: str) -> Dict[str, Any]:
    content = content.strip()
    if content.startswith("```"):
        content = content.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    return json.loads(content)


def generate_audit_plan(target: str, objective: str) -> Dict[str, Any]:
    """Ask Nemotron for a bounded plan and validate its actionable fields."""
    if not nebius_config.is_configured:
        return {"status": "unconfigured", "model": nebius_config.model_name, "skills": []}

    prompt = {
        "target": target,
        "objective": objective,
        "allowed_skills": sorted(ALLOWED_PLAN_SKILLS),
        "constraints": [
            "Return JSON only.",
            "Use only allowed_skills.",
            "Do not include shell commands, payloads, credentials, or exploitation instructions.",
            "Keep the plan to at most 6 skills.",
        ],
        "schema": {"summary": "string", "skills": [{"name": "allowed skill", "reason": "string"}]},
    }
    request_body = {
        "model": nebius_config.model_name,
        "temperature": 0.1,
        "max_tokens": min(nebius_config.max_tokens, 1200),
        "messages": [
            {"role": "system", "content": "You are a security planning assistant. Produce bounded, defensive audit plans."},
            {"role": "user", "content": json.dumps(prompt)},
        ],
    }
    request = urllib.request.Request(
        _endpoint(),
        data=json.dumps(request_body).encode("utf-8"),
        headers={"Authorization": f"Bearer {nebius_config.api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=nebius_config.timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        content = payload["choices"][0]["message"]["content"]
        plan = _extract_json(content)
        skills: List[Dict[str, str]] = []
        for item in plan.get("skills", []):
            name = item.get("name") if isinstance(item, dict) else None
            if name in ALLOWED_PLAN_SKILLS:
                skills.append({"name": name, "reason": str(item.get("reason", ""))[:240]})
        return {
            "status": "model_generated",
            "model": nebius_config.model_name,
            "summary": str(plan.get("summary", ""))[:500],
            "skills": skills[:6],
        }
    except (OSError, KeyError, TypeError, ValueError, urllib.error.URLError) as exc:
        return {
            "status": "fallback",
            "model": nebius_config.model_name,
            "skills": [],
            "error": type(exc).__name__,
        }
