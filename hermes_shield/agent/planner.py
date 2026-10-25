"""HermesShield Assessment Planner.

Builds multi-step assessment plans from security objectives.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from enum import Enum

from hermes_shield.agent.skills import Skill, SkillCategory, SkillRisk, skills_registry

logger = logging.getLogger(__name__)


class PlanType:
    RECONNAISSANCE = "reconnaissance"
    FULL_ASSESSMENT = "full_assessment"
    TARGETED = "targeted"
    COMPLIANCE = "compliance"
    RED_TEAM = "red_team"


class PlanStepStatus:
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


@dataclass
class PlanStep:
    step_id: int
    skill_name: str
    description: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    depends_on: List[int] = field(default_factory=list)
    status: str = PlanStepStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: float = 0.0


@dataclass
class AssessmentPlan:
    plan_id: str
    plan_type: str
    objective: str
    target: str
    scope: str
    steps: List = field(default_factory=list)
    created_at: str = ""
    max_risk: str = "MEDIUM"
    max_duration_minutes: int = 60
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_step(self, step_id):
        for step in self.steps:
            if step.step_id == step_id:
                return step
        return None

    def get_pending_steps(self):
        completed = {s.step_id for s in self.steps if s.status == PlanStepStatus.COMPLETED}
        pending = []
        for step in self.steps:
            if step.status == PlanStepStatus.PENDING:
                if all(dep in completed for dep in step.depends_on):
                    pending.append(step)
        return pending

    def get_next_steps(self):
        return self.get_pending_steps()

    def is_complete(self):
        return all(s.status in (PlanStepStatus.COMPLETED, PlanStepStatus.SKIPPED) for s in self.steps)

    def has_failures(self):
        return any(s.status == PlanStepStatus.FAILED for s in self.steps)


class AssessmentPlanner:
    def __init__(self, skills_registry=None):
        self.skills = skills_registry or {}

    def build_plan(
        self,
        objective,
        target,
        scope,
        plan_type=PlanType.FULL_ASSESSMENT,
        max_risk="MEDIUM",
        max_duration_minutes=60,
        available_tools=None,
        requested_skills=None
    ):
        import time
        from datetime import datetime, timezone

        plan_id = f"plan_{int(time.time())}"
        plan = AssessmentPlan(
            plan_id=plan_id,
            plan_type=plan_type,
            objective=objective,
            target=target,
            scope=scope,
            max_risk=max_risk,
            max_duration_minutes=max_duration_minutes,
            created_at=datetime.now(timezone.utc).isoformat()
        )

        steps = self._select_steps(plan_type, objective, target, max_risk, available_tools, requested_skills)
        plan.steps = steps

        logger.info("Built plan %s with %d steps for %s", plan_id, len(steps), target)
        return plan

    def _select_steps(
        self,
        plan_type,
        objective,
        target,
        max_risk,
        available_tools,
        requested_skills=None
    ):
        steps = []
        step_id = 0

        steps.append(self._create_step(
            step_id=step_id,
            skill_name="network_reconnaissance",
            description="Discover open ports and services on " + target,
            parameters={"target": "TARGET", "scan_type": "quick"}
        ))
        step_id += 1

        if "web" in objective.lower() or "http" in objective.lower() or "app" in objective.lower():
            steps.append(self._create_step(
                step_id=step_id,
                skill_name="http_reconnaissance",
                description="HTTP reconnaissance on " + target,
                parameters={"target": "TARGET", "check_tech": True, "discover_urls": True},
                depends_on=[step_id - 1]
            ))
            step_id += 1

        steps.append(self._create_step(
            step_id=step_id,
            skill_name="service_enumeration",
            description="Enumerate service versions on " + target,
            parameters={"target": "TARGET", "ports": "AUTO"},
            depends_on=[0]
        ))
        step_id += 1

        if "config" in objective.lower() or "config" in target.lower():
            steps.append(self._create_step(
                step_id=step_id,
                skill_name="configuration_auditing",
                description="Audit configuration files for misconfigurations",
                parameters={"target": "TARGET", "config_path": "AUTO"},
                depends_on=[0, 2]
            ))
            step_id += 1

        steps.append(self._create_step(
            step_id=step_id,
            skill_name="secret_detection",
            description="Scan for exposed secrets and credentials",
            parameters={"target": "TARGET", "search_paths": ["AUTO"]},
            depends_on=[0, 2]
        ))
        step_id += 1

        vuln_keyword = "vuln"
        obj_lower = objective.lower()
        tgt_lower = target.lower()
        if vuln_keyword in obj_lower or vuln_keyword in tgt_lower:
            steps.append(self._create_step(
                step_id=step_id,
                skill_name="vulnerability_validation",
                description="Validate identified vulnerabilities",
                parameters={"target": "TARGET", "check_type": "config"},
                depends_on=[2, 3, 4]
            ))
            step_id += 1

        steps.append(self._create_step(
            step_id=step_id,
            skill_name="attack_path_building",
            description="Build attack paths from validated findings",
            parameters={"target": "TARGET"},
            depends_on=[step_id - 1]
        ))
        step_id += 1

        steps.append(self._create_step(
            step_id=step_id,
            skill_name="impact_assessment",
            description="Assess impact of validated vulnerabilities",
            depends_on=[step_id - 1]
        ))
        step_id += 1

        steps.append(self._create_step(
            step_id=step_id,
            skill_name="evidence_collection",
            description="Collect and correlate all evidence",
            depends_on=list(range(step_id))
        ))
        step_id += 1

        steps.append(self._create_step(
            step_id=step_id,
            skill_name="remediation_planning",
            description="Generate remediation recommendations",
            depends_on=[step_id - 2]
        ))
        step_id += 1

        steps.append(self._create_step(
            step_id=step_id,
            skill_name="report_generation",
            description="Generate final assessment report",
            depends_on=[step_id - 2, step_id - 1]
        ))
        step_id += 1

        if requested_skills:
            selected_names = set(requested_skills)
            required_ids = {
                step.step_id for step in steps if step.skill_name in selected_names
            }
            changed = True
            while changed:
                changed = False
                for step in steps:
                    if step.step_id in required_ids:
                        before = set(required_ids)
                        required_ids.update(step.depends_on)
                        changed = changed or required_ids != before
            steps = [step for step in steps if step.step_id in required_ids]

        filtered_steps = self._filter_steps(steps, available_tools, max_risk)
        return filtered_steps

    def _create_step(
        self,
        step_id,
        skill_name,
        description,
        parameters=None,
        depends_on=None
    ):
        from hermes_shield.agent.planner import PlanStep, PlanStepStatus
        return PlanStep(
            step_id=step_id,
            skill_name=skill_name,
            description=description,
            parameters=parameters or {},
            depends_on=depends_on or [],
            status=PlanStepStatus.PENDING
        )

    def _filter_steps(self, steps, available_tools, max_risk):
        from hermes_shield.agent.skills import skills_registry

        risk_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
        max_risk_level = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}.get(max_risk, 1)

        filtered = []
        for step in steps:
            skill = self._get_skill(step.skill_name)
            if not skill:
                logger.warning("Unknown skill: %s, skipping", step.skill_name)
                continue

            skill_risk = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}.get(skill.risk.value, 1)
            if skill_risk > max_risk_level:
                logger.info("Skipping %s: risk %s > %s", step.skill_name, skill.risk.value, max_risk)
                continue

            if available_tools:
                missing = [t for t in skill.required_tools if t not in available_tools]
                if missing:
                    logger.warning("Skipping %s: missing tools %s", step.skill_name, missing)
                    continue

            filtered.append(step)

        return filtered

    def _get_skill(self, name):
        from hermes_shield.agent.skills import skills_registry
        return skills_registry.get_skill(name)


def create_default_plan(objective, target, scope):
    planner = AssessmentPlanner()
    return planner.build_plan(objective, target, scope)