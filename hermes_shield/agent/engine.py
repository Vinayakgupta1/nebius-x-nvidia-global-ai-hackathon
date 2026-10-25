"""HermesShield Execution Engine.

Executes assessment plans step by step with full logging and safety checks.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timezone
from enum import Enum

from hermes_shield.agent.planner import AssessmentPlan, PlanStep, PlanStepStatus, PlanStepStatus
from hermes_shield.agent.scope import Scope, ScopeEnforcer, ScopeViolation
from hermes_shield.agent.skills import Skill, skills_registry
from hermes_shield.memory import MemoryStore, create_memory_store
from hermes_shield.tools import tool_registry

logger = logging.getLogger(__name__)


class ExecutionResult(Enum):
    """Result of step execution."""
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


@dataclass
class StepExecution:
    """Result of a single step execution."""
    step_id: int
    skill_name: str
    status: ExecutionResult
    result: Dict[str, Any] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    error: Optional[str] = None
    started_at: str = ""
    completed_at: str = ""
    duration_seconds: float = 0.0
    memory_entries_created: List[str] = field(default_factory=list)


@dataclass
class ExecutionContext:
    """Context passed between steps during execution."""
    target: str
    scope: Any
    plan: Any
    memory: Any
    executions: List[Any] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    validated_vulnerabilities: List[str] = field(default_factory=list)
    false_positives: List[str] = field(default_factory=list)
    attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    tested_controls: List[Dict[str, Any]] = field(default_factory=list)
    remediation_items: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    assessment_history: List[Dict[str, Any]] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    technologies: List[Dict[str, Any]] = field(default_factory=list)
    directories: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    config_issues: List[Dict[str, Any]] = field(default_factory=list)
    secrets: List[Dict[str, Any]] = field(default_factory=list)
    attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    validated_vulns: List[Dict[str, Any]] = field(default_factory=list)
    false_positives: List[Dict[str, Any]] = field(default_factory=list)
    tested_controls_list: List[Dict[str, Any]] = field(default_factory=list)
    remediation_items_list: List[Dict[str, Any]] = field(default_factory=list)
    evidence_list: List[Dict[str, Any]] = field(default_factory=list)

    def get_context_dict(self) -> Dict[str, Any]:
        """Get context as dictionary for skill preconditions."""
        return {
            "target": self.target,
            "open_ports": self.open_ports,
            "services": self.services,
            "technologies": self.technologies,
            "directories": self.directories,
            "endpoints": self.endpoints,
            "vulnerabilities": self.vulnerabilities,
            "config_issues": self.config_issues,
            "secrets": self.secrets,
            "attack_paths": self.attack_paths,
            "hypotheses": self.hypotheses,
            "vulnerabilities": self.vulnerabilities,
            "validated_vulnerabilities": self.validated_vulnerabilities,
            "false_positives": self.false_positives,
            "attack_paths": self.attack_paths,
            "tested_controls": self.tested_controls_list,
        }


class ExecutionEngine:
    """Executes assessment plans with full safety and logging."""

    def __init__(
        self,
        plan: Any,
        scope: Any,
        memory: Any,
        scope_enforcer: Any,
        available_tools: Optional[set] = None,
        progress_callback: Optional[Callable] = None
    ):
        self.plan = plan
        self.scope = scope
        self.scope_enforcer = scope_enforcer
        self.memory = memory
        self.available_tools = available_tools or set()
        self.progress_callback = progress_callback

        # Initialize context
        self.context = ExecutionContext(
            target=plan.target,
            scope=scope,
            plan=plan,
            memory=memory
        )

        # Initialize skills registry
        from hermes_shield.agent.skills import skills_registry
        skills_registry.set_available_tools(self.available_tools)

        # Execution tracking
        self.executions: List[Any] = []
        self.started_at: Optional[str] = None
        self.completed_at: Optional[str] = None

        logger.info(f"Execution engine initialized for plan {plan.plan_id}")

    def execute_plan(self) -> Dict[str, Any]:
        """Execute the full assessment plan."""
        self.started_at = datetime.now(timezone.utc).isoformat()
        logger.info(f"Starting execution of plan {self.plan.plan_id}")

        # Notify progress
        if self.progress_callback:
            self.progress_callback({"type": "plan_start", "plan_id": self.plan.plan_id})

        try:
            while not self.plan.is_complete():
                next_steps = self.plan.get_next_steps()
                if not next_steps:
                    logger.warning("No executable steps remaining")
                    break

                # Execute steps (could be parallel, but sequential for safety)
                for step in next_steps:
                    if self.plan.is_complete():
                        break
                    execution = self._execute_step(step)
                    self.executions.append(execution)
                    self._update_context(execution)
                    self._record_audit(execution)

                    # Notify progress
                    if self.progress_callback:
                        self.progress_callback({
                            "type": "step_complete",
                            "step": step.step_id,
                            "skill": execution.skill_name,
                            "status": execution.status.value
                        })

                    # Check stop conditions
                    if self._should_stop():
                        logger.warning("Stop condition met, halting execution")
                        break

        except ScopeViolation as e:
            logger.error(f"Scope violation halted execution: {e}")
            self._record_fatal_error(f"Scope violation: {e}")
        except Exception as e:
            logger.error(f"Execution error: {e}")
            self._record_fatal_error(f"Execution error: {e}")

        self.completed_at = datetime.now(timezone.utc).isoformat()
        return self._generate_execution_summary()

    def _execute_step(self, step: Any) -> Any:
        """Execute a single plan step."""
        from hermes_shield.agent.planner import PlanStepStatus
        from hermes_shield.agent.skills import skills_registry

        step.status = PlanStepStatus.RUNNING
        step.started_at = datetime.now(timezone.utc).isoformat()
        start_time = time.time()

        logger.info(f"Executing step {step.step_id}: {step.skill_name}")

        # Create execution record
        execution = StepExecution(
            step_id=step.step_id,
            skill_name=step.skill_name,
            status=ExecutionResult.SUCCESS,
            started_at=step.started_at
        )

        try:
            # Get skill
            skill = skills_registry.get_skill(step.skill_name)
            if not skill:
                raise ValueError(f"Unknown skill: {step.skill_name}")

            # Check preconditions
            if not skill.can_execute(self.available_tools, self.context.get_context_dict()):
                raise ValueError(f"Preconditions not met for {step.skill_name}")

            # Execute skill
            result = self._execute_skill(skill, step.parameters)
            execution.result = result
            execution.status = ExecutionResult.SUCCESS

            # Extract evidence
            execution.evidence = result.get("evidence", [])
            execution.evidence_ids = result.get("evidence_ids", [])

            # Update step
            step.status = PlanStepStatus.COMPLETED
            step.result = result
            step.completed_at = datetime.now(timezone.utc).isoformat()

        except Exception as e:
            logger.error(f"Step {step.step_id} failed: {e}")
            execution.status = ExecutionResult.FAILED
            execution.error = str(e)
            step.status = PlanStepStatus.FAILED
            step.error = str(e)
            step.completed_at = datetime.now(timezone.utc).isoformat()

        finally:
            step.duration_seconds = time.time() - start_time
            execution.duration_seconds = step.duration_seconds
            execution.completed_at = datetime.now(timezone.utc).isoformat()

        return execution

    def _execute_skill(self, skill: Any, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a skill by invoking its tool."""
        # Resolve parameter placeholders
        resolved_params = self._resolve_parameters(parameters)

        # Get tool instance
        tool = tool_registry.get(skill.required_tools[0]) if skill.required_tools else None
        if not tool:
            # For skills without tools, return context-based result
            return self._execute_builtin_skill(skill)

        # Execute tool
        result = tool.execute(**resolved_params)

        # Sanitize result
        from hermes_shield.memory import sanitize_dict
        result = {
            "success": result.success,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.exit_code,
            "evidence": [result.stdout, result.stderr] if result.stdout else [],
            "evidence_ids": [],
            "tool": skill.required_tools[0],
            "skill": skill.name
        }

        return result

    def _execute_builtin_skill(self, skill: Any) -> Dict[str, Any]:
        """Execute skills without external tools (analysis/analysis skills)."""
        context = self.context.get_context_dict()

        if skill.name == "impact_assessment":
            return self._assess_impact()
        elif skill.name == "attack_path_building":
            return self._build_attack_paths()
        elif skill.name == "evidence_collection":
            return self._collect_evidence()
        elif skill.name == "report_generation":
            return self._generate_report()
        elif skill.name == "remediation_planning":
            return self._plan_remediation()
        else:
            return {"success": True, "result": "Built-in skill executed"}

    def _assess_impact(self) -> Dict[str, Any]:
        """Assess impact of validated vulnerabilities."""
        vulns = self.context.validated_vulns
        if not vulns:
            return {"success": True, "impact": "No validated vulnerabilities to assess"}

        impact = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "details": []
        }

        for vuln in self.context.validated_vulns:
            severity = vuln.get("severity", "MEDIUM").lower()
            impact[severity] = impact.get(severity, 0) + 1
            impact["details"].append({
                "title": vuln.get("title", "Unknown"),
                "severity": severity,
                "affected": vuln.get("target", "unknown")
            })

        return {"success": True, "impact": impact, "evidence": [json.dumps(impact)]}

    def _build_attack_paths(self) -> Dict[str, Any]:
        """Build attack paths from validated findings."""
        vulns = self.context.validated_vulns
        if len(vulns) < 2:
            return {"success": True, "attack_paths": [], "message": "Need at least 2 findings for chaining"}

        paths = []
        # Simple chaining logic
        for i, v1 in enumerate(vulns):
            for v2 in vulns[i+1:]:
                paths.append({
                    "title": f"Chain: {v1.get('title')} -> {v2.get('title')}",
                    "description": f"Chain {v1.get('title')} with {v2.get('title')}",
                    "chained_findings": [v1.get("id"), v2.get("id")],
                    "risk": "MEDIUM"
                })

        return {"success": True, "attack_paths": paths, "evidence": [json.dumps(paths)]}

    def _collect_evidence(self) -> Dict[str, Any]:
        """Collect and correlate evidence."""
        evidence = {
            "executions": [e.to_dict() if hasattr(e, 'to_dict') else str(e) for e in self.executions],
            "memory_entries": self.context.memory.export() if hasattr(self.context.memory, 'export') else [],
            "findings": self.context.findings,
            "hypotheses": self.context.hypotheses,
            "attack_paths": self.context.attack_paths,
        }
        return {"success": True, "evidence": [json.dumps(evidence)], "evidence_ids": []}

    def _generate_report(self) -> Dict[str, Any]:
        """Generate final report."""
        report = {
            "plan_id": self.plan.plan_id,
            "target": self.plan.target,
            "scope": self.plan.scope,
            "objective": self.plan.objective,
            "started_at": self.started_at,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "executions": len(self.executions),
            "successful": sum(1 for e in self.executions if e.status == "success"),
            "failed": sum(1 for e in self.executions if e.status == "failed"),
            "findings": self.context.findings,
            "hypotheses": self.context.hypotheses,
            "validated_vulnerabilities": self.context.validated_vulns,
            "attack_paths": self.context.attack_paths,
            "remediation": self.context.remediation_items_list,
            "evidence": self.context.evidence_list,
        }
        return {"success": True, "report": report, "evidence": [json.dumps(report)]}

    def _plan_remediation(self) -> Dict[str, Any]:
        """Generate remediation recommendations."""
        remediations = []
        for vuln in self.context.validated_vulns:
            remediations.append({
                "finding_id": vuln.get("id"),
                "title": vuln.get("title"),
                "priority": vuln.get("severity", "MEDIUM"),
                "recommendation": f"Patch/mitigate {vuln.get('title', 'vulnerability')}",
                "effort": "MEDIUM"
            })

        return {"success": True, "remediation": remediations, "evidence": [json.dumps(remediations)]}

    def _resolve_parameters(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve parameter placeholders."""
        resolved = {}
        for key, value in parameters.items():
            if value == "TARGET":
                resolved[key] = self.plan.target
            elif value == "AUTO":
                # Auto-detect based on context
                if key == "ports":
                    resolved[key] = ",".join(map(str, self.context.open_ports)) if self.context.open_ports else "1-1000"
                elif key == "config_path":
                    resolved[key] = "./config"
                elif key == "search_paths":
                    resolved[key] = [".", "./config"]
                elif key == "target":
                    resolved[key] = self.plan.target
                elif key == "check_type":
                    resolved[key] = "config"
                else:
                    resolved[key] = value
            else:
                resolved[key] = value
        return resolved

    def _update_context(self, execution: Any) -> None:
        """Update execution context with step results."""
        if execution.status != "success":
            return

        result = execution.result
        skill_name = execution.skill_name

        if skill_name == "network_reconnaissance":
            self._extract_ports(execution.result)
        elif skill_name == "http_reconnaissance":
            self._extract_http_info(execution.result)
        elif skill_name == "service_enumeration":
            self._extract_services(execution.result)
        elif skill_name == "configuration_auditing":
            self._extract_config_issues(execution.result)
        elif skill_name == "secret_detection":
            self._extract_secrets(execution.result)
        elif skill_name == "vulnerability_validation":
            self._extract_vulnerabilities(execution.result)
        elif skill_name == "attack_path_building":
            self._extract_attack_paths(execution.result)
        elif skill_name == "impact_assessment":
            pass  # Already handled
        elif skill_name == "evidence_collection":
            pass  # Already handled
        elif skill_name == "report_generation":
            pass  # Already handled
        elif skill_name == "remediation_planning":
            pass  # Already handled

    def _extract_ports(self, result: Dict[str, Any]) -> None:
        """Extract open ports from network recon result."""
        ports = result.get("open_ports", [])
        self.context.open_ports = list(set(self.context.open_ports + ports))

    def _extract_http_info(self, result: Dict[str, Any]) -> None:
        """Extract HTTP recon info."""
        tech = result.get("technology_fingerprint", {})
        if tech:
            self.context.technologies.append(tech)
        urls = result.get("discovered_urls", [])
        self.context.endpoints.extend(urls)

    def _extract_services(self, result: Dict[str, Any]) -> None:
        """Extract service enumeration results."""
        services = result.get("services", [])
        self.context.services.extend(services)

    def _extract_config_issues(self, result: Dict[str, Any]) -> None:
        """Extract configuration issues."""
        findings = result.get("findings", [])
        self.context.config_issues.extend(findings)

    def _extract_secrets(self, result: Dict[str, Any]) -> None:
        """Extract detected secrets."""
        secrets = result.get("secrets_found", [])
        self.context.secrets.extend(secrets)

    def _extract_vulnerabilities(self, result: Dict[str, Any]) -> None:
        """Extract validated vulnerabilities."""
        vulns = result.get("details", {})
        if vulns.get("confirmed"):
            vuln = {
                "title": "Validated vulnerability",
                "details": vulns.get("evidence", ""),
                "risk": vulns.get("risk_rating", "MEDIUM"),
                "id": f"vuln_{len(self.context.validated_vulns)+1}"
            }
            self.context.validated_vulns.append(vuln)
            self.context.validated_vulns.append(vuln.get("id", ""))

    def _extract_attack_paths(self, result: Dict[str, Any]) -> None:
        paths = result.get("attack_paths", [])
        self.context.attack_paths.extend(paths)

    def _record_audit(self, execution: Any) -> None:
        """Record audit log entry."""
        audit_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "step_id": execution.step_id,
            "skill": execution.skill_name,
            "status": execution.status.value,
            "duration": execution.duration_seconds,
            "evidence_count": len(execution.evidence),
            "memory_entries": len(execution.memory_entries_created)
        }
        self.context.assessment_history.append(audit_entry)
        logger.info(f"AUDIT: {json.dumps(audit_entry)}")

    def _should_stop(self) -> bool:
        """Check if execution should stop."""
        # Check scope violations
        if self.scope_enforcer.get_violations():
            return True

        # Check time limit
        if self.started_at:
            elapsed = time.time() - time.mktime(
                datetime.fromisoformat(self.started_at.replace('Z', '+00:00')).timetuple()
            )
            if elapsed > self.plan.max_duration_minutes * 60:
                logger.warning("Time limit exceeded")
                return True

        # Check critical failures
        critical_failures = sum(1 for e in self.executions if e.status == "failed")
        if critical_failures > 3:
            logger.warning("Too many failures, stopping")
            return True

        return False

    def _record_fatal_error(self, error: str) -> None:
        """Record fatal error."""
        audit_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "FATAL_ERROR",
            "error": error,
            "plan_id": self.plan.plan_id
        }
        self.context.assessment_history.append(audit_entry)

    def _generate_execution_summary(self) -> Dict[str, Any]:
        """Generate final execution summary."""
        return {
            "plan_id": self.plan.plan_id,
            "target": self.plan.target,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": time.time() - time.mktime(
                datetime.fromisoformat(self.started_at.replace('Z', '+00:00')).timetuple()
            ) if self.started_at else 0,
            "total_steps": len(self.plan.steps),
            "completed_steps": sum(1 for e in self.executions if e.status == "success"),
            "failed_steps": sum(1 for e in self.executions if e.status == "failed"),
            "scope_violations": len(self.scope_enforcer.get_violations()),
            "findings_count": len(self.context.validated_vulns),
            "hypotheses_count": len(self.context.hypotheses),
            "attack_paths_count": len(self.context.attack_paths),
            "evidence_count": sum(len(e.evidence) for e in self.executions),
            "memory_entries": sum(len(e.memory_entries_created) for e in self.executions),
            "executions": [e.to_dict() if hasattr(e, 'to_dict') else str(e) for e in self.executions],
        }


def execute_assessment(
    objective: str,
    target: str,
    scope: str,
    memory: Any,
    scope_enforcer: Any,
    available_tools: Optional[set] = None
) -> Dict[str, Any]:
    """Convenience function to execute a full assessment."""
    from hermes_shield.agent.planner import AssessmentPlanner, PlanType

    planner = AssessmentPlanner()
    plan = planner.build_plan(objective, target, scope)

    engine = ExecutionEngine(
        plan=plan,
        scope=scope,
        memory=memory,
        scope_enforcer=scope_enforcer,
        available_tools=available_tools
    )

    return engine.execute_plan()