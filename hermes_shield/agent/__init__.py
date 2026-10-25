"""HermesShield Autonomous Security Auditor - Main Agent Module.

Orchestrates the complete autonomous security assessment lifecycle.
"""

import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field

from hermes_shield.config import setup_logging, nebius_config, agent_config
from hermes_shield.agent.scope import Scope, ScopeEnforcer, parse_scope_declaration, validate_authorization
from hermes_shield.agent.skills import initialize_skills_registry
from hermes_shield.agent.planner import AssessmentPlanner, PlanType, AssessmentPlan
from hermes_shield.agent.engine import ExecutionEngine, ExecutionContext
from hermes_shield.agent.reporting import generate_report, ReportFormat
from hermes_shield.memory import create_memory_store, MemoryStore
from hermes_shield.tools import tool_registry
from hermes_shield.nemotron import generate_audit_plan

# Configure logging
setup_logging()
logger = logging.getLogger(__name__)


@dataclass
class AgentConfig:
    """Configuration for the Hermes Agent."""
    max_risk: str = "MEDIUM"  # LOW, MEDIUM, HIGH
    max_duration_minutes: int = 60
    available_tools: Optional[Set[str]] = None
    authorization_token: Optional[str] = None
    output_format: str = "markdown"  # markdown, json, html


class HermesAgent:
    """Autonomous security auditing agent."""

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or AgentConfig()
        self.memory: Optional[MemoryStore] = None
        self.scope: Optional[Any] = None
        self.scope_enforcer: Optional[Any] = None
        self.plan: Optional[Any] = None
        self.execution_engine: Optional[Any] = None

        logger.info("HermesAgent initialized")

    def assess(
        self,
        objective: str,
        target: str,
        scope: str,
        config: Optional[AgentConfig] = None
    ) -> Dict[str, Any]:
        """
        Execute a complete autonomous security assessment.

        Args:
            objective: Security assessment objective
            target: Target system (IP, domain, URL)
            scope: Scope declaration string
            config: Optional override configuration

        Returns:
            Dict with assessment results and report
        """
        if config:
            self.config = config

        logger.info(f"Starting assessment: {objective} against {target}")

        # 1. Parse scope
        self.scope = parse_scope_declaration(scope)
        self.scope.target = target  # Ensure target is set
        logger.info(f"Scope parsed: {self.scope.target}, rules: {len(self.scope.rules)}")

        # 2. Validate authorization
        if not validate_authorization(self.scope, self.config.authorization_token):
            raise ValueError(
                "Authorization missing or invalid. "
                "Provide authorization_token in config or set authorization_ref in scope."
            )

        # 2. Create scope enforcer
        self.scope_enforcer = ScopeEnforcer(self.scope)

        # 3. Initialize memory
        self.memory = create_memory_store(target=target)

        # 4. Initialize skills registry with available tools
        available_tools = self.config.available_tools or set(tool_registry.list_tools())
        from hermes_shield.agent.skills import initialize_skills_registry
        initialize_skills_registry(self.config.available_tools or set(tool_registry.list_tools()))

        # 4. Build assessment plan
        from hermes_shield.agent.planner import PlanType
        plan_type = PlanType.FULL_ASSESSMENT
        model_plan = generate_audit_plan(target, objective)
        planner = AssessmentPlanner()
        requested_skills = [item["name"] for item in model_plan.get("skills", [])]
        self.plan = planner.build_plan(
            objective=objective,
            target=target,
            scope=scope,
            max_risk=self.config.max_risk,
            max_duration_minutes=self.config.max_duration_minutes,
            available_tools=set(tool_registry.list_tools()) & (self.config.available_tools or set(tool_registry.list_tools())),
            requested_skills=requested_skills or None,
        )
        self.plan.metadata["model_plan"] = model_plan

        logger.info(f"Plan created with {len(self.plan.steps)} steps")

        # 5. Initialize execution engine
        self.execution_engine = ExecutionEngine(
            plan=self.plan,
            scope=self.scope,
            memory=self.memory,
            scope_enforcer=self.scope_enforcer,
            available_tools=self.config.available_tools or set()
        )

        # 6. Execute plan
        execution_result = self.execution_engine.execute_plan()

        # 7. Generate report
        report = generate_report(
            memory=self.memory,
            plan_id=self.plan.plan_id,
            target=target,
            objective=self.plan.objective,
            format=self.config.output_format
        )

        # 8. Compile final result
        result = {
            "plan_id": self.plan.plan_id,
            "target": target,
            "objective": objective,
            "scope": scope,
            "execution": execution_result,
            "report": report,
            "memory_stats": self.memory.get_stats() if self.memory else {},
            "scope_violations": len(self.scope_enforcer.get_violations()) if self.scope_enforcer else 0,
            "model_plan": model_plan,
        }

        logger.info(f"Assessment complete: {self.plan.plan_id}")
        return result

    def get_memory(self) -> Optional[MemoryStore]:
        """Get the memory store."""
        return self.memory

    def get_plan(self) -> Optional[Any]:
        """Get the current plan."""
        return self.plan

    def get_scope(self) -> Optional[Any]:
        """Get the current scope."""
        return self.scope


def run_assessment(
    objective: str,
    target: str,
    scope: str,
    max_risk: str = "MEDIUM",
    max_duration_minutes: int = 60,
    output_format: str = "markdown",
    authorization_token: Optional[str] = None,
    available_tools: Optional[Set[str]] = None
) -> Dict[str, Any]:
    """
    Convenience function to run a complete assessment.

    Args:
        objective: Security assessment objective
        target: Target system (IP, domain, URL)
        scope: Scope declaration (e.g., "192.168.1.0/24, example.com")
        max_risk: Maximum risk level (LOW, MEDIUM, HIGH)
        max_duration_minutes: Maximum assessment duration
        output_format: Report format (markdown, json, html)
        authorization_token: Optional authorization token
        available_tools: Set of allowed tools

    Returns:
        Dict with assessment results
    """
    config = AgentConfig(
        max_risk=max_risk,
        max_duration_minutes=max_duration_minutes,
        output_format=output_format,
        authorization_token=authorization_token,
        available_tools=available_tools
    )

    agent = HermesAgent(config)
    return agent.assess(objective, target, scope, config=config)


def quick_scan(target: str, scope: str) -> Dict[str, Any]:
    """Quick reconnaissance scan."""
    return run_assessment(
        objective="Quick network reconnaissance",
        target=target,
        scope=scope,
        max_risk="LOW",
        max_duration_minutes=15,
        output_format="markdown",
        authorization_token="test_token"
    )


def full_assessment(target: str, scope: str, auth_token: str = None) -> Dict[str, Any]:
    """Full security assessment."""
    return run_assessment(
        objective="Full security assessment with vulnerability validation",
        target=target,
        scope=scope,
        max_risk="MEDIUM",
        max_duration_minutes=60,
        output_format="markdown",
        authorization_token=auth_token
    )


# Export main classes
__all__ = [
    "HermesAgent",
    "AgentConfig",
    "run_assessment",
    "quick_scan",
    "full_assessment",
    "Scope",
    "ScopeEnforcer",
    "ScopeViolation",
    "MemoryStore",
    "ExecutionEngine",
    "generate_report",
]