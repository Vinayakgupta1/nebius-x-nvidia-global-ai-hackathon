"""Tests for HermesShield Agent."""

import pytest
import tempfile
import json
from unittest.mock import Mock, patch

from hermes_shield.agent import (
    HermesAgent,
    AgentConfig,
    run_assessment,
    quick_scan,
    full_assessment,
)
from hermes_shield.agent.scope import Scope, ScopeEnforcer, ScopeViolation, parse_scope_declaration
from hermes_shield.agent.planner import AssessmentPlanner, PlanType, PlanStep, PlanStepStatus
from hermes_shield.agent.engine import ExecutionEngine, StepExecution, ExecutionResult, ExecutionContext
from hermes_shield.agent.skills import Skill, SkillCategory, SkillRisk, SkillsRegistry, skills_registry
from hermes_shield.agent.reporting import generate_report, ReportFormat
from hermes_shield.memory import MemoryStore, MemoryState, MemoryCategory


class TestScope:
    """Tests for scope enforcement."""

    def test_parse_scope_ip(self):
        """Test parsing IP range scope."""
        scope = parse_scope_declaration("192.168.1.0/24")
        assert scope.target == "192.168.1.0/24"
        assert len(scope.rules) == 1
        assert scope.rules[0].scope_type.value == "cidr"

    def test_parse_scope_domain(self):
        """Test parsing domain scope."""
        scope = parse_scope_declaration("example.com")
        assert scope.target == "example.com"
        assert scope.rules[0].scope_type.value == "domain"

    def test_parse_scope_multiple(self):
        """Test parsing multiple targets."""
        scope = parse_scope_declaration("192.168.1.0/24, example.com")
        assert len(scope.rules) == 2

    def test_scope_enforcer_allows_in_scope(self):
        """Test scope enforcer allows in-scope targets."""
        scope = Scope(target="192.168.1.0/24")
        enforcer = ScopeEnforcer(scope)
        assert enforcer.check_target("192.168.1.100")
        assert enforcer.enforce_target("192.168.1.50") is True

    def test_scope_enforcer_blocks_out_of_scope(self):
        """Test scope enforcer blocks out-of-scope targets."""
        scope = Scope(target="192.168.1.0/24")
        enforcer = ScopeEnforcer(scope)
        assert not enforcer.check_target("10.0.0.1")
        with pytest.raises(ScopeViolation):
            enforcer.enforce_target("10.0.0.1")

    def test_scope_action_enforcement(self):
        """Test action enforcement."""
        scope = Scope(target="192.168.1.0/24", denied_actions=["exploit", "bruteforce"])
        enforcer = ScopeEnforcer(scope)
        assert enforcer.check_action("scan")
        assert not enforcer.check_action("exploit")
        with pytest.raises(ScopeViolation):
            enforcer.enforce_action("exploit")


class TestPlanner:
    """Tests for assessment planner."""

    def test_build_plan(self):
        """Test building a basic plan."""
        planner = AssessmentPlanner()
        plan = planner.build_plan(
            objective="Full assessment",
            target="192.168.1.100",
            scope="192.168.1.0/24"
        )
        assert plan.target == "192.168.1.100"
        assert len(plan.steps) > 0
        assert plan.plan_id.startswith("plan_")

    def test_plan_step_dependencies(self):
        """Test plan step dependencies are correct."""
        planner = AssessmentPlanner()
        plan = planner.build_plan(
            objective="Web app assessment",
            target="192.168.1.100",
            scope="192.168.1.0/24"
        )

        # Check dependencies are respected
        for step in plan.steps:
            for dep in step.depends_on:
                dep_step = plan.get_step(dep)
                assert dep_step is not None

    def test_plan_completion(self):
        """Test plan completion detection."""
        planner = AssessmentPlanner()
        plan = planner.build_plan("Test", "192.168.1.1", "192.168.1.0/24")
        assert not plan.is_complete()

        # Complete all steps
        for step in plan.steps:
            step.status = PlanStepStatus.COMPLETED
        assert plan.is_complete()


class TestExecutionEngine:
    """Tests for execution engine."""

    @pytest.fixture
    def mock_context(self):
        """Create mock execution context."""
        with tempfile.TemporaryDirectory() as tmpdir:
            memory = MemoryStore(target="192.168.1.100", audit_root=tmpdir)
            from hermes_shield.agent.scope import Scope, ScopeEnforcer
            scope = Scope(target="192.168.1.100")
            enforcer = ScopeEnforcer(scope)

            from hermes_shield.agent.planner import AssessmentPlanner
            planner = AssessmentPlanner()
            plan = planner.build_plan("Test", "192.168.1.100", "192.168.1.0/24")

            engine = ExecutionEngine(
                plan=plan,
                scope=scope,
                memory=memory,
                scope_enforcer=enforcer,
                available_tools=set()
            )
            yield engine

    def test_engine_initialization(self, mock_context):
        """Test engine initializes correctly."""
        engine = mock_context
        assert engine.plan is not None
        assert engine.memory is not None
        assert engine.context.target == "192.168.1.100"

    def test_execute_builtin_skill(self, mock_context):
        """Test built-in skill execution."""
        engine = mock_context

        from hermes_shield.agent.skills import Skill, SkillCategory, SkillRisk
        skill = Skill(
            name="impact_assessment",
            description="Test",
            category=SkillCategory.REPORTING,
            risk=SkillRisk.LOW
        )

        result = engine._execute_builtin_skill(skill)
        assert result["success"] is True


class TestSkills:
    """Tests for skills registry."""

    def test_skill_registry_initialization(self):
        """Test skills registry initialization."""
        skills_registry.set_available_tools({"nmap", "nikto"})
        assert "nmap" in skills_registry._available_tools

    def test_skill_preconditions(self):
        """Test skill precondition checking."""
        skill = skills_registry.get_skill("network_reconnaissance")
        assert skill is not None

        # Should pass with target identified
        context = {"target": "192.168.1.100"}
        assert skill.can_execute({"network_reconnaissance"}, context) is True

        # Should fail without target
        context = {}
        assert skill.can_execute({"network_reconnaissance"}, context) is False

    def test_skill_risk_filtering(self):
        """Test skill filtering by risk."""
        skills_registry.set_available_tools(set())
        skills = skills_registry.get_executable_skills(
            {"target": "192.168.1.100"},
            max_risk="LOW"
        )
        # Only LOW risk skills should be returned
        for skill in skills:
            assert skill.risk.value == "LOW"


class TestAgentIntegration:
    """Integration tests for the full agent."""

    @patch('hermes_shield.agent.engine.ExecutionEngine.execute_plan')
    def test_agent_assess(self, mock_execute):
        """Test full agent assessment flow."""
        mock_execute.return_value = {
            "plan_id": "test_plan",
            "target": "192.168.1.100",
            "completed_steps": 5,
            "failed_steps": 0
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            config = AgentConfig(
                max_risk="LOW",
                max_duration_minutes=5,
                available_tools=set(),
                authorization_token="test_token"
            )

            agent = HermesAgent(config)
            result = agent.assess(
                objective="Quick scan",
                target="192.168.1.100",
                scope="192.168.1.0/24"
            )

            assert result["plan_id"] is not None
            assert result["target"] == "192.168.1.100"
            assert "report" in result

    def test_quick_scan(self):
        """Test quick scan function."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = AgentConfig(
                max_risk="LOW",
                max_duration_minutes=1,
                available_tools=set(),
                authorization_token="test"
            )

            agent = HermesAgent(config)
            with patch('hermes_shield.agent.engine.ExecutionEngine.execute_plan') as mock:
                mock.return_value = {"completed_steps": 2, "failed_steps": 0}
                result = quick_scan("192.168.1.100", "192.168.1.0/24")
                assert "execution" in result

    def test_full_assessment(self):
        """Test full assessment function."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = AgentConfig(
                max_risk="MEDIUM",
                available_tools=set(),
                authorization_token="test"
            )

            agent = HermesAgent(config)
            with patch('hermes_shield.agent.engine.ExecutionEngine.execute_plan') as mock:
                mock.return_value = {"completed_steps": 10, "failed_steps": 0}
                result = full_assessment("192.168.1.100", "192.168.1.0/24", auth_token="test")
                assert "execution" in result


class TestReporting:
    """Tests for report generation."""

    def test_generate_markdown_report(self):
        """Test markdown report generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            memory = MemoryStore(target="192.168.1.100", audit_root=tmpdir)
            memory.record_finding(
                title="SQL Injection",
                description="Test",
                severity="HIGH",
                evidence=["ev_1"],
                state=MemoryState.VERIFIED,
                confidence=0.9
            )

            report = generate_report(
                memory=memory,
                plan_id="test_plan",
                target="192.168.1.100",
                objective="Test assessment",
                format="markdown"
            )

            assert "SQL Injection" in report
            assert "192.168.1.100" in report
            assert "HIGH" in report

    def test_generate_json_report(self):
        """Test JSON report generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            memory = MemoryStore(target="192.168.1.100", audit_root=tmpdir)
            memory.record_finding(
                title="Test Finding",
                description="Test",
                severity="MEDIUM",
                evidence=["ev_1"],
                state=MemoryState.VERIFIED
            )

            report = generate_report(
                memory=memory,
                plan_id="test_plan",
                target="192.168.1.100",
                objective="Test",
                format="json"
            )

            data = json.loads(report)
            assert data["metadata"]["target"] == "192.168.1.100"
            assert len(data["findings"]) == 1


class TestEndToEnd:
    """End-to-end integration tests."""

    def test_session_continuity(self):
        """Test memory persists across agent sessions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Session 1
            memory1 = MemoryStore(target="192.168.1.100", audit_root=tmpdir)
            entry_id = memory1.record_finding(
                title="Persistent Finding",
                description="Test",
                severity="HIGH",
                evidence=["ev_1"],
                state=MemoryState.VERIFIED
            )

            # Session 2 - new memory instance
            memory2 = MemoryStore(target="192.168.1.100", audit_root=tmpdir)
            entry = memory2.get_entry(entry_id)
            assert entry is not None
            assert entry.content["title"] == "Persistent Finding"

    def test_scope_isolation(self):
        """Test targets don't share memory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            memory_a = MemoryStore(target="192.168.1.1", audit_root=tmpdir)
            memory_b = MemoryStore(target="192.168.1.2", audit_root=tmpdir)

            memory_a.record_finding("A Finding", "Test", "LOW", [], state=MemoryState.KNOWN)
            memory_b.record_finding("B Finding", "Test", "LOW", [], state=MemoryState.KNOWN)

            a_findings = memory_a.get_known()
            b_findings = memory_b.get_known()

            assert len(a_findings) == 1
            assert len(b_findings) == 1
            assert a_findings[0].content["title"] == "A Finding"
            assert b_findings[0].content["title"] == "B Finding"


class TestSafety:
    """Tests for safety features."""

    def test_scope_violation_stops_execution(self):
        """Test scope violations halt execution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scope = Scope(target="192.168.1.0/24")
            enforcer = ScopeEnforcer(scope)
            memory = MemoryStore(target="192.168.1.100", audit_root=tmpdir)

            from hermes_shield.agent.planner import AssessmentPlanner
            planner = AssessmentPlanner()
            plan = planner.build_plan("Test", "192.168.1.100", "192.168.1.0/24")

            engine = ExecutionEngine(
                plan=plan,
                scope=scope,
                memory=memory,
                scope_enforcer=enforcer,
                available_tools=set()
            )

            # Try to execute step with out-of-scope target
            with pytest.raises(ScopeViolation):
                enforcer.enforce_target("10.0.0.1")

    def test_max_risk_enforcement(self):
        """Test max risk level is enforced."""
        skills_registry.set_available_tools({"nmap", "nikto"})

        planner = AssessmentPlanner()
        plan = planner.build_plan(
            objective="Full assessment with high risk tools",
            target="192.168.1.100",
            scope="192.168.1.0/24",
            max_risk="LOW"
        )

        # High risk steps should be filtered out
        for step in plan.steps:
            skill = skills_registry.get_skill(step.skill_name)
            if skill:
                assert skill.risk.value != "HIGH"

    def test_unauthorized_action_blocked(self):
        """Test unauthorized actions are blocked."""
        scope = Scope(
            target="192.168.1.0/24",
            denied_actions=["exploit", "bruteforce", "dos"]
        )
        enforcer = ScopeEnforcer(scope)

        assert enforcer.check_action("scan")
        assert not enforcer.check_action("exploit")
        assert not enforcer.check_action("bruteforce")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])