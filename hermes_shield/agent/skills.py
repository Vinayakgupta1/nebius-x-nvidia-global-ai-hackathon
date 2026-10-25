"""HermesShield Skills Registry.

Maps security assessment skills to available tools and defines preconditions/postconditions.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
from enum import Enum
from hermes_shield.tools import tool_registry
from hermes_shield.memory import MemoryState, MemoryCategory


class SkillCategory(Enum):
    """Categories of security skills."""
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    VALIDATION = "validation"
    EXPLOITATION = "exploitation"  # Safe validation only
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


class SkillRisk(Enum):
    """Risk level of skill execution."""
    LOW = "LOW"      # Passive info gathering
    MEDIUM = "MEDIUM"  # Active scanning, limited interaction
    HIGH = "HIGH"    # Active exploitation, potential service disruption


@dataclass
class Skill:
    """A security assessment skill with preconditions and tool mappings."""
    name: str
    description: str
    category: SkillCategory
    risk: SkillRisk
    required_tools: List[str] = field(default_factory=list)
    optional_tools: List[str] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)
    produces_categories: List[str] = field(default_factory=list)
    consumes_categories: List[str] = field(default_factory=list)
    max_duration_seconds: int = 300
    risk_mitigation: str = ""
    requires_authorization: bool = False

    def can_execute(self, available_tools: Set[str], context: Dict[str, Any]) -> bool:
        """Check if skill can be executed with current tools and context."""
        # Check required tools available
        for tool in self.required_tools:
            if tool not in available_tools:
                return False
        # Check preconditions
        for precond in self.preconditions:
            if not self._check_precondition(precond, context):
                return False
        return True

    def _check_precondition(self, precond: str, context: Dict[str, Any]) -> bool:
        """Check a single precondition."""
        # Simple precondition checks
        if precond == "target_identified":
            return context.get("target") is not None
        elif precond == "ports_discovered":
            return len(context.get("open_ports", [])) > 0
        elif precond == "web_services_found":
            return any(p in [80, 443, 8080, 8443] for p in context.get("open_ports", []))
        elif precond == "services_enumerated":
            return len(context.get("services", [])) > 0
        elif precond == "vulnerabilities_found":
            return len(context.get("vulnerabilities", [])) > 0
        elif precond == "attack_path_hypothesis":
            return len(context.get("hypotheses", [])) > 0
        return True  # Unknown preconditions default to True


# Define all available skills
SKILLS_REGISTRY = {
    # Reconnaissance
    "network_reconnaissance": Skill(
        name="network_reconnaissance",
        description="Discover live hosts, open ports, and network topology",
        category=SkillCategory.RECONNAISSANCE,
        risk=SkillRisk.LOW,
        required_tools=["network_reconnaissance"],
        preconditions=["target_identified"],
        postconditions=["ports_discovered", "hosts_identified"],
        produces_categories=["open_ports", "hosts", "network_topology"],
        max_duration_seconds=120,
        risk_mitigation="Rate-limited scanning, no aggressive timing",
    ),

    "http_reconnaissance": Skill(
        name="http_reconnaissance",
        description="Discover web technologies, directories, and endpoints",
        category=SkillCategory.RECONNAISSANCE,
        risk=SkillRisk.LOW,
        required_tools=["http_reconnaissance"],
        preconditions=["web_services_found"],
        postconditions=["technologies_identified", "directories_discovered"],
        produces_categories=["technologies", "directories", "endpoints"],
        max_duration_seconds=180,
        risk_mitigation="Respects robots.txt, rate-limited requests",
    ),

    "service_enumeration": Skill(
        name="service_enumeration",
        description="Enumerate service versions and configurations",
        category=SkillCategory.ENUMERATION,
        risk=SkillRisk.MEDIUM,
        required_tools=["service_enumeration"],
        preconditions=["ports_discovered"],
        postconditions=["services_enumerated", "versions_identified"],
        produces_categories=["services", "versions", "banners"],
        max_duration_seconds=300,
        risk_mitigation="Version detection only, no aggressive probing",
    ),

    "configuration_auditing": Skill(
        name="configuration_auditing",
        description="Audit configuration files for security misconfigurations",
        category=SkillCategory.VULNERABILITY_ASSESSMENT,
        risk=SkillRisk.LOW,
        required_tools=["configuration_auditing"],
        preconditions=["files_accessible"],
        postconditions=["config_issues_identified"],
        produces_categories=["config_issues", "misconfigurations"],
        max_duration_seconds=120,
        risk_mitigation="Read-only configuration review",
    ),

    "secret_detection": Skill(
        name="secret_detection",
        description="Detect exposed secrets, credentials, and sensitive data",
        category=SkillCategory.VULNERABILITY_ASSESSMENT,
        risk=SkillRisk.LOW,
        required_tools=["secret_detection"],
        preconditions=["files_accessible"],
        postconditions=["secrets_identified"],
        produces_categories=["secrets", "credentials"],
        max_duration_seconds=120,
        risk_mitigation="Detection only, no credential extraction",
    ),

    # Vulnerability Assessment
    "vulnerability_validation": Skill(
        name="vulnerability_validation",
        description="Safe validation of identified vulnerabilities (no exploitation)",
        category=SkillCategory.VULNERABILITY_ASSESSMENT,
        risk=SkillRisk.MEDIUM,
        required_tools=["vulnerability_validation"],
        preconditions=["vulnerabilities_found"],
        postconditions=["vulnerabilities_validated"],
        produces_categories=["validated_vulnerabilities", "poc_evidence"],
        max_duration_seconds=300,
        risk_mitigation="Safe validation only - no exploitation, no payload delivery",
        requires_authorization=True,
    ),

    "secret_detection_advanced": Skill(
        name="secret_detection_advanced",
        description="Advanced secret detection with entropy analysis",
        category=SkillCategory.VULNERABILITY_ASSESSMENT,
        risk=SkillRisk.LOW,
        required_tools=["secret_detection"],
        preconditions=["files_accessible"],
        postconditions=["high_entropy_secrets_found"],
        produces_categories=["high_entropy_secrets"],
        max_duration_seconds=180,
        risk_mitigation="Read-only entropy analysis, no extraction",
    ),

    # Validation
    "vulnerability_validation": Skill(
        name="vulnerability_validation",
        description="Validate suspected vulnerabilities with safe checks",
        category=SkillCategory.VALIDATION,
        risk=SkillRisk.MEDIUM,
        required_tools=["vulnerability_validation"],
        preconditions=["vulnerabilities_found"],
        postconditions=["vulnerabilities_confirmed", "false_positives_identified"],
        produces_categories=["validated_vulnerabilities", "false_positives"],
        max_duration_seconds=300,
        risk_mitigation="Safe verification only - no exploitation",
        requires_authorization=True,
    ),

    "attack_path_validation": Skill(
        name="attack_path_validation",
        description="Validate hypothesized attack paths with safe checks",
        category=SkillCategory.VALIDATION,
        risk=SkillRisk.MEDIUM,
        required_tools=["vulnerability_validation"],
        preconditions=["attack_path_hypothesis"],
        postconditions=["attack_paths_validated"],
        produces_categories=["validated_attack_paths"],
        max_duration_seconds=300,
        risk_mitigation="Safe chaining validation only",
    ),

    # Post-Exploitation (Safe)
    "impact_assessment": Skill(
        name="impact_assessment",
        description="Assess potential impact of validated vulnerabilities",
        category=SkillCategory.POST_EXPLOITATION,
        risk=SkillRisk.LOW,
        required_tools=[],
        preconditions=["vulnerabilities_validated"],
        postconditions=["impact_assessed"],
        produces_categories=["impact_assessment", "risk_rating"],
        consumes_categories=["validated_vulnerabilities"],
        max_duration_seconds=60,
        risk_mitigation="Analysis only, no system interaction",
    ),

    "attack_path_building": Skill(
        name="attack_path_building",
        description="Build and validate attack chains from findings",
        category=SkillCategory.POST_EXPLOITATION,
        risk=SkillRisk.MEDIUM,
        required_tools=["vulnerability_validation"],
        preconditions=["vulnerabilities_validated"],
        postconditions=["attack_paths_built"],
        produces_categories=["attack_paths"],
        consumes_categories=["validated_vulnerabilities"],
        max_duration_seconds=180,
        risk_mitigation="Safe chaining analysis only",
    ),

    # Reporting
    "evidence_collection": Skill(
        name="evidence_collection",
        description="Collect, correlate, and structure evidence",
        category=SkillCategory.REPORTING,
        risk=SkillRisk.LOW,
        required_tools=["evidence_collection"],
        preconditions=[],
        postconditions=["evidence_collected", "evidence_correlated"],
        produces_categories=["evidence_collection"],
        max_duration_seconds=60,
        risk_mitigation="Data aggregation only",
    ),

    "report_generation": Skill(
        name="report_generation",
        description="Generate comprehensive security assessment report",
        category=SkillCategory.REPORTING,
        risk=SkillRisk.LOW,
        required_tools=[],
        preconditions=["evidence_collected"],
        postconditions=["report_generated"],
        produces_categories=["final_report"],
        consumes_categories=["evidence_collection"],
        max_duration_seconds=60,
        risk_mitigation="Document generation only",
    ),

    "remediation_planning": Skill(
        name="remediation_planning",
        description="Generate prioritized remediation recommendations",
        category=SkillCategory.REPORTING,
        risk=SkillRisk.LOW,
        required_tools=[],
        preconditions=["vulnerabilities_validated"],
        postconditions=["remediation_plan_generated"],
        produces_categories=["remediation_plan"],
        consumes_categories=["validated_vulnerabilities"],
        max_duration_seconds=60,
        risk_mitigation="Advisory generation only",
    ),
}


class SkillsRegistry:
    """Registry for managing and selecting skills."""

    def __init__(self):
        self.skills = SKILLS_REGISTRY.copy()
        self._available_tools = set()

    def set_available_tools(self, tools: Set[str]):
        """Update available tools."""
        self._available_tools = tools

    def get_skill(self, name: str) -> Optional[Skill]:
        """Get skill by name."""
        return self.skills.get(name)

    def get_all_skills(self) -> Dict[str, Skill]:
        """Get all registered skills."""
        return self.skills.copy()

    def get_available_skills(self, context: Dict[str, Any]) -> List[Skill]:
        """Get skills that can be executed with current context."""
        available = []
        for skill in self.skills.values():
            if skill.can_execute(self._available_tools, context):
                available.append(skill)
        return available

    def get_skills_by_category(self, category: str) -> List[Skill]:
        """Get skills filtered by category."""
        return [
            s for s in self.skills.values()
            if s.category.value == category
        ]

    def get_skills_by_risk(self, risk: str) -> List[Skill]:
        """Get skills filtered by risk level."""
        return [
            s for s in self.skills.values()
            if s.risk.value == risk
        ]

    def get_executable_skills(self, context: Dict[str, Any], max_risk: str = "MEDIUM") -> List[Skill]:
        """Get skills that can be executed given context and risk tolerance."""
        risk_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
        max_risk_level = risk_order.get(max_risk, 1)

        executable = []
        for skill in self.skills.values():
            if skill.can_execute(self._available_tools, context):
                skill_risk_level = risk_order.get(skill.risk.value, 1)
                if skill_risk_level <= max_risk_level:
                    executable.append(skill)
        return executable


# Global instance
skills_registry = SkillsRegistry()


def initialize_skills_registry(available_tools: Set[str]):
    """Initialize skills registry with available tools."""
    skills_registry.set_available_tools(available_tools)
    return skills_registry