"""HermesShield Report Generator.

Generates comprehensive security assessment reports from memory and execution data.
"""

import json
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

from hermes_shield.memory import MemoryStore


class ReportFormat(Enum):
    """Report output formats."""
    MARKDOWN = "markdown"
    JSON = "json"
    HTML = "html"
    PDF = "pdf"  # Future


@dataclass
class ReportSection:
    """A section in the report."""
    title: str
    content: str
    level: int = 1  # Header level (1-3)
    findings: List[Dict] = field(default_factory=list)


@dataclass
class Finding:
    """Structured finding for report."""
    finding_id: str
    title: str
    affected_asset: str
    vulnerability_category: str
    evidence: List[str]
    validation_result: str  # "CONFIRMED", "FALSE_POSITIVE", "UNVALIDATED"
    impact: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: float
    remediation: str
    timestamps: Dict[str, str]
    tools_used: List[str]
    skill_used: str
    affected_asset_type: str = "host"


class ReportGenerator:
    """Generates security assessment reports."""

    def __init__(self, memory: Any, context: Any = None):
        self.memory = memory
        self.context = context

    def generate_report(
        self,
        plan_id: str,
        target: str,
        objective: str,
        format: ReportFormat = ReportFormat.MARKDOWN
    ) -> str:
        """Generate full assessment report."""
        if format == ReportFormat.MARKDOWN:
            return self._generate_markdown(plan_id, target, objective)
        elif format == ReportFormat.JSON:
            return self._generate_json(plan_id, target, objective)
        elif format == ReportFormat.HTML:
            return self._generate_html(plan_id, target, objective)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _gather_findings(self, target: str) -> List[Finding]:
        """Gather all findings from memory."""
        findings = []

        # Get validated vulnerabilities
        vulns = self.memory.get_by_category("findings", target)
        for v in vulns:
            if v.state.value in ("VERIFIED", "KNOWN"):
                finding = Finding(
                    finding_id=v.id,
                    title=v.content.get("title", "Unknown"),
                    affected_asset=v.target,
                    vulnerability_category=v.content.get("severity", "UNKNOWN"),
                    evidence=v.evidence_refs,
                    validation_result=v.state.value,
                    impact=v.content.get("severity", "MEDIUM"),
                    confidence=v.confidence,
                    remediation=f"Remediate {v.content.get('title', 'vulnerability')}",
                    timestamps={
                        "created": v.created_at,
                        "updated": v.updated_at
                    },
                    tools_used=v.metadata.get("tools", []),
                    skill_used=v.source_tool
                )
                findings.append(finding)

        # Add false positives
        false_pos = self.memory.get_by_category("false_positives", target)
        for fp in false_pos:
            finding = Finding(
                finding_id=fp.id,
                title=f"FALSE POSITIVE: {fp.content.get('original_finding_id', 'unknown')}",
                affected_asset=fp.target,
                vulnerability_category="FALSE_POSITIVE",
                evidence=[],
                validation_result="FALSE_POSITIVE",
                impact="INFO",
                confidence=1.0,
                remediation=fp.content.get("reason", "Not applicable"),
                timestamps={"created": fp.created_at, "updated": fp.updated_at},
                tools_used=[],
                skill_used=fp.source_tool
            )
            findings.append(finding)

        return findings

    def _generate_markdown(self, plan_id: str, target: str, objective: str) -> str:
        """Generate Markdown report."""
        findings = self._gather_findings(target)
        stats = self.memory.get_stats()

        lines = [
            f"# HermesShield Security Assessment Report",
            f"",
            f"**Plan ID:** {plan_id}",
            f"**Target:** {target}",
            f"**Objective:** {objective}",
            f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
            f"",
            f"## Executive Summary",
            f"",
            f"This report details the security assessment of **{target}** "
            f"conducted under plan **{plan_id}**. "
            f"The objective was: **{objective}**.",
            f"",
            f"### Assessment Statistics",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Memory Entries | {stats.get('total_entries', 0)} |",
            f"| Verified Findings | {stats.get('by_state', {}).get('VERIFIED', 0)} |",
            f"| Known Findings | {stats.get('by_state', {}).get('KNOWN', 0)} |",
            f"| Hypotheses | {stats.get('by_state', {}).get('HYPOTHESIS', 0)} |",
            f"| Rejected (False Positives) | {stats.get('by_state', {}).get('REJECTED', 0)} |",
            f"| Outdated (Need Revalidation) | {stats.get('by_state', {}).get('OUTDATED', 0)} |",
            f"",
            f"### Findings Summary",
            f"",
        ]

        if not lines[-1].startswith("### Findings"):
            # Add findings
            findings = self._gather_findings(target)
            if findings:
                lines.append(f"| Finding ID | Title | Asset | Category | Impact | Confidence | Validation |")
                lines.append(f"|------------|-------|-------|----------|--------|------------|------------|")
                for f in findings:
                    lines.append(
                        f"| {f.finding_id[:8]}... | {f.title} | {f.affected_asset} | "
                        f"{f.vulnerability_category} | {f.impact} | {f.confidence:.0%} | {f.validation_result} |"
                    )
            else:
                lines.append(f"No verified findings.")

            lines.extend([
                f"",
                f"## Detailed Findings",
                f"",
            ])

            for f in findings:
                lines.extend([
                    f"### {f.finding_id}: {f.title}",
                    f"",
                    f"**Asset:** {f.affected_asset}  ",
                    f"**Category:** {f.vulnerability_category}  ",
                    f"**Impact:** {f.impact}  ",
                    f"**Confidence:** {f.confidence:.0%}  ",
                    f"**Validation:** {f.validation_result}  ",
                    f"**Skill:** {f.skill_used}  ",
                    f"**Tools:** {', '.join(f.tools_used) if f.tools_used else 'N/A'}  ",
                    f"**Created:** {f.timestamps.get('created', 'N/A')}  ",
                    f"**Updated:** {f.timestamps.get('updated', 'N/A')}  ",
                    f"",
                    f"**Description:** {f.title}",
                    f"",
                    f"**Evidence:**",
                    f"",
                ])
                for ev in f.evidence:
                    lines.append(f"- {ev}")
                lines.extend([
                    f"",
                    f"**Remediation:** {f.remediation}",
                    f"",
                    f"---",
                    f"",
                ])

            # Add attack paths
            # Get attack paths from memory
            attack_paths = []
            for entry in self.memory.get_by_category("attack_paths", target):
                attack_paths.append(entry.content)

            if attack_paths:
                lines.extend([
                    f"## Attack Paths",
                    f"",
                ])
                for i, path in enumerate(attack_paths):
                    lines.extend([
                        f"### Attack Path {i+1}: {path.get('title', 'Untitled')}",
                        f"",
                        f"**Description:** {path.get('description', 'N/A')}",
                        f"**Chained Findings:** {', '.join(path.get('chained_findings', []))}",
                        f"**Risk:** {path.get('risk', 'UNKNOWN')}",
                        f"",
                        f"---",
                        f"",
                    ])

            # Add remediation
            remediation = []
            for entry in self.memory.get_by_category("remediation_state", target):
                remediation.append(entry.content)

            if remediation:
                lines.extend([
                    f"## Remediation Plan",
                    f"",
                    f"| Finding ID | Status | Priority | Recommendation |",
                    f"|------------|--------|----------|----------------|",
                ])
                for r in remediation:
                    lines.append(
                        f"| {r.get('finding_id', 'N/A')} | {r.get('status', 'open')} | "
                        f"{r.get('priority', 'MEDIUM')} | {r.get('recommendation', 'N/A')} |"
                    )
                lines.append(f"")

            # Add evidence
            lines.extend([
                f"## Evidence Index",
                f"",
            ])
            for entry in self.memory.get_by_category("evidence_collection", target):
                lines.append(f"- {entry.id}: {entry.content.get('action', 'unknown')}")

            lines.extend([
                f"",
                f"## Assessment History",
                f"",
            ])
            for entry in self.memory.get_by_category("assessment_history", target):
                content = entry.content
                lines.append(f"- **{content.get('timestamp', 'N/A')}**: {content.get('action', 'unknown')} - {content.get('details', {})}")

            lines.extend([
                f"",
                f"---",
                f"",
                f"*Report generated by HermesShield Autonomous Security Auditor*",
                f"*Generated: {datetime.now(timezone.utc).isoformat()}*",
            ])

        return "\n".join(lines)

    def _generate_json(self, plan_id: str, target: str, objective: str) -> str:
        """Generate JSON report."""
        findings = self._gather_findings(target)
        stats = self.memory.get_stats()

        report = {
            "metadata": {
                "plan_id": plan_id,
                "target": target,
                "objective": "objective",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "generator": "HermesShield"
            },
            "statistics": stats,
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "affected_asset": f.affected_asset,
                    "vulnerability_category": f.vulnerability_category,
                    "evidence": f.evidence,
                    "validation_result": f.validation_result,
                    "impact": f.impact,
                    "confidence": f.confidence,
                    "remediation": f.remediation,
                    "timestamps": f.timestamps,
                    "tools_used": f.tools_used,
                    "skill_used": f.skill_used
                }
                for f in self._gather_findings(target)
            ],
            "statistics": stats
        }
        return json.dumps(report, indent=2)

    def _generate_html(self, plan_id: str, target: str, objective: str) -> str:
        """Generate HTML report."""
        md = self._generate_markdown(plan_id, target, objective)
        # Simple markdown to HTML conversion
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>HermesShield Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        h1, h2, h3 {{ color: #333; }}
        code {{ background: #f4f4f4; padding: 2px 4px; }}
        pre {{ background: #f4f4f4; padding: 10px; overflow-x: auto; }}
    </style>
</head>
<body>
{md.replace('\n', '<br>')}
</body>
</html>"""
        return html


def generate_report(
    memory: Any,
    plan_id: str,
    target: str,
    objective: str,
    format: str = "markdown"
) -> str:
    """Convenience function to generate report."""
    generator = ReportGenerator(memory)
    format_enum = ReportFormat(format.lower())
    return generator.generate_report(plan_id, target, objective, format_enum)