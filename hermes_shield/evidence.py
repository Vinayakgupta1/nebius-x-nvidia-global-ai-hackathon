"""HermesShield Evidence Collection Module.

Collects, formats, and persists audit evidence from tool executions
and model responses. All evidence is stored as structured JSON with
consistent schemas. Redaction rules remove sensitive data before
persistence.

Evidence schema (per item):
{
    "timestamp": "2026-01-01T00:00:00Z",
    "skill": "vulnerability_scan",
    "tool": "nmap",
    "target": "192.168.1.1",
    "command": "nmap -sV -T4 target",
    "exit_code": 0,
    "stdout": "...",
    "stderr": "",
    "status": "completed"
}
"""

import os
import json
import logging
import re
import tempfile
from hermes_shield.__init__ import get_safe_logger

logger = get_safe_logger(__name__)

# Evidence directory name within audit root
EVIDENCE_DIR = "evidence"

# Required fields for every evidence item
REQUIRED_FIELDS = ["timestamp", "skill", "tool", "target", "command", "exit_code", "status"]

# Redaction patterns - sensitive data that must be masked before persistence
REDACTION_PATTERNS = [
    # Passwords and API keys
    (r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]", "****"),
    (r"(?i)(api_key|apikey|apikey)\s*=\s*['\"][^'\"]+['\"]", "****"),
    (r"(?i)(secret[_\s]?key|secretkey)\s*=\s*['\"][^'\"]+['\"]", "****"),
    # Credit card numbers (luhn-like patterns)
    (r"(?:\d[ -]*){13,16}", "****CENSORED****"),
    # Bearer tokens
    (r"(?i)(authorization|auth)\s*:\s*['\"]?Bearer\s+['\"][^'\"]+['\"]", "Bearer ****"),
]


class EvidenceCollector:
    """Collects and persists audit evidence items.

    Responsibilities:
    - Validate evidence items against schema
    - Apply redaction rules to remove sensitive data
    - Persist evidence to JSON files with restricted permissions
    - Load and merge evidence from multiple sources
    - Provide evidence search/filter capabilities
    """

    def __init__(self, audit_root=None):
        """Initialize the evidence collector.

        Args:
            audit_root: Base directory for audit data (defaults to HERMES_AUDIT_ROOT env)
        """
        self.audit_root = audit_root or os.environ.get("HERMES_AUDIT_ROOT", "./audit_data")
        self.evidence_dir = os.path.join(self.audit_root, EVIDENCE_DIR)
        self._items = []
        self._audit_id = None

        # Ensure evidence directory exists
        os.makedirs(self.evidence_dir, exist_ok=True)

        logger.debug(f"EvidenceCollector initialized (audit_root={self.audit_root})")

    def set_audit_id(self, audit_id):
        """Set the audit ID for this evidence collection session.

        Args:
            audit_id: Unique audit identifier
        """
        self._audit_id = audit_id
        logger.debug(f"EvidenceCollector audit_id set to {audit_id}")

    def collect(self, evidence_item):
        """Validate and store an evidence item.

        Applies redaction rules before storage. Ensures all required fields
        are present, filling defaults where missing.

        Args:
            evidence_item: Dict with evidence data

        Returns:
            dict: The validated (and potentially redacted) evidence item
        """
        if not isinstance(evidence_item, dict):
            logger.error("Evidence item must be a dict")
            return None

        # Make a copy to avoid mutating the original
        item = dict(evidence_item)

        # Ensure timestamp exists
        if "timestamp" not in item:
            from datetime import datetime, timezone
            item["timestamp"] = datetime.now(timezone.utc).isoformat()

        # Ensure required fields have sensible defaults
        if "exit_code" not in item:
            item["exit_code"] = -1
        if "status" not in item:
            item["status"] = "unknown"

        # Apply redaction rules to remove sensitive data
        item = self._apply_redactions(item)

        # Validate required fields
        missing = [f for f in REQUIRED_FIELDS if f not in item]
        if missing:
            logger.warning(f"Evidence item missing required fields: {missing}")

        # Store the item
        self._items.append(item)
        logger.debug(f"Evidence collected: skill={item.get('skill', 'unknown')}")

        return item

    def _apply_redactions(self, item):
        """Apply redaction patterns to remove sensitive data from evidence.

        Scans string values in the evidence dict for known sensitive patterns
        (passwords, API keys, credit card numbers, etc.) and masks them.

        Args:
            item: Evidence dict to redact

        Returns:
            dict: Redacted evidence item
        """
        for key, value in item.items():
            if isinstance(value, str):
                for pattern, replacement in REDACTION_PATTERNS:
                    item[key] = re.sub(pattern, replacement, value)
            elif isinstance(value, dict):
                item[key] = self._apply_redactions(value)
            elif isinstance(value, list):
                item[key] = [
                    self._apply_redactions(v) if isinstance(v, dict) else v
                    for v in value
                ]
        return item

    def save(self, filename=None):
        """Persist collected evidence to JSON file(s).

        Evidence is saved with restricted file permissions (chmod 600).
        If no filename is provided, generates a filename based on audit ID.

        Args:
            filename: Optional filename (defaults to audit_id or timestamp)

        Returns:
            list: Paths to saved evidence files
        """
        if not self._items:
            logger.warning("No evidence items to save")
            return []

        saved_paths = []

        # Generate filename
        if filename is None:
            if self._audit_id:
                filename = f"{self._audit_id}_evidence.json"
            else:
                from datetime import datetime, timezone
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                filename = f"evidence_{timestamp}.json"

        filepath = os.path.join(self.evidence_dir, filename)

        # Prepare data - include all collected items
        data = {"audit_id": self._audit_id, "items": self._items, "count": len(self._items)}

        try:
            # Write with restricted permissions
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

            # Set file permissions to 600 (owner read/write only)
            os.chmod(filepath, 0o600)

            saved_paths.append(filepath)
            logger.info(f"Evidence saved to {filepath} ({len(self._items)} items, chmod 600)")

        except Exception as e:
            logger.error(f"Failed to save evidence to {filepath}: {e}")
            raise

        return saved_paths

    def get_items(self):
        """Return all collected evidence items.

        Returns:
            list: List of evidence dicts
        """
        return self._items

    def get_count(self):
        """Return the number of collected evidence items.

        Returns:
            int: Count of evidence items
        """
        return len(self._items)

    def filter_by_skill(self, skill_name):
        """Filter evidence items by skill name.

        Args:
            skill_name: Name of the skill to filter by

        Returns:
            list: Evidence items matching the skill
        """
        return [item for item in self._items if item.get("skill") == skill_name]

    def filter_by_tool(self, tool_name):
        """Filter evidence items by tool name.

        Args:
            tool_name: Name of the tool to filter by

        Returns:
            list: Evidence items matching the tool
        """
        return [item for item in self._items if item.get("tool") == tool_name]

    def __len__(self):
        return len(self._items)


def verify_evidence_redaction():
    """Test that evidence redaction works correctly.

    Returns:
        dict: PASS/FAIL result with details
    """
    from hermes_shield.evidence import EvidenceCollector

    result = {"status": "FAIL", "details": {}}

    try:
        import tempfile
        from hermes_shield.config import AgentConfig

        # Create collector with a temp audit root
        with tempfile.TemporaryDirectory() as tmpdir:
            collector = EvidenceCollector(audit_root=tmpdir)

            # Set audit ID
            collector.set_audit_id("test_redaction_audit")

            # Collect evidence with sensitive data
            test_evidence = {
                "skill": "test_skill",
                "tool": "test_tool",
                "target": "test_target",
                "command": "echo 'password=mysecret123 api_key=abc123'",
                "exit_code": 0,
                "stdout": "password=mysecret123 api_key=abc123 some_output_data",
                "stderr": "",
                "status": "completed",
                "timestamp": "2026-01-01T00:00:00Z",
            }

            collector.collect(test_evidence)
            saved = collector.save()

            # Read back and check redaction
            if saved:
                with open(saved[0], "r") as f:
                    content = f.read()

                # Check that sensitive data was redacted
                has_password = "mysecret123" in content
                has_api_key = "abc123" in content

                if not has_password and not has_api_key:
                    result["status"] = "PASS"
                    result["details"]["message"] = "Sensitive data properly redacted"
                else:
                    result["details"]["message"] = "Sensitive data NOT redacted - found in persistence"
                    result["details"]["found_password"] = "mysecret123" in content
                    result["details"]["found_api_key"] = "abc123" in content

        logger.info(f"Evidence redaction verification: {result['status']}")

    except Exception as e:
        result["details"]["error"] = str(e)
        logger.error(f"Evidence redaction verification error: {e}")

    return result


if __name__ == "__main__":
    # Simple CLI test
    import json
    import sys

    # Create collector and test
    collector = EvidenceCollector()

    # Add a test evidence item
    item = {
        "skill": "test_skill",
        "tool": "test_tool",
        "target": "127.0.0.1",
        "command": "echo hello",
        "exit_code": 0,
        "stdout": "hello world",
        "stderr": "",
        "status": "completed",
        "timestamp": "2026-01-01T00:00:00Z",
    }

    collector.collect(item)
    paths = collector.save("test_evidence.json")

    # Read back and print
    if paths:
        with open(paths[0]) as f:
            data = json.load(f)
        print(json.dumps(data, indent=2))