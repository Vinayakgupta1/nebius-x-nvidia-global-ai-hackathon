"""HermesShield Configuration Auditing Tool.

Audits configuration files and settings for common security misconfigurations.
Checks for default credentials, insecure settings, and exposed sensitive data.

Security controls:
- Read-only access to configuration files within sandbox
- No write access to any configuration files
- Pattern-based scanning for known misconfigurations
- Output sanitization (no host secrets leaked)
- Timeout enforcement
- Target limited to audit_data directory scope
"""

from hermes_shield.tools import InputValidationError,  BaseTool, ToolResult, tool_registry

TOOL_NAME = "configuration_auditing"
PURPOSE = "Audit configuration files for security misconfigurations"
RISK_CLASSIFICATION = "LOW"

INPUT_SCHEMA = {
    "type": "object",
    "required": ["target", "config_path"],
    "properties": {
        "target": {"type": "string", "description": "Target system identifier"},
        "config_path": {
            "type": "string",
            "description": "Path to configuration file relative to audit root",
        },
        "check_default_credentials": {
            "type": "boolean",
            "description": "Whether to check for default credentials",
            "default": True,
        },
        "check_sensitive_exposure": {
            "type": "boolean",
            "description": "Whether to check for sensitive data exposure",
            "default": True,
        },
    },
}

OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["target", "config_path", "findings"],
    "properties": {
        "target": {"type": "string"},
        "config_path": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "category": {"type": "string"},
                    "severity": {"type": "string", "enum": ["info", "low", "medium", "high"]},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "affected_setting": {"type": "string"},
                    "recommendation": {"type": "string"},
                },
            },
        },
    },
}

PERMISSIONS = {"filesystem": "read_only", "network": "none"}
TIMEOUT = 30
EVIDENCE_ITEMS = ["audit_findings"]


class ConfigurationAuditingTool(BaseTool):
    """Configuration auditing tool for security misconfigurations."""

    TOOL_NAME = TOOL_NAME
    PURPOSE = PURPOSE
    RISK_CLASSIFICATION = RISK_CLASSIFICATION
    INPUT_SCHEMA = INPUT_SCHEMA
    OUTPUT_SCHEMA = OUTPUT_SCHEMA
    PERMISSIONS = PERMISSIONS
    TIMEOUT = TIMEOUT
    EVIDENCE_ITEMS = EVIDENCE_ITEMS

    def get_target(self, input_data: Dict[str, Any]) -> str:
        """Extract target from input data."""
        return input_data.get("target", "unknown")

    def validate_input(self, input_data: Dict[str, Any]) -> bool:
        """Validate input against INPUT_SCHEMA."""
        self._validate_input_schema(input_data)
        if not input_data.get("target"):
            raise InputValidationError("Target is required")
        if not input_data.get("config_path"):
            raise InputValidationError("Config path is required")
        # Security: config_path must be within allowed scope
        config_path = input_data["config_path"]
        if config_path.startswith("/") or ".." in config_path:
            raise InputValidationError(
                "Config path must be relative and within sandbox scope"
            )
        return True

    def _read_config_file(self, config_path: str) -> Optional[str]:
        """Read a configuration file within the sandbox.

        Only reads files within the audit_data sandbox directory.

        Args:
            config_path: Relative path to configuration file

        Returns:
            File contents or None if not found
        """
        audit_root = os.environ.get("HERMES_AUDIT_ROOT", "./audit_data")
        full_path = os.path.join(audit_root, config_path)

        # Security: ensure path is within audit root
        if not os.path.abspath(full_path).startswith(
            os.path.abspath(audit_root)
        ):
            logger.error(f"Path traversal attempt: {config_path}")
            raise InputValidationError("Config path outside sandbox scope")

        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except FileNotFoundError:
            logger.warning(f"Config file not found: {full_path}")
            return None
        except Exception as e:
            logger.error(f"Error reading config file: {e}")
            return None

    def _check_default_credentials(self, content: str, setting: str) -> list:
        """Check for default/common credentials in configuration.

        Args:
            content: Configuration file content
            setting: The setting being checked

        Returns:
            List of finding dicts
        """
        findings = []

        # Common default credential patterns
        default_cred_patterns = [
            (r"(?i)(admin|root).*(password|pass|credential).*=.*['\"][^'\"]+['\"]",
             "Default admin credentials detected"),
            (r"(?i)default.*=.*['\"]admin['\"]", "Default admin username detected"),
            (r"(?i)default.*=.*['\"]password['\"]", "Default password detected"),
        ]

        for pattern, description in default_cred_patterns:
            if re.search(pattern, content):
                findings.append(
                    {
                        "category": "credentials",
                        "severity": "medium",
                        "title": f"Default {description}",
                        "description": f"Potential default {setting} found in configuration",
                        "affected_setting": setting,
                        "recommendation": "Replace default credentials with strong, unique passwords",
                    }
                )

        return findings

    def _check_sensitive_exposure(self, content: str, setting: str) -> list:
        """Check for sensitive data exposure in configuration.

        Args:
            content: Configuration file content
            setting: The setting being checked

        Returns:
            List of finding dicts
        """
        findings = []

        # Sensitive data patterns
        sensitive_patterns = [
            (r"(?i)(api_key|apikey|secret).*(=).*['\"][^'\"]{8,}['\"]",
             "API key or secret exposure"),
            (r"(?i)(password|passwd|pwd).*(=).*['\"][^'\"]{4,}['\"]",
             "Password exposure in configuration"),
            (r"(?i)token.*=.*['\"][^'\"]{16,}['\"]",
             "Long-lived token exposure"),
        ]

        for pattern, description in sensitive_patterns:
            if re.search(pattern, content):
                findings.append(
                    {
                        "category": "secrets",
                        "severity": "high",
                        "title": f"Sensitive {description}",
                        "description": f"Sensitive data ({setting}) found in configuration",
                        "affected_setting": setting,
                        "recommendation": "Remove sensitive data from configuration; use environment variables",
                    }
                )

        return findings

    def execute(self, input_data: Dict[str, Any]) -> ToolResult:
        """Execute configuration auditing.

        Args:
            input_data: Validated input with target, config_path, and check options

        Returns:
            ToolResult with audit findings
        """
        start_time = time.time()
        target = self.get_target(input_data)

        try:
            # Read configuration file
            config_path = input_data.get("config_path", "")
            check_creds = input_data.get("check_default_credentials", True)
            check_exposure = input_data.get("check_sensitive_exposure", True)

            config_content = self._read_config_file(config_path)

            all_findings = []

            # Check for default credentials
            if config_content and check_creds:
                cred_findings = self._check_default_credentials(
                    config_content, config_path
                )
                all_findings.extend(cred_findings)

            # Check for sensitive data exposure
            if config_content and check_exposure:
                exposure_findings = self._check_sensitive_exposure(
                    config_content, config_path
                )
                all_findings.extend(exposure_findings)

            execution_time = time.time() - start_time

            # Build result
            result = ToolResult(
                success=True,
                tool_name=self.TOOL_NAME,
                execution_time=execution_time,
                stdout=f"Audited {config_path} on {target}: {len(all_findings)} findings",
                stderr="",
                exit_code=0,
            )

            # Populate evidence
            result.evidence = {
                "target": target,
                "config_path": config_path,
                "findings_count": len(all_findings),
                "findings": all_findings,
                "config_audited": config_path,
            }

            # Build stdout summary
            summary = f"Configuration audit of {config_path}\n"
            summary += f"Target: {target}\n"
            summary += f"Findings: {len(all_findings)}\n\n"

            if all_findings:
                summary += "Findings:\n"
                for i, finding in enumerate(all_findings, 1):
                    severity_color = {
                        "high": "RED",
                        "medium": "YELLOW",
                        "info": "BLUE",
                        "low": "GREEN",
                    }.get(finding.get("severity", "info"), "INFO")
                    summary += f"  {i}. [{severity_color}] {finding.get('title', 'Unnamed')}\n"
                    summary += f"     {finding.get('description', '')}\n"
            else:
                summary += "No security misconfigurations detected.\n"

            result.stdout = summary

            # Log audit
            self._log_audit(
                "configuration_auditing",
                {
                    "target": target,
                    "config_path": config_path,
                    "findings_count": len(all_findings),
                    "check_default_credentials": check_creds,
                    "check_sensitive_exposure": check_exposure,
                    "execution_time": execution_time,
                },
            )

            return result

        except InputValidationError as e:
            logger.error(f"Input validation error: {e}")
            return ToolResult(
                success=False,
                tool_name=self.TOOL_NAME,
                execution_time=time.time() - start_time,
                error=str(e),
                exit_code=-1,
            )
        except TimeoutError as e:
            logger.error(f"Tool timeout: {e}")
            return ToolResult(
                success=False,
                tool_name=self.TOOL_NAME,
                execution_time=self.TIMEOUT,
                error=str(e),
                exit_code=-1,
            )
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return ToolResult(
                success=False,
                tool_name=self.TOOL_NAME,
                execution_time=time.time() - start_time,
                error=f"Unexpected error: {e}",
                exit_code=-1,
            )


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python config_audit.py <target> <config_path>")
        sys.exit(1)

    target = sys.argv[1]
    config_path = sys.argv[2]
    tool_instance = tool_registry.create_instance("configuration_auditing")

    print(f"Configuration Auditing Tool")
    print(f"Target: {target}")
    print(f"Config path: {config_path}")


# Register the tool
tool_registry.register(ConfigurationAuditingTool)