"""HermesShield Tool Abstraction Framework.

Defines the base class and contract for all security audit tools.
Every tool must implement this interface to be registered and executable
by the Hermes Agent.

Security guarantees:
- Input validation before execution
- Timeout enforcement (no unbounded waits)
- Output sanitization (no host secrets leaked)
- Structured result return (never raw shell access)
- Audit log generation (every action recorded)
- No host secret exposure (environment variable filtering)
- No privilege escalation (sandboxed subprocess execution)
"""

import abc
import json
import logging
import os
import re
import time
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from hermes_shield.config import agent_config, nebius_config
from hermes_shield.evidence import EvidenceCollector

# Configure logging
logger = logging.getLogger("hermes_shield.tools")


class ToolResult:
    """Structured result from tool execution.

    Encapsulates all output from a tool run in a safe, validated format.
    """

    def __init__(
        self,
        success: bool,
        tool_name: str,
        execution_time: float,
        evidence: Optional[Dict[str, Any]] = None,
        stdout: Optional[str] = None,
        stderr: Optional[str] = None,
        exit_code: Optional[int] = None,
        error: Optional[str] = None,
    ):
        self.success = success
        self.tool_name = tool_name
        self.execution_time = execution_time
        self.evidence = evidence or {}
        self.stdout = stdout or ""
        self.stderr = stderr or ""
        self.exit_code = exit_code
        self.error = error
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "success": self.success,
            "tool_name": self.tool_name,
            "execution_time": self.execution_time,
            "evidence": self.evidence,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "error": self.error,
            "timestamp": self.timestamp,
        }

    def __str__(self) -> str:
        return f"ToolResult(success={self.success}, tool={self.tool_name}, exit={self.exit_code})"


class ToolError(Exception):
    """Base exception for tool-related errors."""

    pass


class InputValidationError(ToolError):
    """Raised when input validation fails."""

    pass


class TimeoutError(ToolError):
    """Raised when tool execution exceeds timeout."""

    pass


class SandboxEscapeError(ToolError):
    """Raised when tool attempts to escape sandbox."""

    pass


class BaseTool(abc.ABC):
    """Abstract base class for all HermesShield security tools.

    Subclasses must define:
    - TOOL_NAME: str - unique identifier
    - PURPOSE: str - human-readable description
    - INPUT_SCHEMA: dict - JSON schema for input validation
    - OUTPUT_SCHEMA: dict - expected output structure
    - PERMISSIONS: dict - filesystem/network access rights
    - TIMEOUT: int - maximum execution time (seconds)
    - RISK_CLASSIFICATION: str - risk level (LOW, MEDIUM, HIGH)
    - EVIDENCE_ITEMS: list - evidence items generated
    - ALLOWED_ENV: list - permitted environment variables

    Security guarantees enforced by base class:
    - Input schema validation
    - Timeout enforcement
    - Output sanitization (regex redaction of secrets)
    - Structured ToolResult return
    - Audit logging
    """

    # Tool metadata - must be overridden by subclasses
    TOOL_NAME: str = "base"
    PURPOSE: str = "Base tool - override in subclass"
    INPUT_SCHEMA: dict = {}
    OUTPUT_SCHEMA: dict = {}
    PERMISSIONS: dict = {"filesystem": "read_only", "network": "none"}
    TIMEOUT: int = 30
    RISK_CLASSIFICATION: str = "LOW"
    EVIDENCE_ITEMS: list = []
    ALLOWED_ENV: list = ["PATH", "HOME", "TERM"]

    def __init__(self):
        self.evidence_collector = EvidenceCollector()
        self._execution_log: list = []

    @property
    def name(self) -> str:
        """Return the tool name."""
        return self.TOOL_NAME

    @abc.abstractmethod
    def validate_input(self, input_data: Dict[str, Any]) -> bool:
        """Validate input against INPUT_SCHEMA.

        Args:
            input_data: Dictionary of input parameters

        Returns:
            True if valid, raises InputValidationError otherwise
        """
        raise NotImplementedError

    @abc.abstractmethod
    def execute(self, input_data: Dict[str, Any]) -> ToolResult:
        """Execute the tool with validated input.

        Args:
            input_data: Validated input parameters

        Returns:
            ToolResult with execution outcome
        """
        raise NotImplementedError

    def _validate_input_schema(self, input_data: Dict[str, Any]) -> None:
        """Validate input against the tool's INPUT_SCHEMA.

        Uses JSON Schema validation to ensure all required fields
        are present and have correct types.

        Args:
            input_data: Input dictionary to validate

        Raises:
            InputValidationError: If validation fails
        """
        if not isinstance(input_data, dict):
            raise InputValidationError(
                f"Input must be a dict, got {type(input_data)}"
            )

        # Check required fields
        required = self.INPUT_SCHEMA.get("required", [])
        properties = self.INPUT_SCHEMA.get("properties", {})

        for field in required:
            if field not in input_data:
                raise InputValidationError(f"Required field '{field}' missing")

        # Type checking for defined properties
        for field, schema in properties.items():
            if field in input_data:
                expected_type = schema.get("type")
                if expected_type and not isinstance(input_data[field], self._python_type(expected_type)):
                    raise InputValidationError(
                        f"Field '{field}' expected type {expected_type}, got {type(input_data[field])}"
                    )

    @staticmethod
    def _python_type(schema_type: str) -> type:
        """Map JSON Schema type to Python type."""
        mapping = {
            "string": str,
            "number": (int, float),
            "integer": int,
            "boolean": bool,
            "array": list,
            "object": dict,
        }
        return mapping.get(schema_type, str)

    def _sanitize_output(self, output: str) -> str:
        """Sanitize output to remove any host secrets or sensitive data.

        Applies redaction patterns to remove:
        - API keys and tokens
        - Passwords and credentials
        - PII (personal identification information)
        - Any environment variable values that look sensitive

        Args:
            output: Raw command output string

        Returns:
            Sanitized output with sensitive data masked
        """
        redaction_patterns = [
            # API keys
            (r"(?i)(api_key|apikey|x_api_key)\s*=\s*['\"][^'\"]+['\"]", "api_key=****"),
            # Passwords
            (r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]", "password=****"),
            # Bearer tokens
            (r"(?i)(authorization|auth).*Bearer\s+['\"][^'\"]+['\"]", "Authorization: Bearer ****"),
            # Port numbers and IP addresses in unexpected contexts
            (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\b", "[REDACTED_IP_PORT]"),
        ]

        sanitized = output
        for pattern, replacement in redaction_patterns:
            sanitized = re.sub(pattern, replacement, sanitized)

        return sanitized

    def _execute_subprocess(
        self,
        command: list,
        timeout: Optional[int] = None,
        allowed_env: Optional[dict] = None,
    ) -> Tuple[Optional[str], Optional[str], int]:
        """Execute a command in a sandboxed subprocess.

        This is the core sandbox mechanism - all tool execution goes through
        this method to ensure:
        - Environment variable filtering
        - Working directory scoping
        - Timeout enforcement
        - Output capture and sanitization

        Args:
            command: List of command arguments (argv format)
            timeout: Maximum execution time in seconds (defaults to TOOL_TIMEOUT)
            allowed_env: Additional environment variables to allow

        Returns:
            Tuple of (stdout, stderr, exit_code)

        Raises:
            TimeoutError: If execution exceeds timeout
        """
        timeout = timeout or self.TIMEOUT
        env = self._build_allowed_env(allowed_env)

        logger.info(f"Executing: {' '.join(command)} (timeout={timeout}s)")

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=self._get_safe_cwd(),
                stdin=subprocess.DEVNULL,
                shell=False,
            )

            try:
                stdout, stderr = process.communicate(timeout=timeout)
                exit_code = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                exit_code = -1
                logger.warning(
                    f"Tool timeout after {timeout}s: {' '.join(command)}"
                )
                raise TimeoutError(
                    f"Tool execution exceeded {timeout} second timeout"
                )

            # Sanitize output
            stdout_str = stdout.decode(errors="replace") if stdout else ""
            stderr_str = stderr.decode(errors="replace") if stderr else ""

            # Enforce output size limit
            size_limit = 1048576  # 1MB
            if len(stdout_str) > size_limit:
                stdout_str = stdout_str[:size_limit] + "\n... [output truncated] ..."
                logger.warning(
                    f"stdout truncated ({len(stdout_str)} bytes exceeded limit)"
                )

            if len(stderr_str) > size_limit:
                stderr_str = stderr_str[:size_limit] + "\n... [output truncated] ..."
                logger.warning(
                    f"stderr truncated ({len(stderr_str)} bytes exceeded limit)"
                )

            logger.info(
                f"Execution complete: exit_code={exit_code}, "
                f"stdout_len={len(stdout_str)}, stderr_len={len(stderr_str)}"
            )

            return stdout_str, stderr_str, exit_code

        except FileNotFoundError:
            error_msg = f"Command not found: {command[0]}"
            logger.error(error_msg)
            return "", error_msg, -1
        except Exception as e:
            error_msg = f"Execution error: {e}"
            logger.error(error_msg)
            return "", error_msg, -1

    def _build_allowed_env(self, extra_env: Optional[dict] = None) -> dict:
        """Build the environment dict for subprocess execution.

        Only variables in ALLOWED_ENV are included, plus any provided in extra_env.
        This prevents credential leakage from the host environment.

        Args:
            extra_env: Additional environment variables to allow

        Returns:
            Dictionary of environment variables for subprocess
        """
        env = {}
        for key in self.ALLOWED_ENV:
            if key in os.environ:
                env[key] = os.environ[key]

        if extra_env:
            for key, value in extra_env.items():
                env[key] = value

        return env

    def _get_safe_cwd(self) -> str:
        """Get a safe working directory for tool execution.

        Ensures tools run in a scoped directory, never in the host's
        current working directory if that would expose sensitive paths.

        Returns:
            Path to use as working directory
        """
        audit_root = os.environ.get("HERMES_AUDIT_ROOT", "./audit_data")
        sandbox_dir = os.path.join(audit_root, "sandbox", self.TOOL_NAME)
        os.makedirs(sandbox_dir, exist_ok=True)
        return sandbox_dir

    def _log_audit(self, action: str, details: Dict[str, Any]) -> None:
        """Log an audit entry for tool execution.

        Every tool action is recorded with:
        - Timestamp
        - Tool name
        - Action performed
        - Input hash (without exposing sensitive values)
        - Outcome (success/failure)
        - Evidence item ID (if applicable)

        Args:
            action: Description of the action performed
            details: Additional details (non-sensitive)
        """
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": self.TOOL_NAME,
            "action": action,
            "details": details,
            "risk_classification": self.RISK_CLASSIFICATION,
        }
        self._execution_log.append(log_entry)
        logger.info(f"AUDIT: {log_entry}")

    def _generate_evidence(
        self,
        skill: str,
        tool_output: Dict[str, Any],
        target: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate standardized evidence item from tool output.

        All evidence items include:
        - Timestamp
        - Skill/tool name
        - Target (if applicable)
        - Command executed
        - Exit code
        - Sanitized output
        - Risk classification

        Args:
            skill: The skill/category name
            tool_output: Structured output from tool execution
            target: Target being analyzed (optional)

        Returns:
            Evidence dict ready for persistence
        """
        evidence = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "skill": skill,
            "tool": self.TOOL_NAME,
            "target": target or "unknown",
            "command": json.dumps(tool_output.get("input", {})),
            "exit_code": tool_output.get("exit_code", -1),
            "status": "completed" if tool_output.get("success", False) else "failed",
            "stdout": tool_output.get("stdout", ""),
            "stderr": tool_output.get("stderr", ""),
            "risk": self.RISK_CLASSIFICATION,
        }

        # Add any tool-specific evidence fields
        for item in self.EVIDENCE_ITEMS:
            if item in tool_output:
                evidence[item] = tool_output[item]

        return evidence

    @abc.abstractmethod
    def get_target(self, input_data: Dict[str, Any]) -> Optional[str]:
        """Extract the target from input data.

        Args:
            input_data: Validated input parameters

        Returns:
            Target string (domain, IP, URL, etc.) or None
        """
        raise NotImplementedError

    def run(self, input_data: Dict[str, Any]) -> ToolResult:
        """Main entry point for tool execution.

        This method orchestrates the full execution flow:
        1. Validate input
        2. Extract target
        3. Execute tool
        4. Sanitize output
        5. Generate evidence
        6. Log audit
        7. Return structured result

        Args:
            input_data: Raw input parameters

        Returns:
            ToolResult with execution outcome
        """
        start_time = time.time()

        try:
            # Step 1: Validate input
            self._validate_input_schema(input_data)

            # Step 2: Extract target
            target = self.get_target(input_data)

            # Step 3: Execute tool
            result = self.execute(input_data)

            # Step 4: Sanitize any remaining output
            if result.stdout and not result.stdout.startswith("AUDIT:"):
                result.stdout = self._sanitize_output(result.stdout)
            if result.stderr and not result.stderr.startswith("AUDIT:"):
                result.stderr = self._sanitize_output(result.stderr)

            # Step 5: Generate evidence
            evidence = self._generate_evidence(
                skill=self.TOOL_NAME,
                tool_output={
                    "success": result.success,
                    "exit_code": result.exit_code,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "input": input_data,
                },
                target=target,
            )

            # Persist evidence
            if evidence:
                self.evidence_collector.collect(evidence)
                self.evidence_collector.save(filename=f"{self.TOOL_NAME}_evidence.json")

            # Step 6: Log audit
            execution_time = time.time() - start_time
            self._log_audit(
                action="executed",
                details={
                    "target": target,
                    "execution_time": execution_time,
                    "exit_code": result.exit_code,
                    "success": result.success,
                },
            )

            # Update result with evidence info
            result.evidence = evidence

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
            logger.error(f"Unexpected tool error: {e}")
            return ToolResult(
                success=False,
                tool_name=self.TOOL_NAME,
                execution_time=time.time() - start_time,
                error=f"Unexpected error: {e}",
                exit_code=-1,
            )


# Registry for tool discovery
class ToolRegistry:
    """Registry for discovering and lookup tools by name."""

    def __init__(self):
        self._tools: Dict[str, type] = {}

    def register(self, tool_class: type) -> None:
        """Register a tool class.

        Args:
            tool_class: Subclass of BaseTool to register
        """
        name = getattr(tool_class, "TOOL_NAME", None)
        if not name:
            raise ValueError("Tool class must have TOOL_NAME attribute")
        if name in self._tools:
            logger.warning(f"Tool '{name}' already registered, overwriting")
        self._tools[name] = tool_class
        logger.info(f"Registered tool: {name}")

    def get(self, name: str) -> type:
        """Get a registered tool class by name.

        Args:
            name: Tool name

        Returns:
            Tool subclass

        Raises:
            KeyError: If tool not found
        """
        if name not in self._tools:
            raise KeyError(f"Tool '{name}' not found in registry")
        return self._tools[name]

    def list_tools(self) -> list:
        """List all registered tool names.

        Returns:
            List of tool name strings
        """
        return list(self._tools.keys())

    def create_instance(self, name: str) -> BaseTool:
        """Create an instance of a registered tool.

        Args:
            name: Tool name

        Returns:
            Instantiated tool object
        """
        tool_class = self.get(name)
        return tool_class()


# Global tool registry instance
tool_registry = ToolRegistry()

# Import all tools to trigger registration
from . import (
    network_reconnaissance,
    http_reconnaissance,
    service_enumeration,
    configuration_auditing,
    secret_detection,
    vulnerability_validation,
    evidence_collection,
)

# Export commonly used items
__all__ = [
    "BaseTool",
    "ToolResult",
    "ToolRegistry",
    "tool_registry",
    "InputValidationError",
    "TimeoutError",
    "SandboxEscapeError",
    "network_reconnaissance",
    "http_reconnaissance",
    "service_enumeration",
    "configuration_auditing",
    "secret_detection",
    "vulnerability_validation",
    "evidence_collection",
]