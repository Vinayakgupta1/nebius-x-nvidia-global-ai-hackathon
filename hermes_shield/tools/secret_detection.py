"""HermesShield Secret Detection Tool.

Detects secrets, credentials, and sensitive data in target files, logs,
and outputs. Uses pattern matching and entropy analysis to identify
potential credential material without executing code.

Security controls:
- Read-only file scanning within sandbox
- No code execution or script interpretation
- Pattern-based detection only (no false-positive-free guarantees)
- Output sanitization (redact detected secrets)
- Timeout enforcement
- Compliant with data handling policies (findings logged, not persisted raw)
"""

from hermes_shield.tools import InputValidationError,  BaseTool, ToolResult, tool_registry

TOOL_NAME = "secret_detection"
PURPOSE = "Detect secrets, credentials, and sensitive data in target files"
RISK_CLASSIFICATION = "LOW"

INPUT_SCHEMA = {
    "type": "object",
    "required": ["target", "search_paths"],
    "properties": {
        "target": {"type": "string", "description": "Target system identifier"},
        "search_paths": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Paths to search (relative to audit root)",
        },
        "include_entropy": {
            "type": "boolean",
            "description": "Whether to include entropy scoring",
            "default": False,
        },
    },
}

OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["target", "search_paths", "secrets_found"],
    "properties": {
        "target": {"type": "string"},
        "search_paths": {
            "type": "array",
            "items": {"type": "string"},
        },
        "secrets_found": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                    "line_number": {"type": "integer"},
                    "secret_type": {"type": "string"},
                    "secret_value": {"type": "string"},
                    "entropy": {"type": "number"},
                    "recommendation": {"type": "string"},
                },
            },
        },
    },
}

PERMISSIONS = {"filesystem": "read_only", "network": "none"}
TIMEOUT = 30
EVIDENCE_ITEMS = ["secret_detection_output"]

class SecretDetectionTool(BaseTool):
    """Secret detection tool for finding credentials in files."""

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
        if not input_data.get("search_paths"):
            raise InputValidationError("Search paths are required")
        # Security: all paths must be relative and within audit root
        for path in input_data["search_paths"]:
            if path.startswith("/") or ".." in path:
                raise InputValidationError(
                    f"Search path '{path}' must be relative and within sandbox scope"
                )
        return True

    def _read_file_safe(self, file_path: str) -> Optional[str]:
        """Safely read a file within the sandbox.

        Args:
            file_path: Relative path to file

        Returns:
            File content or None
        """
        audit_root = os.environ.get("HERMES_AUDIT_ROOT", "./audit_data")
        full_path = os.path.join(audit_root, file_path)

        # Security: ensure path is within audit root
        if not os.path.abspath(full_path).startswith(
            os.path.abspath(audit_root)
        ):
            logger.error(f"Path traversal attempt: {file_path}")
            raise InputValidationError(f"Path '{file_path}' outside sandbox scope")

        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except FileNotFoundError:
            return None
        except Exception as e:
            logger.warning(f"Error reading {file_path}: {e}")
            return None

    def _detect_secrets_regex(self, content: str, line_num: int) -> list:
        """Detect secrets using regex pattern matching.

        Args:
            content: File content
            line_num: Line number (1-indexed)

        Returns:
            List of detected secret dicts
        """
        secrets = []

        # Secret detection patterns
        secret_patterns = [
            # API keys (various formats)
            (
                r"(?i)(api_key|apikey|x_api_key)\s*=\s*['\"][^'\"]{8,}['\"]",
                "api_key",
            ),
            # Passwords
            (
                r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]",
                "password",
            ),
            # AWS-style secret keys
            (
                r"(?i)aws.*secret.*access.*key\s*=\s*['\"][A-Z0-9]{20,}['\"]",
                "aws_secret_access_key",
            ),
            # Generic token patterns
            (
                r"(?i)(token|auth_token|api_token)\s*=\s*['\"][A-Za-z0-9\-_]{16,}['\"]",
                "token",
            ),
            # Credit card numbers (luhn algorithm approx)
            (
                r"(?:\d[ -]*){13,16}",
                "potential_credit_card",
            ),
            # Private keys (beginning markers)
            (
                r"(-----BEGIN (RSA |EC |OPEN )?PRIVATE KEY-----)",
                "private_key",
            ),
        ]

        for pattern, secret_type in secret_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                matched_value = match.group(0)
                # Don't expose the full secret in the finding - just the type
                secrets.append(
                    {
                        "file_path": "",
                        "line_number": line_num,
                        "secret_type": secret_type,
                        "secret_value": "**REDACTED**",
                        "entropy": 0.0,
                        "recommendation": f"Rotate or rotate {secret_type} immediately",
                    }
                )

        return secrets

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text.

        Simple entropy calculation to help assess secret likelihood.

        Args:
            text: Text to calculate entropy for

        Returns:
            Entropy score (0-8+)
        """
        if not text:
            return 0.0

        # Basic entropy calculation
        import math

        chars = defaultdict(int)
        for char in text:
            chars[char] += 1

        length = len(text)
        entropy = 0

        for count in chars.values():
            p = count / length
            if p > 0:
                entropy = math.log2(p)

        return round(entropy, 2)

    def execute(self, input_data: Dict[str, Any]) -> ToolResult:
        """Execute secret detection.

        Args:
            input_data: Validated input with target and search_paths

        Returns:
            ToolResult with detected secrets
        """
        start_time = time.time()
        target = self.get_target(input_data)

        try:
            all_secrets = []
            paths_searched = 0

            for search_path in input_data.get("search_paths", []):
                try:
                    file_content = self._read_file_safe(search_path)
                    paths_searched += 1

                    if file_content:
                        # Split into lines and scan each
                        lines = file_content.split("\n")
                        for line_num, line in enumerate(lines, 1):
                            line_secrets = self._detect_secrets_regex(
                                line, line_num
                            )
                            for secret in line_secrets:
                                # Add file path context
                                secret["file_path"] = search_path
                                # Calculate entropy if requested
                                if input_data.get("include_entropy", False):
                                    secret["entropy"] = self._calculate_entropy(
                                        secret.get("secret_value", "")
                                    )
                                all_secrets.append(secret)
                except InputValidationError:
                    # Skip paths that fail validation
                    continue
                except Exception as e:
                    logger.warning(f"Error scanning {search_path}: {e}")

            execution_time = time.time() - start_time

            # Build result
            result = ToolResult(
                success=True,
                tool_name=self.TOOL_NAME,
                execution_time=execution_time,
                stdout=f"Scanned {paths_searched} paths on {target}: {len(all_secrets)} potential secrets detected",
                stderr="",
                exit_code=0,
            )

            # Populate evidence
            result.evidence = {
                "target": target,
                "search_paths": input_data.get("search_paths"),
                "paths_searched": paths_searched,
                "secrets_found": all_secrets,
            }

            # Build stdout summary - only show count and types, never raw values
            summary = f"Secret detection on {target}\n"
            summary += f"Paths searched: {paths_searched}\n"
            summary += f"Potential secrets detected: {len(all_secrets)}\n\n"

            # Group by type
            type_counts = {}
            for secret in all_secrets:
                st = secret.get("secret_type", "unknown")
                type_counts[st] = type_counts.get(st, 0) + 1

            if type_counts:
                summary += "Secret types found:\n"
                for st, count in type_counts.items():
                    summary += f"  - {st}: {count}\n"

            if not type_counts and not all_secrets:
                summary += "No detectable secrets found in scanned files.\n"

            result.stdout = summary

            # Log audit
            self._log_audit(
                "secret_detection",
                {
                    "target": target,
                    "paths_searched": paths_searched,
                    "secrets_found_count": len(all_secrets),
                    "include_entropy": input_data.get("include_entropy", False),
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
        print("Usage: python secret_detection.py <target> <search_path1> [search_path2 ...]")
        sys.exit(1)

    target = sys.argv[1]
    search_paths = sys.argv[2:]
    tool_instance = tool_registry.create_instance("secret_detection")

    print(f"Secret Detection Tool for {target}")
    print(f"Search paths: {search_paths}")


# Register the tool
tool_registry.register(SecretDetectionTool)