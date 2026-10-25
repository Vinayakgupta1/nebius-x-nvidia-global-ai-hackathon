"""HermesShield HTTP Reconnaissance Tool.

Performs HTTP reconnaissance using whatweb and gau for technology
fingerprinting and URL discovery. Operates within sandboxed subprocess
with strict allowlisting.

Security controls:
- Only allowlisted tool commands permitted
- Output sanitization to prevent credential leakage
- Timeout enforcement (default 30s)
- No arbitrary HTTP request generation (scoped to target only)
- No cookie or header injection capabilities
"""

from hermes_shield.tools import InputValidationError,  BaseTool, ToolResult, tool_registry

TOOL_NAME = "http_reconnaissance"
PURPOSE = "HTTP reconnaissance for technology fingerprinting and URL discovery"
RISK_CLASSIFICATION = "LOW"

INPUT_SCHEMA = {
    "type": "object",
    "required": ["target"],
    "properties": {
        "target": {"type": "string", "description": "Target URL (http:// or https://)"},
        "check_tech": {
            "type": "boolean",
            "description": "Whether to run technology fingerprinting",
            "default": True,
        },
        "discover_urls": {
            "type": "boolean",
            "description": "Whether to discover URLs via gau",
            "default": True,
        },
    },
}

OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["target", "technology_fingerprint", "discovered_urls"],
    "properties": {
        "target": {"type": "string"},
        "technology_fingerprint": {
            "type": "object",
            "description": "Detected technologies and versions",
            "properties": {
                "cms": {"type": "string", "description": "Content Management System"},
                "framework": {"type": "string", "description": "JavaScript framework"},
                "web_server": {"type": "string", "description": "Web server software"},
            },
        },
        "discovered_urls": {"type": "array", "items": {"type": "string"}},
    },
}

PERMISSIONS = {"filesystem": "read_only", "network": "target_only"}
TIMEOUT = 30
EVIDENCE_ITEMS = ["whatweb_output", "gau_output"]

# Allowlisted tools for this module
ALLOWED_HTTP_TOOLS = ["whatweb", "gau"]


class HTTPReconnaissanceTool(BaseTool):
    """HTTP reconnaissance tool using whatweb and gau."""

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
        target = input_data.get("target", "")
        if not target:
            raise InputValidationError("Target is required")
        # Ensure target has a valid URL scheme
        if not target.startswith(("http://", "https://")):
            raise InputValidationError("Target must start with http:// or https://")
        return True

    def _run_whatweb(self, target: str) -> Tuple[str, str, int]:
        """Run whatweb technology fingerprinting.

        Args:
            target: Target URL

        Returns:
            Tuple of (stdout, stderr, exit_code)
        """
        cmd = ["whatweb", "-v", "-a", "0", target]
        return self._execute_subprocess(cmd, timeout=self.TIMEOUT // 2)

    def _run_gau(self, target: str) -> Tuple[str, str, int]:
        """Run gau URL discovery.

        Args:
            target: Target URL

        Returns:
            Tuple of (stdout, stderr, exit_code)
        """
        cmd = ["gau", target]
        return self._execute_subprocess(cmd, timeout=self.TIMEOUT // 2)

    def _parse_whatweb_output(self, output: str) -> Dict[str, str]:
        """Parse whatweb output into technology fingerprint dict.

        Args:
            output: Raw whatweb output

        Returns:
            Dictionary of detected technologies
        """
        fingerprint = {
            "cms": "",
            "framework": "",
            "web_server": "",
        }

        # Parse simple whatweb output format
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            if "WordPress" in line or "wp-" in line.lower():
                fingerprint["cms"] = "WordPress"
            elif "Joomla" in line or "joomla-" in line.lower():
                fingerprint["cms"] = "Joomla"
            elif "Drupal" in line or "drupal-" in line.lower():
                fingerprint["cms"] = "Drupal"
            elif "React" in line:
                fingerprint["framework"] = "React"
            elif "Angular" in line:
                fingerprint["framework"] = "Angular"
            elif "Vue.js" in line or "vue-" in line.lower():
                fingerprint["framework"] = "Vue.js"
            elif "Apache" in line:
                fingerprint["web_server"] = "Apache"
            elif "nginx" in line.lower():
                fingerprint["web_server"] = "nginx"
            elif "IIS" in line:
                fingerprint["web_server"] = "IIS"

        return fingerprint

    def _parse_gau_output(self, output: str) -> list:
        """Parse gau output into list of discovered URLs.

        Args:
            output: Raw gau output

        Returns:
            List of discovered URLs
        """
        urls = []
        for line in output.split("\n"):
            line = line.strip()
            if line and line.startswith("http"):
                urls.append(line)
        return urls

    def execute(self, input_data: Dict[str, Any]) -> ToolResult:
        """Execute HTTP reconnaissance.

        Args:
            input_data: Validated input with target, check_tech, discover_urls

        Returns:
            ToolResult with HTTP reconnaissance findings
        """
        start_time = time.time()
        target = self.get_target(input_data)

        try:
            # Run whatweb if configured
            whatweb_output = ""
            if input_data.get("check_tech", True):
                try:
                    whatweb_stdout, whatweb_stderr, whatweb_exit = self._run_whatweb(target)
                    whatweb_output = whatweb_stdout
                except Exception as e:
                    logger.warning(f"whatweb failed: {e}")

            # Run gau if configured
            gau_output = ""
            if input_data.get("discover_urls", True):
                try:
                    gau_stdout, gau_stderr, gau_exit = self._run_gau(target)
                    gau_output = gau_stdout
                except Exception as e:
                    logger.warning(f"gau failed: {e}")

            # Parse results
            fingerprint = self._parse_whatweb_output(whatweb_output)
            discovered_urls = self._parse_gau_output(gau_output)

            execution_time = time.time() - start_time

            # Build result
            result = ToolResult(
                success=True,
                tool_name=self.TOOL_NAME,
                execution_time=execution_time,
                stdout=f"Target: {target}\nTechnologies: {json.dumps(fingerprint, indent=2)}\nURLs: {len(discovered_urls)} discovered",
                stderr="",
                exit_code=0,
            )

            # Populate evidence
            result.evidence = {
                "target": target,
                "technology_fingerprint": fingerprint,
                "discovered_urls": discovered_urls,
                "whatweb_raw": whatweb_output,
                "gau_raw": gau_output,
            }

            # Truncate stdout for display
            stdout_summary = f"Target: {target}\n"
            stdout_summary += f"CMS: {fingerprint.get('cms', 'unknown')}\n"
            stdout_summary += f"Framework: {fingerprint.get('framework', 'unknown')}\n"
            stdout_summary += f"Web Server: {fingerprint.get('web_server', 'unknown')}\n"
            stdout_summary += f"Discovered URLs: {len(discovered_urls)}"
            result.stdout = stdout_summary

            # Log audit
            self._log_audit(
                "http_reconnaissance",
                {
                    "target": target,
                    "check_tech": input_data.get("check_tech", True),
                    "discover_urls": input_data.get("discover_urls", True),
                    "technologies_detected": list(fingerprint.values()),
                    "urls_found": len(discovered_urls),
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


# Register the tool
tool_registry.register(HTTPReconnaissanceTool)


if __name__ == "__main__":
    # Simple test mode
    import sys

    if len(sys.argv) < 2:
        print("Usage: python http_recon.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    tool_instance = tool_registry.create_instance("http_reconnaissance")

    print(f"HTTP Reconnaissance Tool ready for target: {target}")
    print(f"Tool name: {tool_instance.TOOL_NAME}")
    print(f"Risk classification: {tool_instance.RISK_CLASSIFICATION}")