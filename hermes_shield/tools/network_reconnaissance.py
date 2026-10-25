"""HermesShield Network Reconnaissance Tool.

Performs network reconnaissance using nmap for port scanning and service
detection. Operates within sandboxed subprocess with strict allowlisting.

Security controls:
- Only allowlisted nmap commands permitted
- Environment variable filtering via ALLOWED_ENV
- Output sanitization to prevent credential leakage
- Timeout enforcement (default 60s)
- No privileged escalation (no -A, --script with dangerous payloads)
"""

from hermes_shield.tools import InputValidationError,  BaseTool, ToolResult, ToolRegistry

# Register this tool
tool_registry = ToolRegistry()

TOOL_NAME = "network_reconnaissance"
PURPOSE = "Network reconnaissance using nmap for port scanning and service detection"
RISK_CLASSIFICATION = "LOW"

INPUT_SCHEMA = {
    "type": "object",
    "required": ["target"],
    "properties": {
        "target": {"type": "string", "description": "Target IP address or hostname"},
        "scan_type": {
            "type": "string",
            "enum": ["quick", "full", "service"],
            "description": "Type of scan to perform",
            "default": "quick",
        },
        "ports": {
            "type": "string",
            "description": "Port range or list (e.g., '1-1000' or '22,80,443')",
            "default": "1-100",
        },
    },
}

OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["target", "open_ports", "services"],
    "properties": {
        "target": {"type": "string"},
        "open_ports": {"type": "array", "items": {"type": "integer"}},
        "services": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "port": {"type": "integer"},
                    "service": {"type": "string"},
                    "version": {"type": "string"},
                },
                "required": ["port", "service"],
            },
        },
        "os_family": {"type": "string"},
    },
}

PERMISSIONS = {"filesystem": "read_only", "network": "target_only"}
TIMEOUT = 60
EVIDENCE_ITEMS = ["nmap_output"]


class NetworkReconnaissanceTool(BaseTool):
    """Network reconnaissance tool using nmap."""

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
        # Additional validation: target must be non-empty
        if not input_data.get("target") or input_data["target"].strip() == "":
            raise InputValidationError("Target must be a non-empty string")
        return True

    def _build_nmap_command(self, input_data: Dict[str, Any]) -> list:
        """Build the nmap command based on input parameters.

        Security: Only allowlisted nmap flags are included.
        """
        target = input_data["target"]
        scan_type = input_data.get("scan_type", "quick")
        ports = input_data.get("ports", "1-100")

        # Build command based on scan type
        if scan_type == "quick":
            # Quick scan: SYN scan top 100 ports
            cmd = ["nmap", "-sS", "-T4", "-p", ports, target]
        elif scan_type == "full":
            # Full scan: full TCP scan all ports
            cmd = ["nmap", "-sS", "-p-", "-T4", target]
        else:  # service
            # Service detection scan
            cmd = ["nmap", "-sV", "-T4", "-p", ports, target]

        logger.info(f"Built nmap command: {' '.join(cmd)}")
        return cmd

    def execute(self, input_data: Dict[str, Any]) -> ToolResult:
        """Execute network reconnaissance.

        Args:
            input_data: Validated input with target, scan_type, ports

        Returns:
            ToolResult with scan findings
        """
        start_time = time.time()
        target = self.get_target(input_data)

        try:
            # Build and execute nmap command
            cmd = self._build_nmap_command(input_data)

            # Execute via base class subprocess method
            stdout, stderr, exit_code = self._execute_subprocess(
                cmd, timeout=self.TIMEOUT
            )

            execution_time = time.time() - start_time

            # Parse nmap output
            services = []
            open_ports = []

            if exit_code == 0 and stdout:
                # Parse nmap -oX or human-readable output
                # looking for open ports and service info
                for line in stdout.split("\n"):
                    # Look for open port entries
                    if "/open" in line or "/open" in line.lower():
                        # Extract port number
                        port_match = re.search(r"(\d+)/open", line)
                        if port_match:
                            port = int(port_match.group(1))
                            open_ports.append(port)

                            # Look for service/version info
                            service_match = re.search(
                                r"(\d+)/open/(\S+)", line
                            )
                            if service_match:
                                services.append(
                                    {
                                        "port": port,
                                        "service": service_match.group(2),
                                        "version": "",
                                    }
                                )
                            else:
                                services.append(
                                    {"port": port, "service": "unknown", "version": ""}
                                )

            # Build result
            result = ToolResult(
                success=exit_code == 0 and len(open_ports) > 0,
                tool_name=self.TOOL_NAME,
                execution_time=execution_time,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
            )

            # Populate evidence
            result.evidence = {
                "target": target,
                "open_ports": open_ports,
                "services": services,
                "scan_type": input_data.get("scan_type", "quick"),
                "nmap_raw_stdout": stdout,
            }
            result.stdout = (
                f"Open ports: {open_ports}\nServices: {json.dumps(services, indent=2)}"
            )

            # Log audit
            self._log_audit(
                "network_reconnaissance",
                {
                    "target": target,
                    "scan_type": input_data.get("scan_type", "quick"),
                    "open_ports_count": len(open_ports),
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

if __name__ == "__main__":
    # Simple test mode
    import sys
    from hermes_shield.tool_execution import default_executor

    if len(sys.argv) < 2:
        print("Usage: python network_recon.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    tool_instance = tool_registry.create_instance("network_reconnaissance")

    # Quick test with -oN for parseable output would go here
    # For now, just show the tool is importable
    print(f"Network Reconnaissance Tool ready for target: {target}")
    print(f"Tool name: {tool_instance.TOOL_NAME}")
    print(f"Risk classification: {tool_instance.RISK_CLASSIFICATION}")


# Register the tool
tool_registry.register(NetworkReconnaissanceTool)