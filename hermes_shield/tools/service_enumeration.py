"""HermesShield Service Enumeration Tool.

Enumerates services running on target ports using nmap service detection
and banner grabbing. Identifies running services, versions, and potential
configuration issues.

Security controls:
- nmap -sV for service version detection only
- No arbitrary banner grabbing beyond nmap's safe detection
- Output sanitization
- Timeout enforcement
- Only probe explicitly specified ports
"""

from hermes_shield.tools import InputValidationError,  BaseTool, ToolResult, tool_registry

TOOL_NAME = "service_enumeration"
PURPOSE = "Service enumeration and version detection on target ports"
RISK_CLASSIFICATION = "LOW"

INPUT_SCHEMA = {
    "type": "object",
    "required": ["target", "ports"],
    "properties": {
        "target": {"type": "string", "description": "Target IP address or hostname"},
        "ports": {"type": "string", "description": "Port range or list"},
        "include_banner": {
            "type": "boolean",
            "description": " whether to include service banners",
            "default": False,
        },
    },
}

OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["target", "services"],
    "properties": {
        "target": {"type": "string"},
        "services": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "port": {"type": "integer"},
                    "service": {"type": "string"},
                    "version": {"type": "string"},
                    "banner": {"type": "string"},
                },
            },
        },
    },
}

PERMISSIONS = {"filesystem": "read_only", "network": "target_only"}
TIMEOUT = 60
EVIDENCE_ITEMS = ["nmap_service_output"]



class ServiceEnumerationTool(BaseTool):
    """Service enumeration tool using nmap for version detection."""

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
        if not input_data.get("ports"):
            raise InputValidationError("Ports specification is required")
        return True

    def _build_nmap_service_command(self, input_data: Dict[str, Any]) -> list:
        """Build nmap service detection command.

        Uses nmap -sV for service version detection only.
        No arbitrary banner grabbing.
        """
        target = input_data["target"]
        ports = input_data["ports"]
        include_banner = input_data.get("include_banner", False)

        if include_banner:
            # nmap -sV with script for banners (limited, safe scripts only)
            cmd = ["nmap", "-sV", "--script", "banner", "-T4", "-p", ports, target]
        else:
            # Simple service version detection
            cmd = ["nmap", "-sV", "-T4", "-p", ports, target]

        logger.info(f"Built nmap service command: {' '.join(cmd)}")
        return cmd

    def _parse_nmap_service_output(self, output: str) -> list:
        """Parse nmap -sV output into structured service list.

        Args:
            output: Raw nmap output

        Returns:
            List of service dicts with port, service, version, banner
        """
        services = []

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue

            # Pattern: 22/tcp open  ssh     OpenSSH 8.1p1 Ubuntu-6ubuntu0.3
            match = re.match(
                r"^(\d+)/tcp\s+(open|closed|filtered)\s+(\S+)(?:\s+(\S+(?:\s+\S+)?))?", line
            )
            if match and match.group(2) == "open":
                port = int(match.group(1))
                service_name = match.group(3)
                version = match.group(4) if match.group(4) else ""
                banner = match.group(5).strip() if match.group(5) else ""

                services.append(
                    {
                        "port": port,
                        "service": service_name,
                        "version": version,
                        "banner": banner[:100] if banner else "",  # Truncate long banners
                    }
                )

        return services

    def execute(self, input_data: Dict[str, Any]) -> ToolResult:
        """Execute service enumeration.

        Args:
            input_data: Validated input with target and ports

        Returns:
            ToolResult with service enumeration findings
        """
        start_time = time.time()
        target = self.get_target(input_data)

        try:
            # Build and execute nmap service detection command
            cmd = self._build_nmap_service_command(input_data)

            stdout, stderr, exit_code = self._execute_subprocess(
                cmd, timeout=self.TIMEOUT
            )

            execution_time = time.time() - start_time

            # Parse nmap output
            services = self._parse_nmap_service_output(stdout)

            # Build result
            result = ToolResult(
                success=exit_code == 0 and len(services) > 0,
                tool_name=self.TOOL_NAME,
                execution_time=execution_time,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
            )

            # Populate evidence
            result.evidence = {
                "target": target,
                "ports_scanned": input_data.get("ports"),
                "services": services,
                "include_banner": input_data.get("include_banner", False),
            }

            # Build stdout summary
            summary = f"Target: {target}\nPorts: {input_data.get('ports')}\nServices found: {len(services)}\n"
            for svc in services[:10]:  # Limit display to first 10
                summary += f"  Port {svc['port']}/{svc['service']}"
                if svc.get("version"):
                    summary += f" {svc['version']}"
                summary += "\n"
            if len(services) > 10:
                summary += f"... and {len(services) - 10} more services\n"
            result.stdout = summary

            # Log audit
            self._log_audit(
                "service_enumeration",
                {
                    "target": target,
                    "ports_scanned": input_data.get("ports"),
                    "services_found": len(services),
                    "include_banner": input_data.get("include_banner", False),
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
tool_registry.register(ServiceEnumerationTool)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python service_enum.py <target> <ports>")
        sys.exit(1)

    target = sys.argv[1]
    ports = sys.argv[2]
    tool_instance = tool_registry.create_instance("service_enumeration")

    print(f"Service Enumeration Tool for {target} on ports {ports}")
    print(f"Tool name: {tool_instance.TOOL_NAME}")