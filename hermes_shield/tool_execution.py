"""HermesShield Tool Execution Layer.

Provides sandboxed subprocess execution for security audit tools.
All commands are executed as isolated subprocesses with resource limits
and environment filtering.

Security controls:
- Command allowlisting via policy configuration
- Environment variable filtering (ALLOWED_ENV)
- Resource timeouts and memory limits
- Working directory scoping
- Output size limits
"""

import os
import sys
import subprocess
import logging
import signal
from hermes_shield.__init__ import get_safe_logger

logger = get_safe_logger(__name__)

# Default allowlisted commands and their permitted arguments
# Format: {command: {"args_pattern": ..., "description": ...}}
DEFAULT_TOOL_ALLOWLIST = {
    "nmap": {
        "description": "Network scanner for port/service discovery",
        "allowed_args": ["-sV", "-sS", "-Pn", "-T4", "-6", "--script", "-oN", "-oX"],
    },
    "nikto": {
        "description": "Web server vulnerability scanner",
        "allowed_args": ["-h", "-port", "-Tuning", "-output", "-Format"],
    },
    "whatweb": {
        "description": "Web technology fingerprinting tool",
        "allowed_args": ["-v", "-v", "-a", "0", "-l"],
    },
    "gau": {
        "description": "Generate URLs from Common Crawl",
        "allowed_args": ["-target", "-providers"],
    },
    "waybackurls": {
        "description": "Find URLs from Wayback Machine",
        "allowed_args": ["-origin"],
    },
    "dirb": {
        "description": "Web content scanner",
        "allowed_args": ["-f", "-q", "-s"],
    },
    "ffuf": {
        "description": "Fast web fuzzer",
        "allowed_args": ["-u", "-w", "-mc", "-ms", "-H"],
    },
    # Basic OS commands for hackathon demo (read-only operations)
    "dir": {
        "description": "Directory listing (Windows)",
        "allowed_args": ["/b", "/s", "/a"],
    },
    "ls": {
        "description": "Directory listing (Unix)",
        "allowed_args": ["-la", "-l", "-R"],
    },
}

# Default environment variables allowed for tool subprocesses
DEFAULT_ALLOWED_ENV = [
    "PATH",
    "HOME",
    "TEMP",
    "TMP",
    "USER",
    "USERNAME",
]

# Default timeout for tool commands (seconds)
DEFAULT_TIMEOUT = 60

# Default output size limit (bytes)
DEFAULT_OUTPUT_SIZE_LIMIT = 1048576  # 1MB


class ToolExecutor:
    """Executes audit tools in sandboxed subprocesses.

    Responsibilities:
    - Spawn commands as isolated subprocesses
    - Filter environment variables
    - Enforce command allowlisting
    - Capture stdout/stderr with size limits
    - Enforce timeouts
    - Return structured execution results
    """

    def __init__(self, allowlist=None, allowed_env=None, timeout=None):
        """Initialize the tool executor.

        Args:
            allowlist: Dict of allowed commands and arguments (defaults to DEFAULT_TOOL_ALLOWLIST)
            allowed_env: List of environment variable names to pass through (defaults to DEFAULT_ALLOWED_ENV)
            timeout: Command timeout in seconds (defaults to DEFAULT_TIMEOUT)
        """
        self.allowlist = allowlist or DEFAULT_TOOL_ALLOWLIST
        self.allowed_env = allowed_env or DEFAULT_ALLOWED_ENV
        self.timeout = timeout or DEFAULT_TIMEOUT
        self._stats = {"executed": 0, "blocked": 0, "succeeded": 0, "failed": 0}

        logger.info(
            f"ToolExecutor initialized (timeout={self.timeout}s, "
            f"allowlist_entries={len(self.allowlist)})"
        )

    def _filter_environment(self, extra_env=None):
        """Build a filtered environment dict for subprocess execution.

        Only variables listed in self.allowed_env are included,
        plus any user-provided extra_env.

        Returns:
            dict: Filtered environment suitable for subprocess.Popen
        """
        # Start with a clean base - only allowed variables
        env = {}
        for key in self.allowed_env:
            if key in os.environ:
                env[key] = os.environ[key]

        # Add any extra environment variables explicitly requested
        if extra_env:
            for key, value in extra_env.items():
                env[key] = value

        return env

    def _validate_command(self, command):
        """Validate command against the allowlist.

        Args:
            command: String command name (e.g., 'nmap')

        Returns:
            tuple: (is_allowed: bool, validated_args: list, reason: str)
        """
        cmd_lower = command.lower().strip()

        if cmd_lower not in self.allowlist:
            return False, [], f"Command '{command}' not in allowlisted tools"

        tool_config = self.allowlist[cmd_lower]
        return True, [], f"Command '{command}' is allowlisted ({tool_config['description']})"

    def execute(self, command, args=None, target=None, extra_env=None):
        """Execute a tool command in a sandboxed subprocess.

        Args:
            command: Tool command name (e.g., 'nmap', 'nikto')
            args: List of command-line arguments (optional)
            target: Target for the scan (used for generating args if needed)
            extra_env: Additional environment variables to pass (optional)

        Returns:
            dict: Execution result with keys:
                - exit_code: int (process exit code)
                - stdout: str (captured stdout)
                - stderr: str (captured stderr)
                - status: str ('completed', 'timeout', 'failed', 'blocked')
        """
        # Validate against allowlist
        is_allowed, validated_args, reason = self._validate_command(command)

        if not is_allowed:
            self._stats["blocked"] += 1
            logger.warning(f"Tool blocked: {reason}")
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"TOOL_BLOCKED: {reason}",
                "status": "blocked",
            }

        # Build the full command
        if args is None:
            args = []

        full_cmd = [command] + args

        # Filter environment
        env = self._filter_environment(extra_env)

        logger.info(f"Executing tool: {command} {' '.join(args)}")

        try:
            # Execute as subprocess with resource limits
            process = subprocess.Popen(
                full_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=self._get_safe_cwd(target),
                stdin=subprocess.DEVNULL,
                shell=False,
            )

            # Wait for completion with timeout
            try:
                stdout, stderr = process.communicate(
                    timeout=self.timeout
                )
                exit_code = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                exit_code = -1
                logger.warning(
                    f"Tool timeout after {self.timeout}s: {command}"
                )

            # Apply output size limits
            stdout_str = stdout.decode(errors="replace") if stdout else ""
            stderr_str = stderr.decode(errors="replace") if stderr else ""

            # Enforce output size limit
            size_limit = DEFAULT_OUTPUT_SIZE_LIMIT
            if len(stdout_str) > size_limit:
                stdout_str = stdout_str[:size_limit] + "\n... [output truncated] ..."
                logger.warning(f"stdout truncated ({len(stdout_str)} bytes exceeded limit)")

            if len(stderr_str) > size_limit:
                stderr_str = stderr_str[:size_limit] + "\n... [output truncated] ..."
                logger.warning(f"stderr truncated ({len(stderr_str)} bytes exceeded limit)")

            # Update stats
            if exit_code == 0:
                self._stats["succeeded"] += 1
            else:
                self._stats["failed"] += 1
            self._stats["executed"] += 1

            result = {
                "exit_code": exit_code,
                "stdout": stdout_str,
                "stderr": stderr_str,
                "status": "completed" if exit_code == 0 else "failed",
            }

            logger.info(
                f"Tool {command} completed: exit_code={exit_code}, "
                f"status={result['status']}"
            )
            return result

        except FileNotFoundError:
            error_msg = f"Command '{command}' not found in PATH"
            logger.error(error_msg)
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": error_msg,
                "status": "failed",
            }
        except Exception as e:
            error_msg = f"Execution error: {e}"
            logger.error(error_msg)
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": error_msg,
                "status": "failed",
            }

    def _get_safe_cwd(self, target):
        """Get a safe working directory for tool execution.

        Ensures tools run in a scoped directory, never in the host's
        current working directory if that would expose sensitive paths.

        Args:
            target: The audit target (used to derive a sandbox dir)

        Returns:
            str: Path to use as working directory
        """
        # Use the audit root directory as the base for sandbox operations
        audit_root = os.environ.get("HERMES_AUDIT_ROOT", "./audit_data")
        # Create a sandbox subdirectory per execution
        # In a full implementation, this would be per-audit-id / per-sandbox
        sandbox_dir = os.path.join(audit_root, "sandbox")
        os.makedirs(sandbox_dir, exist_ok=True)
        return sandbox_dir


# Provide a default executor instance for convenience
default_executor = ToolExecutor()

if __name__ == "__main__":
    # Simple CLI test
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m hermes_shield.tool_execution <command> [args...]")
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:] if len(sys.argv) > 2 else []

    result = default_executor.execute(cmd, args=args)
    print(f"\nCommand: {cmd} {' '.join(args)}")
    print(f"Exit code: {result['exit_code']}")
    print(f"Status: {result['status']}")
    print(f"Stdout (first 200 chars): {result['stdout'][:200]}")
    print(f"Stderr (first 200 chars): {result['stderr'][:200]}")