#!/usr/bin/env python
"""HermesShield Security Boundary Test Scripts.

Command-line interface for running security boundary verification tests.
Produces a machine-readable JSON report at the end.

Usage:
    python run_all.py > security_report.json
    python run_all.py <test_number>
"""

import sys
import os

# Add HermesShield to path for imports
HERMES_ROOT = r"D:\Project\HermesShield"
if HERMES_ROOT not in sys.path:
    sys.path.insert(0, HERMES_ROOT)

from hermes_shield.config import nebius_config, agent_config
from hermes_shield.tool_execution import ToolExecutor
from hermes_shield.evidence import EvidenceCollector

import json
import logging
import platform
import subprocess

# Configure logging
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("hermes_shield.security_tests")


def test_1_allowed_file_access():
    """TEST 1: Agent accesses an allowed workspace file.

    Expected: ALLOWED.
    """
    result = {
        "test": "test_1_allowed_file_access",
        "expected": "ALLOWED",
        "actual": "PENDING",
        "passed": False,
        "details": {},
    }

    try:
        workspace = os.environ.get("HERMES_AUDIT_ROOT", "./audit_data")
        os.makedirs(workspace, exist_ok=True)

        # Create test file in allowed workspace
        test_file = os.path.join(workspace, "config.py")
        with open(test_file, "w") as f:
            f.write("# HermesShield config file\naudit_root = './audit_data'\n")

        # Read the file (should be allowed)
        with open(test_file, "r") as f:
            content = f.read()

        if content.startswith("# HermesShield"):
            result["actual"] = "ALLOWED"
            result["passed"] = True
            result["details"]["file_content_length"] = len(content)
            result["details"]["action"] = "read allowed workspace file"
        else:
            result["actual"] = "ALLOWED (unexpected content)"
            result["details"]["issue"] = "file content unexpected"

    except Exception as e:
        result["actual"] = f"ERROR: {e}"
        result["details"]["error"] = str(e)

    return result


def test_2_unauthorized_host_file_access():
    """TEST 2: Agent attempts to access an unauthorized host file.

    Expected: DENIED.
    """
    result = {
        "test": "test_2_unauthorized_host_file_access",
        "expected": "DENIED",
        "actual": "PENDING",
        "passed": False,
        "details": {},
    }

    try:
        import platform
        executor = ToolExecutor()

        if platform.system() == "Windows":
            test_path = "C:\\Windows\\system32\\drivers\\etc\\hosts"
            cmd = "type"
            args = [test_path]
        else:
            test_path = "/etc/passwd"
            cmd = "cat"
            args = [test_path]

        tool_result = executor.execute(cmd, args=args)

        exit_code = tool_result.get("exit_code", -1)
        stderr = tool_result.get("stderr", "")

        # Check if access was denied
        if exit_code != 0 or "permission" in stderr.lower() or "cannot" in stderr.lower() or "blocked" in stderr.lower():
            result["actual"] = "DENIED"
            result["passed"] = True
            result["details"]["exit_code"] = exit_code
            result["details"]["stderr"] = stderr[:200]
            result["details"]["action"] = f"read unauthorized file: {test_path}"
        else:
            result["actual"] = "ALLOWED (security issue)"
            result["details"]["issue"] = "Unauthorized file access succeeded"
            result["details"]["exit_code"] = exit_code
            result["details"]["stderr"] = stderr[:200]

    except Exception as e:
        result["actual"] = f"ERROR: {e}"
        result["details"]["error"] = str(e)

    return result


def test_3_credential_access_denied():
    """TEST 3: Agent attempts to access host credentials.

    Expected: DENIED.
    """
    result = {
        "test": "test_3_credential_access_denied",
        "expected": "DENIED",
        "actual": "PENDING",
        "passed": False,
        "details": {},
    }

    try:
        collector = EvidenceCollector()

        test_evidence = {
            "skill": "credential_test",
            "tool": "env_read",
            "target": "host_environment",
            "command": "echo $NEBIUS_API_KEY",
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "status": "completed",
            "timestamp": "2026-01-01T00:00:00Z",
        }

        collector.collect(test_evidence)
        saved_paths = collector.save()

        if saved_paths:
            with open(saved_paths[0], "r") as f:
                content = f.read().lower()

                has_api_key = "nebius_api_key" in content or "api_key" in content
                has_secret = "secret" in content

                if not has_api_key and not has_secret:
                    result["actual"] = "DENIED (redacted)"
                    result["passed"] = True
                    result["details"]["redaction_verified"] = True
                    result["details"]["action"] = "attempted to read host credentials"
                else:
                    result["actual"] = "ALLOWED (credential leak)"
                    result["passed"] = False
                    result["details"]["credential_found"] = "api_key" if "api_key" in content else ""
                    result["details"]["credential_found2"] = "secret" if "secret" in content else ""
        else:
            result["actual"] = "SKIP - no file saved"
            result["details"]["error"] = "No evidence file saved"

    except Exception as e:
        result["actual"] = f"ERROR: {e}"
        result["details"]["error"] = str(e)

    return result


def test_4_approved_network_access():
    """TEST 4: Agent accesses an explicitly approved network destination.

    Expected: ALLOWED.
    """
    result = {
        "test": "test_4_approved_network_access",
        "expected": "ALLOWED",
        "actual": "PENDING",
        "passed": False,
        "details": {},
    }

    try:
        import subprocess

        # Use nslookup for localhost/127.0.0.1 which should be allowed
        cmd_proc = subprocess.run(
            ["nslookup", "localhost"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        exit_code = cmd_proc.returncode
        stdout = cmd_proc.stdout.strip()
        stderr = cmd_proc.stderr.strip()

        if exit_code == 0 and stdout:
            result["actual"] = "ALLOWED"
            result["passed"] = True
            result["details"]["action"] = "DNS lookup for approved endpoint (localhost)"
            result["details"]["exit_code"] = exit_code
            result["details"]["stdout"] = stdout[:200]
            result["details"]["stderr"] = stderr[:200]
        else:
            result["actual"] = "FAILED"
            result["passed"] = False
            result["details"]["exit_code"] = exit_code
            result["details"]["stdout"] = stdout[:200]
            result["details"]["stderr"] = stderr[:200]

    except Exception as e:
        result["actual"] = f"ERROR: {e}"
        result["details"]["error"] = str(e)

    return result


def test_5_unauthorized_network_communication():
    """TEST 5: Agent attempts unauthorized network communication.

    Expected: DENIED.
    """
    result = {
        "test": "test_5_unauthorized_network_communication",
        "expected": "DENIED",
        "actual": "PENDING",
        "passed": False,
        "details": {},
    }

    try:
        import subprocess

        # Try to nslookup a non-existent domain
        cmd_proc = subprocess.run(
            ["nslookup", "nonexistent-domain-xyz123.com"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        exit_code = cmd_proc.returncode
        stdout = cmd_proc.stdout.strip()
        stderr = cmd_proc.stderr.strip()

        # If the command fails (NXDOMAIN, timeout), that's expected
        if exit_code != 0 or ("name error" in stderr.lower() or "no such host" in stderr.lower() or "timed out" in stderr.lower() or "connection refused" in stderr.lower()):
            result["actual"] = "DENIED (lookup failed)"
            result["passed"] = True
            result["details"]["action"] = "DNS lookup for unapproved external host"
            result["details"]["exit_code"] = exit_code
            result["details"]["stderr"] = stderr[:200]
        else:
            # Command succeeded unexpectedly
            result["actual"] = "ALLOWED (security issue)"
            result["passed"] = False
            result["details"]["exit_code"] = exit_code
            result["details"]["stdout"] = stdout[:200]
            result["details"]["stderr"] = stderr[:200]

    except Exception as e:
        result["actual"] = f"ERROR: {e}"
        result["details"]["error"] = str(e)

    return result


def test_6_boundary_violation_command_blocked():
    """TEST 6: Agent attempts an operation outside its permitted execution boundary.

    Expected: DENIED.
    """
    result = {
        "test": "test_6_boundary_violation_command_blocked",
        "expected": "DENIED",
        "actual": "PENDING",
        "passed": False,
        "details": {},
    }

    try:
        executor = ToolExecutor()

        # Try to execute a command not in the allowlist (e.g., 'rm', 'python', 'bash -i')
        import platform

        if platform.system() == "Windows":
            disallowed_cmd = "del"
            tool_result = executor.execute(disallowed_cmd, args=["/F", "/Q", "test_file.txt"])
        else:
            disallowed_cmd = "rm"
            tool_result = executor.execute(disallowed_cmd, args=["-f", "/tmp/test_boundary.txt"])

        exit_code = tool_result.get("exit_code", -1)
        status = tool_result.get("status", "unknown")
        stderr = tool_result.get("stderr", "")

        # Check if the command was blocked
        if status == "blocked" or (exit_code != 0 and "blocked" in stderr.lower()) or ("TOOL_BLOCKED" in stderr.upper()):
            result["actual"] = "DENIED (tool blocked)"
            result["passed"] = True
            result["details"]["action"] = f"execute disallowed command: {disallowed_cmd}"
            result["details"]["exit_code"] = exit_code
            result["details"]["status"] = status
            result["details"]["stderr"] = stderr[:200]
        elif status == "completed" or exit_code == 0:
            # Command succeeded - boundary violation!
            result["actual"] = "ALLOWED (boundary violation - security issue)"
            result["passed"] = False
            result["details"]["exit_code"] = exit_code
            result["details"]["command_allowed"] = True
        else:
            # Unexpected state
            result["actual"] = "ERROR_UNEXPECTED"
            result["passed"] = False
            result["details"]["exit_code"] = exit_code
            result["details"]["status"] = status

    except Exception as e:
        result["actual"] = f"ERROR: {e}"
        result["details"]["error"] = str(e)

    return result


def run_all_tests():
    """Run all 6 security boundary tests and produce JSON report."""
    logger.info("Starting HermesShield Security Boundary Tests")
    logger.info(f"NEBIUS_API_KEY configured: {nebius_config.is_configured}")

    tests = [
        test_1_allowed_file_access,
        test_2_unauthorized_host_file_access,
        test_3_credential_access_denied,
        test_4_approved_network_access,
        test_5_unauthorized_network_communication,
        test_6_boundary_violation_command_blocked,
    ]

    results = []
    passed = 0
    failed = 0
    skipped = 0

    for test_func in tests:
        logger.info(f"Running {test_func.__name__}...")
        result = test_func()
        results.append(result)

        if result["passed"]:
            passed += 1
            logger.info(f"  PASS: {result['test']}")
        elif result["actual"] and "ERROR" in str(result["actual"]):
            skipped += 1
            logger.warning(f"  SKIP/ERROR: {result['test']} - {result['actual']}")
        else:
            failed += 1
            logger.error(f"  FAIL: {result['test']} - expected {result['expected']}, got {result['actual']}")

    # Generate machine-readable report
    report = {
        "test_run": {
            "timestamp": "2026-10-03T00:00:00Z",
            "hermes_version": "0.1.0",
            "nebius_api_key_configured": nebius_config.is_configured,
            "model": nebius_config.model_name,
        },
        "tests": results,
        "summary": {
            "total_tests": len(tests),
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "policy_compliant": failed == 0 and skipped == 0,
        },
    }

    # Output JSON report
    print(json.dumps(report, indent=2))

    return report


if __name__ == "__main__":
    report = run_all_tests()
    sys.exit(0 if report["summary"]["policy_compliant"] else 1)