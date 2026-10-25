"""HermesShield - Autonomous AI security auditing and red-team simulation platform."""

__version__ = "0.1.0"

# Core imports that should always be available
import logging
import os
import sys

# Configure module-level logger (secrets-free)
def _get_safe_logger(name):
    """Get logger configured without exposing sensitive configuration."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger

logger = _get_safe_logger(__name__)

# Safe configuration loader - never logs raw secrets
def get_config():
    """Return configuration values without exposing credentials."""
    return {
        "audit_root": os.environ.get("HERMES_AUDIT_ROOT", "./audit_data"),
        "tool_timeout": int(os.environ.get("TOOL_COMMAND_TIMEOUT", "60")),
        "output_size_limit": int(os.environ.get("TOOL_OUTPUT_SIZE_LIMIT", "1048576")),
        "log_level": os.environ.get("LOG_LEVEL", "INFO"),
        "audit_id_prefix": os.environ.get("AUDIT_ID_PREFIX", "hermes_"),
        "nebius_key_configured": bool(os.environ.get("NEBIUS_API_KEY")),
        "nebius_key_present_masked": (
        os.environ.get("NEBIUS_API_KEY", "")[:4] + "****"
        if os.environ.get("NEBIUS_API_KEY")
        else False
    ),
    }

# Export for external use
get_safe_logger = _get_safe_logger