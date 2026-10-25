"""HermesShield configuration module.

Handles environment variable loading, Nebius Token Factory configuration,
and Nemotron 3 Ultra 550B model setup. All credentials are sourced from
environment variables only - never hardcoded.
"""

import os
import logging

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from hermes_shield.__init__ import get_safe_logger

logger = get_safe_logger(__name__)


class NebiusConfig:
    """Configuration for Nebius Token Factory inference provider.

    Credentials are environment-only and are never intended for frontend use.
    """

    def __init__(self):
        self.api_key = os.environ.get("NEBIUS_API_KEY")
        self.endpoint = os.environ.get(
            "NEBIUS_ENDPOINT", "https://api.nebius.ai/v1"
        )
        self.model_name = os.environ.get("NEBIUS_MODEL", "nvidia/Nemotron-3-Ultra-550b-a55b")
        self.timeout = int(os.environ.get("NEBIUS_TIMEOUT", "120"))
        self.max_tokens = int(os.environ.get("NEBIUS_MAX_TOKENS", "4096"))

        # Validate required fields
        if not self.api_key:
            logger.warning(
                "NEBIUS_API_KEY not set - Nebius integration will be disabled"
            )
        else:
            logger.info("Nebius configuration loaded successfully")

    @property
    def is_configured(self) -> bool:
        """Check if Nebius API key is available."""
        return bool(self.api_key)

    def __str__(self):
        return f"NebiusConfig(model={self.model_name}, configured={self.is_configured})"


class AgentConfig:
    """Configuration for Hermes Agent execution environment."""

    def __init__(self):
        self.audit_root = os.environ.get("HERMES_AUDIT_ROOT", "./audit_data")
        self.tool_timeout = int(os.environ.get("TOOL_COMMAND_TIMEOUT", "60"))
        self.output_size_limit = int(
            os.environ.get("TOOL_OUTPUT_SIZE_LIMIT", "1048576")
        )
        self.log_level = os.environ.get("LOG_LEVEL", "INFO")
        self.audit_id_prefix = os.environ.get("AUDIT_ID_PREFIX", "hermes_")

        logger.info(
            f"Agent configuration loaded: audit_root={self.audit_root}"
        )

    @property
    def is_valid(self) -> bool:
        """Check if agent configuration is minimally valid."""
        # audit_root directory will be created on demand
        return True


def setup_logging(level: str = None):
    """Initialize logging without exposing any configuration secrets."""
    levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    level_name = level or os.environ.get("LOG_LEVEL", "INFO")
    level = levels.get(level_name, logging.INFO)

    # Avoid adding handlers if already configured
    if not logging.root.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )
        handler.setFormatter(formatter)
        logging.root.addHandler(handler)

    logging.root.setLevel(level)
    logging.info(f"Logging level set to {level_name}")


# Provide singleton instances
nebius_config = NebiusConfig()
agent_config = AgentConfig()

logger.info("HermesShield configuration module initialized")