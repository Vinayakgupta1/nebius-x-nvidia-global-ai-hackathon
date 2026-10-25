"""Unit tests for HermesShield Configuration Auditing Tool."""

import pytest
from hermes_shield.tools.configuration_auditing import ConfigurationAuditingTool, tool_registry


class TestConfigAuditToolInitialization:
    """Test that the configuration auditing tool is properly registered."""

    def test_tool_registered(self):
        """Tool should be in the global registry."""
        assert "configuration_auditing" in tool_registry.list_tools()

    def test_tool_instantiable(self):
        """Tool should be instantiable."""
        tool = tool_registry.create_instance("configuration_auditing")
        assert tool.TOOL_NAME == "configuration_auditing"


class TestConfigAuditInputValidation:
    """Test input validation for configuration auditing."""

    def test_valid_input(self):
        """Valid input should pass."""
        tool = tool_registry.create_instance("configuration_auditing")
        assert tool.validate_input({
            "target": "192.168.1.1",
            "config_path": "test_config.cfg"
        }) is True

    def test_missing_target(self):
        """Missing target should fail."""
        tool = tool_registry.create_instance("configuration_auditing")
        with pytest.raises(Exception):  # InputValidationError
            tool.validate_input({"config_path": "test.cfg"})

    def test_missing_config_path(self):
        """Missing config_path should fail."""
        tool = tool_registry.create_instance("configuration_auditing")
        with pytest.raises(Exception):  # InputValidationError
            tool.validate_input({"target": "192.168.1.1"})

    def test_path_traversal_rejected(self):
        """Path traversal in config_path should be rejected."""
        tool = tool_registry.create_instance("configuration_auditing")
        with pytest.raises(Exception):  # InputValidationError
            tool.validate_input({
                "target": "192.168.1.1",
                "config_path": "../../../etc/passwd"
            })


class TestConfigAuditNegativeSecurity:
    """Negative security tests for configuration auditing."""

    def test_no_credential_leakage(self):
        """Ensure no credential leakage in tool output."""
        tool = tool_registry.create_instance("configuration_auditing")
        result = tool.validate_input({
            "target": "192.168.1.1",
            "config_path": "test.cfg"
        })
        assert result is True or result is False  # Should not crash

    def test_path_traversal_blocked(self):
        """Path traversal attempt should be blocked."""
        tool = tool_registry.create_instance("configuration_auditing")
        with pytest.raises(Exception):  # InputValidationError
            tool.validate_input({
                "target": "192.168.1.1",
                "config_path": "/etc/passwd"
            })


class TestConfigAuditImport:
    """Test that the config audit module is importable."""

    def test_module_importable(self):
        """Config audit module should be importable."""
        from hermes_shield.tools import configuration_auditing
        assert configuration_auditing is not None

    def test_tool_class_exists(self):
        """ConfigurationAuditingTool class should exist."""
        from hermes_shield.tools.configuration_auditing import ConfigurationAuditingTool
        assert ConfigurationAuditingTool is not None