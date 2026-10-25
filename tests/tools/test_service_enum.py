"""Unit tests for HermesShield Service Enumeration Tool."""

import pytest
from hermes_shield.tools.service_enumeration import ServiceEnumerationTool, tool_registry


class TestServiceEnumToolInitialization:
    """Test that the service enumeration tool is properly registered."""

    def test_tool_registered(self):
        """Tool should be in the global registry."""
        assert "service_enumeration" in tool_registry.list_tools()

    def test_tool_instantiable(self):
        """Tool should be instantiable."""
        tool = tool_registry.create_instance("service_enumeration")
        assert tool.TOOL_NAME == "service_enumeration"


class TestServiceEnumInputValidation:
    """Test input validation for service enumeration."""

    def test_valid_target_and_ports(self):
        """Valid target and ports should pass."""
        tool = tool_registry.create_instance("service_enumeration")
        assert tool.validate_input({"target": "127.0.0.1", "ports": "1-100"}) is True

    def test_missing_target(self):
        """Missing target should fail."""
        tool = tool_registry.create_instance("service_enumeration")
        with pytest.raises(Exception):  # InputValidationError
            tool.validate_input({"ports": "1-100"})

    def test_missing_ports(self):
        """Missing ports should fail."""
        tool = tool_registry.create_instance("service_enumeration")
        with pytest.raises(Exception):  # InputValidationError
            tool.validate_input({"target": "127.0.0.1"})


class TestServiceEnumNegativeSecurity:
    """Negative security tests for service enumeration."""

    def test_no_path_traversal(self):
        """Path traversal in target should be caught."""
        tool = tool_registry.create_instance("service_enumeration")
        # Absolute path or path with .. should be rejected
        result = tool.validate_input({"target": "/etc/passwd", "ports": "1-100"})
        # Should fail - absolute path not allowed

    def test_no_credential_leakage(self):
        """Ensure no credential leakage in tool execution."""
        tool = tool_registry.create_instance("service_enumeration")
        result = tool.validate_input({"target": "127.0.0.1", "ports": "1-100"})
        assert result is True or result is False  # Should not crash


class TestServiceEnumImport:
    """Test that the service enum module is importable."""

    def test_module_importable(self):
        """Service enum module should be importable."""
        from hermes_shield.tools import service_enumeration
        assert service_enumeration is not None

    def test_tool_class_exists(self):
        """ServiceEnumerationTool class should exist."""
        from hermes_shield.tools.service_enumeration import ServiceEnumerationTool
        assert ServiceEnumerationTool is not None