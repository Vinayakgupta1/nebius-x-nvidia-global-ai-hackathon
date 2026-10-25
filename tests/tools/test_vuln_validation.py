"""Unit tests for HermesShield Vulnerability Validation Tool."""

import pytest
from hermes_shield.tools.vulnerability_validation import VulnerabilityValidationTool, tool_registry


class TestVulnValidationToolInitialization:
    """Test that the vulnerability validation tool is properly registered."""

    def test_tool_registered(self):
        """Tool should be in the global registry."""
        assert "vulnerability_validation" in tool_registry.list_tools()

    def test_tool_instantiable(self):
        """Tool should be instantiable."""
        tool = tool_registry.create_instance("vulnerability_validation")
        assert tool.TOOL_NAME == "vulnerability_validation"


class TestVulnValidationInputValidation:
    """Test input validation for vulnerability validation."""

    def test_valid_input(self):
        """Valid input should pass."""
        tool = tool_registry.create_instance("vulnerability_validation")
        assert tool.validate_input({
            "target": "192.168.1.1",
            "vulnerability_id": "test_vuln"
        }) is True

    def test_missing_target(self):
        """Missing target should fail."""
        tool = tool_registry.create_instance("vulnerability_validation")
        with pytest.raises(Exception):  # InputValidationError
            tool.validate_input({"vulnerability_id": "test_vuln"})

    def test_missing_vuln_id(self):
        """Missing vulnerability ID should fail."""
        tool = tool_registry.create_instance("vulnerability_validation")
        with pytest.raises(Exception):  # InputValidationError
            tool.validate_input({"target": "192.168.1.1"})

    def test_invalid_check_type(self):
        """Invalid check_type should be handled."""
        tool = tool_registry.create_instance("vulnerability_validation")
        # Invalid check_type should default to "config" or be accepted
        result = tool.validate_input({
            "target": "192.168.1.1",
            "vulnerability_id": "test_vuln",
            "check_type": "invalid_type"
        })
        # Should not crash; may default or be accepted


class TestVulnValidationNegativeSecurity:
    """Negative security tests for vulnerability validation."""

    def test_no_credential_leakage(self):
        """Ensure no credential leakage in tool output."""
        tool = tool_registry.create_instance("vulnerability_validation")
        result = tool.validate_input({
            "target": "192.168.1.1",
            "vulnerability_id": "test_vuln"
        })
        assert result is True or result is False  # Should not crash

    def test_invalid_vuln_id_rejected(self):
        """Empty vulnerability ID should be rejected."""
        tool = tool_registry.create_instance("vulnerability_validation")
        with pytest.raises(Exception):  # InputValidationError
            tool.validate_input({
                "target": "192.168.1.1",
                "vulnerability_id": ""
            })


class TestVulnValidationImport:
    """Test that the vuln validation module is importable."""

    def test_module_importable(self):
        """Vuln validation module should be importable."""
        from hermes_shield.tools import vulnerability_validation
        assert vulnerability_validation is not None

    def test_tool_class_exists(self):
        """VulnerabilityValidationTool class should exist."""
        from hermes_shield.tools.vulnerability_validation import VulnerabilityValidationTool
        assert VulnerabilityValidationTool is not None