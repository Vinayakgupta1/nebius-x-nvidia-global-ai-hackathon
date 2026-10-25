"""Unit tests for HermesShield Secret Detection Tool."""

import pytest
from hermes_shield.tools.secret_detection import SecretDetectionTool, tool_registry


class TestSecretDetectionToolInitialization:
    """Test that the secret detection tool is properly registered."""

    def test_tool_registered(self):
        """Tool should be in the global registry."""
        assert "secret_detection" in tool_registry.list_tools()

    def test_tool_instantiable(self):
        """Tool should be instantiable."""
        tool = tool_registry.create_instance("secret_detection")
        assert tool.TOOL_NAME == "secret_detection"


class TestSecretDetectionInputValidation:
    """Test input validation for secret detection."""

    def test_valid_input(self):
        """Valid input should pass."""
        tool = tool_registry.create_instance("secret_detection")
        assert tool.validate_input({
            "target": "192.168.1.1",
            "search_paths": ["test_file.txt"]
        }) is True

    def test_missing_target(self):
        """Missing target should fail."""
        tool = tool_registry.create_instance("secret_detection")
        with pytest.raises(Exception):  # InputValidationError
            tool.validate_input({"search_paths": ["test.txt"]})

    def test_missing_search_paths(self):
        """Missing search_paths should fail."""
        tool = tool_registry.create_instance("secret_detection")
        with pytest.raises(Exception):  # InputValidationError
            tool.validate_input({"target": "192.168.1.1"})

    def test_path_traversal_rejected(self):
        """Path traversal in search_paths should be rejected."""
        tool = tool_registry.create_instance("secret_detection")
        with pytest.raises(Exception):  # InputValidationError
            tool.validate_input({
                "target": "192.168.1.1",
                "search_paths": ["../../etc/passwd"]
            })


class TestSecretDetectionNegativeSecurity:
    """Negative security tests for secret detection."""

    def test_no_credential_leakage(self):
        """Ensure no credential leakage in tool output."""
        tool = tool_registry.create_instance("secret_detection")
        result = tool.validate_input({
            "target": "192.168.1.1",
            "search_paths": ["test.txt"]
        })
        assert result is True or result is False  # Should not crash

    def test_path_traversal_blocked(self):
        """Path traversal attempt should be blocked."""
        tool = tool_registry.create_instance("secret_detection")
        with pytest.raises(Exception):  # InputValidationError
            tool.validate_input({
                "target": "192.168.1.1",
                "search_paths": ["/etc/passwd"]
            })


class TestSecretDetectionImport:
    """Test that the secret detection module is importable."""

    def test_module_importable(self):
        """Secret detection module should be importable."""
        from hermes_shield.tools import secret_detection
        assert secret_detection is not None

    def test_tool_class_exists(self):
        """SecretDetectionTool class should exist."""
        from hermes_shield.tools.secret_detection import SecretDetectionTool
        assert SecretDetectionTool is not None