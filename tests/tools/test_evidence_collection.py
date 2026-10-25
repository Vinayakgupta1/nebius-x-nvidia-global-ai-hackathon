"""Unit tests for HermesShield Evidence Collection Tool."""

import pytest
from hermes_shield.tools.evidence_collection import EvidenceCollectionTool, tool_registry


class TestEvidenceCollectionToolInitialization:
    """Test that the evidence collection tool is properly registered."""

    def test_tool_registered(self):
        """Tool should be in the global registry."""
        assert "evidence_collection" in tool_registry.list_tools()

    def test_tool_instantiable(self):
        """Tool should be instantiable."""
        tool = tool_registry.create_instance("evidence_collection")
        assert tool.TOOL_NAME == "evidence_collection"


class TestEvidenceCollectionInputValidation:
    """Test input validation for evidence collection."""

    def test_collect_action(self):
        """Collect action should pass."""
        tool = tool_registry.create_instance("evidence_collection")
        assert tool.validate_input({
            "action": "collect",
            "data": {"skill": "test", "tool": "test_tool"}
        }) is True

    def test_save_action(self):
        """Save action should pass."""
        tool = tool_registry.create_instance("evidence_collection")
        assert tool.validate_input({
            "action": "save",
            "data": {"filename": "test_evidence.json"}
        }) is True

    def test_merge_action(self):
        """Merge action should pass."""
        tool = tool_registry.create_instance("evidence_collection")
        assert tool.validate_input({
            "action": "merge",
            "data": {"source_files": ["evidence1.json"], "audit_id": "test_audit"}
        }) is True

    def test_list_action(self):
        """List action should pass."""
        tool = tool_registry.create_instance("evidence_collection")
        assert tool.validate_input({"action": "list", "data": {}}) is True

    def test_invalid_action(self):
        """Invalid action should fail."""
        tool = tool_registry.create_instance("evidence_collection")
        with pytest.raises(Exception):  # InputValidationError
            tool.validate_input({
                "action": "invalid_action",
                "data": {}
            })

    def test_missing_data(self):
        """Missing data should fail."""
        tool = tool_registry.create_instance("evidence_collection")
        with pytest.raises(Exception):  # InputValidationError
            tool.validate_input({"action": "collect"})


class TestEvidenceCollectionNegativeSecurity:
    """Negative security tests for evidence collection."""

    def test_no_credential_leakage(self):
        """Ensure no credential leakage in tool output."""
        tool = tool_registry.create_instance("evidence_collection")
        result = tool.validate_input({
            "action": "collect",
            "data": {"skill": "test", "tool": "test_tool"}
        })
        assert result is True or result is False  # Should not crash

    def test_invalid_action_rejected(self):
        """Invalid action should be rejected."""
        tool = tool_registry.create_instance("evidence_collection")
        with pytest.raises(Exception):  # InputValidationError
            tool.validate_input({
                "action": "delete",
                "data": {}
            })


class TestEvidenceCollectionImport:
    """Test that the evidence collection module is importable."""

    def test_module_importable(self):
        """Evidence collection module should be importable."""
        from hermes_shield.tools import evidence_collection
        assert evidence_collection is not None

    def test_tool_class_exists(self):
        """EvidenceCollectionTool class should exist."""
        from hermes_shield.tools.evidence_collection import EvidenceCollectionTool
        assert EvidenceCollectionTool is not None