"""Tests for HermesShield Docker Sandbox."""

import pytest
import tempfile
import json
import os
import sys
import time

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from hermes_shield.sandbox import DockerSandbox, SandboxState


class TestSandboxCreation:
    """Tests for sandbox creation and lifecycle."""

    def test_create_sandbox(self):
        """Test sandbox creation and cleanup."""
        sandbox = DockerSandbox(base_image="alpine:latest")
        sandbox.create()
        
        assert sandbox.container_id is not None
        assert sandbox.container_id != ""
        assert sandbox.image_id is not None
        
        sandbox.cleanup()
        assert sandbox.container_id is None

    def test_create_with_custom_image(self):
        """Test sandbox creation with custom image."""
        sandbox = DockerSandbox(base_image="alpine:latest")
        sandbox.create()
        
        assert sandbox.base_image == "alpine:latest"
        sandbox.cleanup()


class TestSandboxExecution:
    """Tests for command execution in sandbox."""

    @pytest.fixture
    def sandbox(self):
        sandbox = DockerSandbox(base_image="alpine:latest", network_mode="none")
        sandbox.create()
        yield sandbox
        sandbox.cleanup()

    def test_execute_simple_command(self, sandbox):
        """Test executing a simple command."""
        result = sandbox.execute(["sh", "-c", "echo hello"])
        
        assert result.success is True
        assert "hello" in result.stdout
        assert result.exit_code == 0

    def test_execute_with_workdir(self, sandbox):
        """Test execution with custom working directory."""
        result = sandbox.execute(["pwd"], workdir="/tmp")
        
        assert result.success is True
        assert "/tmp" in result.stdout

    def test_execute_with_env(self, sandbox):
        """Test execution with environment variables."""
        result = sandbox.execute(
            ["sh", "-c", "echo $TEST_VAR"],
            env={"TEST_VAR": "test_value"}
        )
        
        assert result.success is True
        assert "test_value" in result.stdout

    def test_execute_timeout(self, sandbox):
        """Test command timeout enforcement."""
        result = sandbox.execute(["sleep", "10"], timeout=1)
        
        assert result.success is False
        assert result.exit_code == -1
        assert "timed out" in result.stderr.lower()

    def test_execute_failure(self, sandbox):
        """Test command failure handling."""
        result = sandbox.execute(["sh", "-c", "exit 42"])
        
        assert result.success is False
        assert result.exit_code == 42


class TestSandboxSnapshots:
    """Tests for snapshot creation and management."""

    @pytest.fixture
    def sandbox(self):
        sandbox = DockerSandbox(base_image="alpine:latest", network_mode="none")
        sandbox.create()
        yield sandbox
        sandbox.cleanup()

    def test_create_snapshot(self, sandbox):
        """Test creating a snapshot."""
        snapshot_id = sandbox.snapshot("test-label")
        
        assert snapshot_id is not None
        assert snapshot_id.startswith("snap-")
        assert snapshot_id in sandbox.snapshots
        
        snapshot = sandbox.snapshots[snapshot_id]
        assert snapshot.label == "test-label"
        assert snapshot.image_snapshot is not None
        assert os.path.exists(snapshot.image_snapshot)

    def test_baseline_snapshot(self, sandbox):
        """Test that first snapshot becomes baseline."""
        snap1 = sandbox.snapshot("first")
        snap2 = sandbox.snapshot("second")
        
        assert sandbox.baseline_snapshot == snap1
        assert sandbox.baseline_snapshot != snap2

    def test_multiple_snapshots(self, sandbox):
        """Test creating multiple snapshots."""
        ids = []
        for i in range(3):
            snap_id = sandbox.snapshot(f"snap-{i}")
            ids.append(snap_id)
        
        assert len(sandbox.snapshots) == 3
        assert len(set(ids)) == 3  # All unique


class TestSandboxExecution:
    """Tests for command execution and state changes."""

    @pytest.fixture
    def sandbox(self):
        sandbox = DockerSandbox(base_image="alpine:latest", network_mode="none")
        sandbox.create()
        yield sandbox
        sandbox.cleanup()

    def test_filesystem_changes_detected(self, sandbox):
        """Test that filesystem changes are detected."""
        # Create baseline
        sandbox.snapshot("baseline")
        
        # Make changes
        sandbox.execute(["sh", "-c", "echo test > /tmp/test.txt"])
        sandbox.execute(["mkdir", "/tmp/testdir"])
        
        # Inspect changes
        changes = sandbox.inspect()
        
        assert changes["change_count"] >= 2
        paths = [c["path"] for c in changes["filesystem_changes"]]
        assert "/tmp/test.txt" in paths
        assert "/tmp/testdir" in paths

    def test_file_modification_detected(self, sandbox):
        """Test that file modifications are detected."""
        sandbox.snapshot("baseline")
        
        sandbox.execute(["sh", "-c", "echo original > /tmp/file.txt"])
        sandbox.snapshot("after-create")
        
        sandbox.execute(["sh", "-c", "echo modified > /tmp/file.txt"])
        
        changes = sandbox.inspect()
        
        # Should detect modification
        modified = [c for c in changes["filesystem_changes"] 
                    if c["type"] == "C" and "file.txt" in c["path"]]
        assert len(modified) > 0

    def test_file_deletion_detected(self, sandbox):
        """Test that file deletions are detected."""
        sandbox.snapshot("baseline")
        
        sandbox.execute(["sh", "-c", "echo test > /tmp/todelete.txt"])
        sandbox.snapshot("after-create")
        
        sandbox.execute(["rm", "/tmp/todelete.txt"])
        
        changes = sandbox.inspect()
        
        deleted = [c for c in changes["filesystem_changes"] 
                   if c["type"] == "D" and "todelete.txt" in c["path"]]
        assert len(deleted) > 0


class TestSandboxRollback:
    """Tests for rollback functionality."""

    @pytest.fixture
    def sandbox(self):
        sandbox = DockerSandbox(base_image="alpine:latest", network_mode="none")
        sandbox.create()
        yield sandbox
        sandbox.cleanup()

    def test_rollback_to_baseline(self, sandbox):
        """Test rollback to baseline snapshot."""
        sandbox.snapshot("baseline")
        
        # Make changes
        sandbox.execute(["sh", "-c", "echo test > /tmp/test.txt"])
        
        # Verify change exists
        result = sandbox.execute(["ls", "/tmp/test.txt"])
        assert result.success is True
        
        # Rollback
        sandbox.rollback()
        
        # Verify file is gone
        result = sandbox.execute(["ls", "/tmp/test.txt"])
        assert result.success is False

    def test_rollback_to_specific_snapshot(self, sandbox):
        """Test rollback to specific snapshot."""
        snap1 = sandbox.snapshot("snap1")
        
        sandbox.execute(["sh", "-c", "echo step1 > /tmp/step1.txt"])
        snap2 = sandbox.snapshot("snap2")
        
        sandbox.execute(["sh", "-c", "echo step2 > /tmp/step2.txt"])
        
        # Rollback to snap1
        sandbox.rollback(snap1)
        
        # Verify step2 is gone, step1 exists
        result1 = sandbox.execute(["ls", "/tmp/step1.txt"])
        result2 = sandbox.execute(["ls", "/tmp/step2.txt"])
        
        assert result1.success is True
        assert result2.success is False

    def test_rollback_creates_new_container(self, sandbox):
        """Test that rollback creates new container."""
        sandbox.snapshot("baseline")
        
        old_container = sandbox.container_id
        sandbox.rollback()
        
        new_container = sandbox.container_id
        assert new_container != old_container


class TestSandboxVerification:
    """Tests for cleanliness verification."""

    @pytest.fixture
    def sandbox(self):
        sandbox = DockerSandbox(base_image="alpine:latest", network_mode="none")
        sandbox.create()
        yield sandbox
        sandbox.cleanup()

    def test_verify_clean_baseline(self, sandbox):
        """Test clean verification with no changes."""
        sandbox.snapshot("baseline")
        
        clean = sandbox.verify_clean()
        
        assert clean["clean"] is True
        assert clean["total_changes"] == 0
        assert len(clean["unexpected_changes"]) == 0

    def test_verify_dirty_after_changes(self, sandbox):
        """Test dirty detection after changes."""
        sandbox.snapshot("baseline")
        
        sandbox.execute(["sh", "-c", "echo test > /tmp/test.txt"])
        
        clean = sandbox.verify_clean()
        
        assert clean["clean"] is False
        assert clean["total_changes"] > 0

    def test_verify_ignores_tmp(self, sandbox):
        """Test that /tmp changes are ignored by default."""
        sandbox.snapshot("baseline")
        
        sandbox.execute(["sh", "-c", "echo test > /tmp/test.txt"])
        
        clean = sandbox.verify_clean()
        
        # /tmp changes should be ignored
        assert clean["clean"] is True


class TestSandboxInspection:
    """Tests for state inspection."""

    @pytest.fixture
    def sandbox(self):
        sandbox = DockerSandbox(base_image="alpine:latest", network_mode="none")
        sandbox.create()
        yield sandbox
        sandbox.cleanup()

    def test_inspect_without_baseline(self, sandbox):
        """Test inspect without baseline returns error."""
        result = sandbox.inspect()
        
        assert "error" in result

    def test_inspect_with_baseline(self, sandbox):
        """Test inspect with baseline."""
        sandbox.snapshot("baseline")
        
        sandbox.execute(["sh", "-c", "echo test > /tmp/test.txt"])
        
        result = sandbox.inspect()
        
        assert "filesystem_changes" in result
        assert result["change_count"] >= 1
        assert result["baseline_snapshot"] is not None


class TestSandboxSecurity:
    """Tests for security boundaries."""

    def test_network_isolation(self):
        """Test network isolation."""
        sandbox = DockerSandbox(base_image="alpine:latest", network_mode="none")
        sandbox.create()
        
        # Should not be able to reach external network
        result = sandbox.execute(["wget", "-q", "--spider", "http://google.com"], timeout=5)
        
        # Should fail due to network isolation
        assert result.success is False
        
        sandbox.cleanup()

    def test_read_only_root(self):
        """Test read-only root filesystem."""
        sandbox = DockerSandbox(base_image="alpine:latest", read_only_root=True)
        sandbox.create()
        
        # Should not be able to write to root
        result = sandbox.execute(["sh", "-c", "touch /test.txt"])
        
        assert result.success is False
        
        sandbox.cleanup()

    def test_network_isolation_blocks_external(self):
        """Test network isolation blocks external connections."""
        sandbox = DockerSandbox(base_image="alpine:latest", network_mode="none")
        sandbox.create()
        
        # Should not be able to resolve external hosts
        result = sandbox.execute(["nslookup", "google.com"], timeout=5)
        
        # Should fail due to no network
        assert result.success is False
        
        sandbox.cleanup()

    def test_environment_filtering(self):
        """Test that only allowed env vars are passed."""
        sandbox = DockerSandbox(
            base_image="alpine:latest",
            network_mode="none",
            allowed_env=["PATH", "HOME", "CUSTOM_VAR"]
        )
        sandbox.create()
        
        # Set a test env var
        result = sandbox.execute(
            ["sh", "-c", "echo $CUSTOM_VAR"],
            env={"CUSTOM_VAR": "test_value", "SECRET_KEY": "should_not_pass"}
        )
        
        assert result.success is True
        assert "test_value" in result.stdout
        
        # SECRET_KEY should not be passed
        # (We can't easily test this without knowing what's in the env)
        
        sandbox.cleanup()


class TestSandboxPersistence:
    """Tests for cross-session persistence."""

    def test_snapshot_persistence(self):
        """Test that snapshots persist across sandbox instances."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Session 1
            sandbox1 = DockerSandbox(
                base_image="alpine:latest",
                network_mode="none"
            )
            sandbox1.create()
            
            snap_id = sandbox1.snapshot("test-snapshot")
            sandbox1.cleanup()
            
            # New sandbox instance with same target
            sandbox2 = DockerSandbox(
                base_image="alpine:latest",
                network_mode="none"
            )
            sandbox2.create()
            
            # Should be able to rollback to snapshot
            # (In practice, would need shared storage - this test documents expected behavior)
            sandbox2.cleanup()

    def test_session_isolation(self):
        """Test that different targets have isolated memory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox_a = DockerSandbox(
                target="192.168.1.1",
                base_image="alpine:latest",
                network_mode="none"
            )
            sandbox_a.create()
            sandbox_a.record_finding("Target A Finding", "Test", "LOW", [])
            
            snapshot_a = snapshot_a.snapshot("snap_a")
            sandbox_a.cleanup()
            
            # Different target
            sandbox_b = DockerSandbox(
                target="192.168.1.2",
                base_image="alpine:latest",
                network_mode="none"
            )
            sandbox_b.create()
            
            snapshots_b = sandbox_b.get_by_category("findings")
            assert len(snapshots_b) == 0
            
            sandbox_b.cleanup()


class TestSandboxState:
    """Tests for SandboxState dataclass."""

    def test_state_creation(self):
        state = SandboxState(
            snapshot_id="snap-123",
            container_id="container-123",
            image_id="sha256:abc123"
        )
        
        assert state.snapshot_id == "snap-123"
        assert state.container_id == "container-123"
        assert state.image_id == "sha256:abc123"
        assert state.state == "HYPOTHESIS"  # Default

    def test_state_serialization(self):
        state = SandboxState(
            snapshot_id="snap-123",
            container_id="container-123",
            image_id="sha256:abc123"
        )
        
        d = state.to_dict()
        assert d["snapshot_id"] == "snap-123"
        assert d["category"] == "findings"
        assert d["state"] == "HYPOTHESIS"
        
        restored = SandboxState.from_dict(d)
        assert restored.snapshot_id == "snap-123"


class TestSandboxStateTransitions:
    """Test state transitions."""

    def test_snapshot_state_defaults(self):
        state = SandboxState(
            snapshot_id="test",
            container_id="container",
            image_id="image"
        )
        
        assert state.state == "HYPOTHESIS"
        assert state.confidence == 0.5
        assert state.revalidation_required is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])