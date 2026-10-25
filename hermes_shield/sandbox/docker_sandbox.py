"""
HermesShield Docker Sandbox Abstraction.

Provides reproducible sandbox state management for security testing using Docker.
Implements what IS available, marks what is NOT IMPLEMENTED.
"""

import json
import logging
import os
import subprocess
import tarfile
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from hermes_shield.tools import ToolResult

logger = logging.getLogger(__name__)


class SandboxState:
    """Represents the state of a sandbox at a point in time."""
    
    def __init__(self, snapshot_id: str, container_id: str, image_id: str):
        self.snapshot_id = snapshot_id
        self.container_id = container_id
        self.image_id = image_id
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.filesystem_snapshot: Optional[str] = None  # Path to exported tar
        self.image_snapshot: Optional[str] = None  # Path to saved image
        self.metadata: Dict[str, Any] = {}
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "container_id": self.container_id,
            "image_id": self.image_id,
            "created_at": self.created_at,
            "filesystem_snapshot": self.filesystem_snapshot,
            "image_snapshot": self.image_snapshot,
            "metadata": self.metadata
        }


class DockerSandbox:
    """
    Docker-based sandbox for reproducible security testing.
    
    IMPLEMENTED capabilities:
    - create(): Create new sandbox container from base image
    - snapshot(): Save container state via docker commit + docker save
    - execute(): Execute commands in sandbox
    - inspect(): Compare current state with baseline
    - rollback(): Restore from snapshot (via docker load + new container)
    - verify_clean(): Verify no persistent changes
    
    NOT IMPLEMENTED (requires Docker experimental features):
    - True checkpoint/restore (docker checkpoint create/restore)
    - Instant state restoration without container recreation
    - Live memory state capture/restore
    - Network state checkpoint/restore
    """
    
    def __init__(
        self,
        base_image: str = "alpine:latest",
        workdir: str = "/workspace",
        timeout: int = 300,
        allowed_env: Optional[List[str]] = None,
        network_mode: str = "none",
        read_only_root: bool = False,
        tmpfs_size: str = "512m"
    ):
        self.base_image = base_image
        self.workdir = workdir
        self.timeout = timeout
        self.allowed_env = allowed_env or ["PATH", "HOME", "TERM"]
        self.network_mode = network_mode
        self.read_only_root = read_only_root
        self.tmpfs_size = tmpfs_size
        
        self.container_id: Optional[str] = None
        self.container_name: Optional[str] = None
        self.image_id: Optional[str] = None
        self.snapshots: Dict[str, SandboxState] = {}
        self.baseline_snapshot: Optional[str] = None
        self._baseline_image_id: Optional[str] = None
        self._workspace: Path = Path(tempfile.gettempdir()) / "hermes_sandbox" / str(uuid.uuid4())
        self._workspace.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"DockerSandbox initialized with base_image={base_image}")
    
    def create(self) -> "DockerSandbox":
        """
        Create and start a new sandbox container.
        Returns self for chaining.
        """
        logger.info("Creating sandbox container")
        
        # Pull base image if needed
        self._pull_image(self.base_image)
        
        # Create container with security constraints
        cmd = [
            "docker", "run", "-d",
            "--name", f"hermes-sandbox-{uuid.uuid4().hex[:8]}",
            "--workdir", self.workdir,
            "--network", self.network_mode,
            "--tmpfs", f"{self.workdir}:size={self.tmpfs_size},exec,nosuid,nodev",
        ]
        
        if self.read_only_root:
            cmd.append("--read-only")
        
        # Environment filtering - don't pass host PATH to container
        for env in self.allowed_env:
            if env in os.environ and env.lower() != "path":
                cmd.extend(["-e", f"{env}={os.environ[env]}"])
        # Set a proper PATH for the container
        cmd.extend(["-e", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"])
        
        cmd.append(self.base_image)
        cmd.extend(["sleep", "1000000"])  # Keep container running (alpine sleep doesn't support 'infinity')
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to create container: {result.stderr}")
        
        self.container_id = result.stdout.strip()
        self.container_name = f"hermes-sandbox-{self.container_id[:12]}"
        
        # Get image ID
        result = subprocess.run(
            ["docker", "inspect", "--format={{.Image}}", self.container_id],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            self.image_id = result.stdout.strip()
        
        # Wait for container to be ready
        time.sleep(2)
        
        logger.info(f"Sandbox created: {self.container_id}")
        return self
    
    def snapshot(self, label: str = "manual") -> str:
        """
        Create a snapshot of current container state.
        
        Uses docker commit + docker save for state capture.
        Returns snapshot ID.
        
        NOTE: This creates a new image layer and saves it to disk.
        For true checkpoint/restore (instant state restore), see NOT IMPLEMENTED.
        """
        if not self.container_id:
            raise RuntimeError("No active container")
        
        snapshot_id = f"snap-{uuid.uuid4().hex[:12]}-{int(time.time())}"
        logger.info(f"Creating snapshot {snapshot_id}")
        
        # 1. Commit container changes to new image
        snapshot_image = f"hermes-snapshot-{snapshot_id}"
        result = subprocess.run(
            ["docker", "commit", self.container_id, snapshot_image],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to commit container: {result.stderr}")
        
        snapshot_image_id = result.stdout.strip()
        
        # 2. Save image to tarball for persistence
        snapshot_dir = self._workspace / "snapshots"
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        snapshot_path = snapshot_dir / f"{snapshot_id}.tar"
        
        result = subprocess.run(
            ["docker", "save", "-o", str(snapshot_path), snapshot_image],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to save image: {result.stderr}")
        
        # 3. Record snapshot metadata
        snapshot_state = SandboxState(
            snapshot_id=snapshot_id,
            container_id=self.container_id,
            image_id=snapshot_image_id
        )
        snapshot_state.image_snapshot = str(snapshot_path)
        snapshot_state.metadata = {
            "label": label,
            "base_image": self.base_image,
            "created_by": "docker_commit_save"
        }
        
        self.snapshots[snapshot_id] = snapshot_state
        
        if self.baseline_snapshot is None:
            self.baseline_snapshot = snapshot_id
            self._baseline_image_id = snapshot_image_id
            logger.info(f"Baseline snapshot set: {snapshot_id}")
        
        logger.info(f"Snapshot created: {snapshot_id} -> {snapshot_image_id}")
        return snapshot_id
    
    def execute(
        self,
        command: List[str],
        timeout: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
        workdir: Optional[str] = None
    ) -> ToolResult:
        """
        Execute command in sandbox container.
        """
        if not self.container_id:
            raise RuntimeError("No active container")
        
        timeout = timeout or self.timeout
        workdir = workdir or self.workdir
        
        # Build docker exec command
        cmd = ["docker", "exec", "-w", workdir]
        
        if env:
            for k, v in env.items():
                cmd.extend(["-e", f"{k}={v}"])
        
        cmd.append(self.container_id)
        cmd.extend(command)
        
        logger.debug(f"Executing: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return ToolResult(
                success=result.returncode == 0,
                tool_name="docker_exec",
                execution_time=0,  # Not measured
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                evidence={"command": " ".join(command), "workdir": workdir}
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                tool_name="docker_exec",
                execution_time=timeout,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                exit_code=-1,
                error="Timeout"
            )
        except Exception as e:
            logger.error(f"Execution error: {e}")
            return ToolResult(
                success=False,
                tool_name="docker_exec",
                execution_time=0,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                error=str(e)
            )
    
    def inspect(self, snapshot_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Inspect current state or compare with snapshot.
        Returns differences from baseline or specified snapshot.
        """
        if snapshot_id and snapshot_id in self.snapshots:
            baseline = self.snapshots[snapshot_id]
        elif self.baseline_snapshot and self.baseline_snapshot in self.snapshots:
            baseline = self.snapshots[self.baseline_snapshot]
        else:
            return {"error": "No baseline snapshot available"}
        
        # Get current container filesystem changes
        result = subprocess.run(
            ["docker", "diff", self.container_id],
            capture_output=True, text=True, timeout=30
        )
        
        changes = []
        for line in result.stdout.strip().split('\n'):
            if line:
                parts = line.split(' ', 1)
                if len(parts) == 2:
                    changes.append({"type": parts[0], "path": parts[1]})
        
        return {
            "baseline_snapshot": baseline.snapshot_id,
            "current_container": self.container_id,
            "filesystem_changes": changes,
            "change_count": len(changes),
            "inspected_at": datetime.now(timezone.utc).isoformat()
        }
    
    def rollback(self, snapshot_id: Optional[str] = None) -> bool:
        """
        Rollback to a previous snapshot.
        
        IMPLEMENTED: Loads snapshot image and creates new container.
        
        NOTE: This creates a NEW container from the snapshot image.
        The original container is stopped and removed.
        Process state (memory, open connections) is NOT preserved.
        
        For true checkpoint/restore with process state, see NOT IMPLEMENTED.
        """
        if snapshot_id is None:
            snapshot_id = self.baseline_snapshot
        
        if not snapshot_id or snapshot_id not in self.snapshots:
            raise ValueError(f"Snapshot not found: {snapshot_id}")
        
        snapshot = self.snapshots[snapshot_id]
        logger.info(f"Rolling back to snapshot: {snapshot_id}")
        
        # 1. Stop and remove current container
        if self.container_id:
            subprocess.run(["docker", "stop", self.container_id], timeout=30, capture_output=True)
            subprocess.run(["docker", "rm", self.container_id], timeout=30, capture_output=True)
        
        # 2. Load snapshot image if not present
        if snapshot.image_snapshot and os.path.exists(snapshot.image_snapshot):
            subprocess.run(
                ["docker", "load", "-i", snapshot.image_snapshot],
                capture_output=True, timeout=120
            )
        
        # 3. Create new container from snapshot image
        snapshot_image = f"hermes-snapshot-{snapshot.snapshot_id}"
        
        # Verify image exists
        result = subprocess.run(
            ["docker", "images", "-q", snapshot_image],
            capture_output=True, text=True, timeout=10
        )
        
        if not result.stdout.strip():
            # Load from saved tar
            if snapshot.image_snapshot and os.path.exists(snapshot.image_snapshot):
                result = subprocess.run(
                    ["docker", "load", "-i", snapshot.image_snapshot],
                    capture_output=True, text=True, timeout=120
                )
                if result.returncode != 0:
                    raise RuntimeError(f"Failed to load snapshot image: {result.stderr}")
        
        # 4. Create new container from snapshot
        cmd = [
            "docker", "run", "-d",
            "--name", f"hermes-sandbox-{uuid.uuid4().hex[:8]}",
            "--workdir", self.workdir,
            "--network", self.network_mode,
            "--tmpfs", f"{self.workdir}:size={self.tmpfs_size},exec,nosuid,nodev",
        ]
        
        if self.read_only_root:
            cmd.append("--read-only")
        
        for env in self.allowed_env:
            if env in os.environ:
                cmd.extend(["-e", f"{env}={os.environ[env]}"])
        
        cmd.append(snapshot_image)
        cmd.extend(["sleep", "1000000"])  # Keep container running (alpine sleep doesn't support 'infinity')
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to create rollback container: {result.stderr}")
        
        new_container_id = result.stdout.strip()
        
        # Update state
        old_container_id = self.container_id
        self.container_id = new_container_id
        self.image_id = snapshot.image_id
        
        logger.info(f"Rollback complete: {old_container_id} -> {self.container_id} from {snapshot_id}")
        return True
    
    def verify_clean(self) -> Dict[str, Any]:
        """
        Verify sandbox is clean (no unexpected changes from baseline).
        """
        if not self.baseline_snapshot:
            return {"clean": False, "reason": "No baseline snapshot"}
        
        inspection = self.inspect()
        
        # Check for unexpected changes
        changes = inspection.get("filesystem_changes", [])
        unexpected = [c for c in inspection["filesystem_changes"] 
                      if c["type"] in ("A", "C") and not c["path"].startswith("/tmp")]
        
        return {
            "clean": len(unexpected) == 0,
            "total_changes": len(changes),
            "unexpected_changes": unexpected,
            "baseline_snapshot": self.baseline_snapshot,
            "checked_at": datetime.now(timezone.utc).isoformat()
        }
    
    def _pull_image(self, image: str) -> None:
        """Pull Docker image if not present locally."""
        result = subprocess.run(
            ["docker", "images", "-q", image],
            capture_output=True, text=True, timeout=10
        )
        if not result.stdout.strip():
            logger.info(f"Pulling image: {image}")
            result = subprocess.run(
                ["docker", "pull", image],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode != 0:
                raise RuntimeError(f"Failed to pull image: {result.stderr}")
    
    def cleanup(self) -> None:
        """Clean up sandbox resources."""
        if self.container_id:
            logger.info(f"Cleaning up container {self.container_id}")
            subprocess.run(["docker", "stop", self.container_id], timeout=30, capture_output=True)
            subprocess.run(["docker", "rm", self.container_id], timeout=30, capture_output=True)
            self.container_id = None
            self.container_name = None
        
        # Clean up snapshot images
        for snapshot in self.snapshots.values():
            if snapshot.image_id:
                subprocess.run(
                    ["docker", "rmi", snapshot.image_id],
                    timeout=30, capture_output=True
                )
        
        # Clean up workspace
        import shutil
        if self._workspace.exists():
            shutil.rmtree(self._workspace, ignore_errors=True)
        
        logger.info("Sandbox cleanup complete")


# ============================================================================
# NOT IMPLEMENTED - Requires Docker experimental features (checkpoint/restore)
# ============================================================================

"""
NOT IMPLEMENTED - Requires Docker Experimental Features (--experimental=true)

The following capabilities require Docker experimental features (--experimental=true
on the daemon) which could not be reliably enabled in this environment:

1. docker checkpoint create <container> <checkpoint_name>
   - Creates a checkpoint of a running container's state (memory, disk, network)
   
2. docker checkpoint ls <container>
   - Lists checkpoints for a container

3. docker checkpoint rm <container> <checkpoint>
   - Removes a checkpoint
   
4. docker start --checkpoint <checkpoint> <container>
   - Restores container from checkpoint with full process state
   
3. docker checkpoint create --leave-running <container> <checkpoint>
   - Creates checkpoint without stopping container

CAPABILITIES THAT WOULD BE ENABLED WITH EXPERIMENTAL FEATURES:
- Instant state restoration (sub-second) with full process memory
- Live migration of running containers
- Forensic analysis of running process memory
- Seamless rollback without container recreation

CURRENT WORKAROUND (IMPLEMENTED):
- docker commit + docker save/load for filesystem state
- Process state (memory, open sockets) NOT preserved
- Requires container recreation on rollback (seconds vs milliseconds)
- Network connections, open file handles, process memory NOT restored

STATUS: NOT IMPLEMENTED - Docker experimental features could not be reliably enabled
"""

if __name__ == "__main__":
    # Demo
    sandbox = DockerSandbox(base_image="alpine:latest", network_mode="none")
    try:
        sandbox.create()
        print(f"Created sandbox: {sandbox.container_id}")
        
        # Test execution
        result = sandbox.execute(["sh", "-c", "echo hello from sandbox"])
        print(f"Execution result: {result.success}, stdout: {result.stdout}")
        
        # Create snapshot
        snap_id = sandbox.snapshot("baseline")
        print(f"Created snapshot: {snap_id}")
        
        # Make some changes
        sandbox.execute(["sh", "-c", "echo 'test' > /tmp/test.txt"])
        
        # Inspect changes
        changes = sandbox.inspect()
        print(f"Changes detected: {changes['change_count']}")
        
        # Rollback
        sandbox.rollback()
        print("Rollback completed")
        
        # Verify clean
        clean = sandbox.verify_clean()
        print(f"Clean: {clean}")
        
    finally:
        sandbox.cleanup()