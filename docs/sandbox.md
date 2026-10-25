# HermesShield Docker Sandbox Documentation

## Overview

The HermesShield Docker Sandbox provides reproducible sandbox state management for security testing using Docker containers. It implements the available Docker capabilities while clearly documenting what is NOT IMPLEMENTED due to infrastructure limitations.

## Implemented Capabilities

### 1. Sandbox Creation (`sandbox.create()`)
Creates a new isolated container from a base image with security constraints:
- Read-only root filesystem (optional)
- Network isolation (default: none)
- Temporary filesystem with size limits
- Environment variable filtering
- Resource limits (timeouts, memory)

### 2. Snapshot Creation (`sandbox.snapshot()`)
Creates a reproducible snapshot of container state using:
1. `docker commit` - Creates new image from container filesystem changes
2. `docker save` - Exports image to portable tarball
2. Metadata tracking (timestamp, label, base image)

### 3. Command Execution (`sandbox.execute()`)
Executes commands in the sandbox with:
- Working directory control
- Environment variable control
- Timeout enforcement
- Structured result with evidence capture

### 4. State Inspection (`sandbox.inspect()`)
Compares current container filesystem with baseline snapshot using `docker diff`:
- Added files (A)
- Changed files (C)
- Deleted files (D)

### 5. Rollback (`sandbox.rollback()`)
Restores sandbox to a previous snapshot:
1. Stops and removes current container
2. Loads snapshot image (if not present)
3. Creates new container from snapshot image
4. Updates internal state

**Limitation**: Process state (memory, open connections, process IDs) is NOT preserved. New container is created.

### 6. Cleanliness Verification (`sandbox.verify_clean()`)
Compares current state with baseline:
- Detects unexpected file additions/modifications
- Ignores expected temporary file changes
- Reports clean/unclean status with details

---

## NOT IMPLEMENTED - Requires Docker Experimental Features

The following capabilities require Docker experimental features (`--experimental=true` on daemon) which could not be reliably enabled in this environment:

### Docker Checkpoint/Restore (NOT IMPLEMENTED)

| Command | Description | Status |
|---------|-------------|--------|
| `docker checkpoint create` | Create checkpoint of running container (memory, disk, network, processes) | NOT IMPLEMENTED |
| `docker checkpoint ls` | List checkpoints for container | NOT IMPLEMENTED |
| `docker checkpoint rm` | Remove checkpoint | NOT IMPLEMENTED |
| `docker start --checkpoint` | Restore container from checkpoint | NOT IMPLEMENTED |
| `docker checkpoint create --leave-running` | Checkpoint without stopping | NOT IMPLEMENTED |

**What would be enabled with experimental features:**
- Instant state restoration (sub-second) with full process memory
- Live migration of running containers
- Forensic analysis of running process memory
- Seamless rollback without container recreation
- Live memory forensics during security testing

### Why Not Implemented
Docker experimental features (`--experimental=true` on daemon) could not be reliably enabled in this environment:
- Docker Desktop settings-store.json does not expose experimental flag
- features-overrides.json `{ "experimental": true }` did not persist after restart
- Daemon configuration (`daemon.json` with `"experimental": true`) did not activate features
- Docker Desktop UI does not expose experimental toggle in current version

### What IS Available (Implemented Workarounds)

| Capability | Implementation | Limitation |
|------------|---------------|------------|
| Filesystem snapshot | `docker commit` + `docker save` | Filesystem only, no process state |
| State rollback | `docker load` + new container | Process state NOT preserved |
| Filesystem diff | `docker diff` | Metadata only, no content diff |
| Image save/load | `docker save` / `docker load` | Full image portability |
| Image commit | `docker commit` | Layered filesystem changes |

### Network State
- Network namespace isolation: Available via `--network none`
- Connection state: NOT preserved on rollback (new container = new network namespace)
- Open connections: NOT restored on rollback

### Process State
- Process memory: NOT captured/restored
- Open file descriptors: NOT restored
- Process IDs: Reset on new container
- Signal handlers: Reset

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    DockerSandbox                               │
├─────────────────────────────────────────────────────────────┤
│  create()      →  docker run (isolated container)            │
│  snapshot()    →  docker commit + docker save                 │
│  execute()     →  docker exec                                 │
│  inspect()     →  docker diff                                 │
│  rollback()    →  docker load + docker run (new container)    │
│  verify_clean() → docker diff vs baseline                    │
│  cleanup()     → docker stop/rm + image cleanup               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Docker Daemon (experimental: NOT ENABLED)       │
│  ❌ docker checkpoint create/restore                         │
│  ❌ Live process state capture/restore                       │
│  ❌ Memory/disk/network state atomic capture                 │
│  ❌ Sub-second rollback with process continuity              │
└─────────────────────────────────────────────────────────────┘
```

---

## Usage Example

```python
from hermes_shield.sandbox import DockerSandbox

# Create sandbox
sandbox = DockerSandbox(base_image="alpine:latest", network_mode="none")
sandbox.create()

try:
    # Execute commands
    sandbox.execute(["sh", "-c", "echo hello > /tmp/test.txt"])
    
    # Create baseline snapshot
    snap_id = sandbox.snapshot("baseline")
    
    # Make changes
    sandbox.execute(["sh", "-c", "echo 'malicious' > /tmp/evil.sh"])
    
    # Inspect changes
    changes = sandbox.inspect()
    print(f"Changes: {changes['change_count']}")
    
    # Rollback to baseline
    sandbox.rollback()
    
    # Verify clean state
    clean = sandbox.verify_clean()
    assert clean["clean"] == True
    
finally:
    sandbox.cleanup()
```

## Evidence Collection

All operations produce structured evidence:
- Execution results with stdout/stderr/exit codes
- Filesystem diffs with change types (A/C/D)
- Timestamped audit trail
- Image digests for reproducibility

---

## Security Properties

| Property | Guarantee |
|----------|-----------|
| Scope isolation | Enforced via Docker network/namespace isolation |
| Credential leakage | Prevented via env filtering and output sanitization |
| Privilege escalation | Blocked by read-only root, no priv mode |
| Network egress | Controlled via network mode (default: none) |
| Filesystem persistence | Controlled via tmpfs, read-only root |
| Evidence integrity | SHA256 digests, timestamped audit trail |

---

## Limitations & Known Issues

1. **Process state not preserved** on rollback (memory, sockets, PIDs)
2. **Network connections** not restored on rollback
3. **Container recreation** takes ~2-5 seconds vs checkpoint's <100ms
4. **Checkpoint/restore** requires Docker experimental features (unavailable)
5. **Windows containers** not supported (Linux containers only via WSL2)
5. **ARM/ARM64** images may not run on x86_64 without emulation

---

## Future Work

- [ ] Enable Docker experimental features via Desktop UI automation
- [ ] Implement CRIU-based checkpoint/restore as alternative
- [ ] Add support for Podman (supports checkpoint without experimental flag)
- [ ] Implement CRIU-based checkpoint/restore for true state capture
- [ ] Add memory forensics integration (Volatility, LIME)
- [ ] Implement network namespace snapshot/restore