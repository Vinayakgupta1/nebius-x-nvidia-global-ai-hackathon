# Oracle Cloud Deployment Plan for HermesShield

## Overview

This document provides a comprehensive step-by-step deployment plan for the HermesShield autonomous security auditing framework on Oracle Cloud Free Tier using Docker containers and Cloudflare Tunnel for secure public access.

---

## 🔍 Project Security Audit Summary

### Current Project Status
- **34/34 tests passing** (100% success rate)
- **Attack Path Correlation**: 11/11 passing (fixed `claim_status.value` comparison)
- **Security-Boundary Tests**: 6/6 passing
- **Adversarial Security**: 17/17 passing
- **Web Dashboard**: `index.html` redesigned with responsive layout
- **Benchmark**: Synthetic lab with 10 vulnerabilities (BENCH-001 to BENCH-010)

### Critical Weaknesses Identified

| # | Weakness | Risk Level | Location |
|---|----------|------------|----------|
| 1 | Benchmark Dockerfile exposes all services | CRITICAL | `benchmark/lab/Dockerfile` - ports 22, 8080, 5432, 445, 443 all EXPOSED |
| 2 | Hardcoded SSH private key in image | CRITICAL | `echo -e "-----BEGIN RSA PRIVATE KEY-----...` baked into Docker image |
| 3 | PostgreSQL with default credentials | CRITICAL | `postgres:postgres` password set, listen_addresses='*', pg_hba.conf allows 0.0.0.0/0 |
| 4 | Sudo NOPASSWD for www-data | CRITICAL | `www-data ALL=(ALL) NOPASSWD: ALL` in sudoers.d |
| 5 | World-writable cron script | CRITICAL | `/opt/scripts/backup.sh` chmod 777, owned by www-data |
| 6 | SMB anonymous access | CRITICAL | Samba `guest ok = yes`, public/backup shares |
| 7 | Weak SSL/TLS self-signed cert | HIGH | RSA 2048 self-signed, CN=localhost only |
| 8 | Docker socket not configured | MEDIUM | Reference to `/var/run/docker.sock` but not mounted in lab |
| 9 | No `.env` file for API keys | MEDIUM | `.env.example` exists but not utilized in deployment |
| 10 | SSH configured with root login | HIGH | `PermitRootLogin yes` in benchmark setup |

---

## 📋 Step-by-Step Deployment Plan

### Phase 1: Preparation (Before Cloud Deployment)

#### Step 1: Create Proper `.env` File
```bash
cd D:/Project/HermesShield
cp .env.example .env
# Edit .env with your configuration
NEBIUS_API_KEY=your_nebius_key_here  # Optional, for AI features
HERMES_AUDIT_ROOT=./audit_data
TOOL_COMMAND_TIMEOUT=60
TOOL_OUTPUT_SIZE_LIMIT=1048576
LOG_LEVEL=INFO
AUDIT_ID_PREFIX=hermes_
```

#### Step 2: Build the Application Docker Image
Since there's no root-level `Dockerfile`, create one for your HermesShield application:

```dockerfile
# Dockerfile for HermesShield application
FROM python:3.11-slim

# Create non-root user
RUN adduser -D -s /bin/sh appuser

# Set working directory
WORKDIR /app

# Copy only requirements first (for layer caching)
COPY hermes_shield/ /app/hermes_shield/
COPY scripts/ /app/scripts/
COPY benchmark/ /app/benchmark/
COPY .env /app/.env

# Install dependencies
RUN pip install --no-cache-dir hermes_shield

# Switch to non-root user
USER appuser

# Expose only what's needed (internal only)
EXPOSE 8080

# Default command
CMD ["python", "-m", "hermes_shield.agent:main"]
```

#### Step 3: Create docker-compose.yml
```yaml
version: '3.8'

services:
  hermesshield:
    build: .
    container_name: hermesshield
    restart: unless-stopped
    environment:
      - NEBIUS_API_KEY=${NEBIUS_API_KEY}
      - HERMES_AUDIT_ROOT=/data
      - TOOL_COMMAND_TIMEOUT=60
      - LOG_LEVEL=INFO
    # Critical: Do NOT publish ports externally - use Cloudflare Tunnel only
    # ports:
    #   - "127.0.0.1:8080:8080"  # REMOVE or comment out
    volumes:
      - ./audit_data:/data:rw  # Audit data volume
    # Critical: No Docker socket mount
    # - /var/run/docker.sock:/var/run/docker.sock  # REMOVE
```

#### Step 4: Remove Vulnerable Benchmark Components
The benchmark Dockerfile has intentional vulnerabilities. For production:
- Remove hardcoded SSH key setup
- Remove default PostgreSQL credentials
- Remove `PermitRootLogin yes`
- Remove `NOPASSWD` sudo entries
- Remove world-writable scripts
- Remove SMB anonymous access
- Fix SSL/TLS configuration

---

### Phase 2: Cloud Server Deployment

#### Step 5: Provision Oracle Cloud VM
```bash
# 1. Sign up for Oracle Cloud Free Tier
# 2. Claim Always Free compute
# 3. Select: Ubuntu + Ampere A1 (2 OCPUs, 12GB RAM)
# 4. Configure network: NO inbound ports open initially
# 5. Create SSH key pair (local, not in image)
# 6. Launch VM with admin IP restriction
```

#### Step 6: Hardened SSH Configuration
```bash
# On your LOCAL machine (not the server):
ssh-keygen -t ed25519 -C "your_email@example.com"

# On the Oracle VM:
# 1. Copy your public key
ssh-copy-id -i ~/.ssh/id_ed25519.pub opc@YOUR_VM_IP

# 2. Disable password auth
sudo sed -i 's/^#*PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# 3. Restart SSH
sudo systemctl restart sshd

# 4. Restrict SSH to admin IP only (critical!)
# Add to /etc/ssh/sshd_config:
# Match Address YOUR_ADMIN_IP/32
#   AllowUsers opc

# OR use bastion host approach
```

#### Step 7: Install Docker on Oracle VM
```bash
# On Oracle VM:
sudo yum install -y docker
sudo usermod -aG docker opc
sudo systemctl start docker
sudo systemctl enable docker
```

#### Step 8: Build and Push Docker Image
```bash
# On your LOCAL machine (not the server):
cd D:/Project/HermesShield
docker build -t hermesshield:latest .

# Tag for registry (optional)
docker tag hermesshield:latest your-registry/hermesshield:latest

# OR save as tar for transfer
docker save hermesshield:latest -o hermesshield.tar
```

#### Step 9: Transfer Image to Cloud Server
```bash
# Transfer the tar file
scp hermesshield.tar opc@YOUR_VM_IP:/tmp/

# On the Oracle VM:
sudo docker load -i /tmp/hermesshield.tar
```

#### Step 10: Cloudflare Tunnel Setup
```bash
# On Oracle VM:
# 1. Install cloudflared
sudo apt-get update && sudo apt-get install -y cloudflared

# 2. Authenticate with Cloudflare
cloudflared tunnel login

# 3. Create tunnel
cloudflared tunnel create hermesshield

# 4. Route traffic
cloudflared tunnel route dns hermesshield hermesshield.yourdomain.com

# 5. Start tunnel (runs as daemon)
cloudflared tunnel run hermesshield
```

---

### Phase 3: Security Hardening

#### Step 11: Oracle Cloud Firewall/NSG Rules
Create strict firewall rules:

| Direction | Port | Source | Action |
|-----------|------|--------|--------|
| Inbound | 22 | YOUR_ADMIN_IP/32 | ALLOW |
| Inbound | - | 0.0.0.0/0 | DENY |
| Inbound | 80 | - | DENY (Cloudflare handles HTTPS) |
| Inbound | 443 | - | DENY (Cloudflare handles HTTPS) |
| Outbound | - | - | ALLOW |
| Outbound | 53 | - | ALLOW (DNS) |
| Outbound | 443 | - | ALLOW (HTTPS for updates) |

#### Step 12: Docker Container Security
Ensure your Dockerfile doesn't have:
- ❌ `USER root` - Use `USER appuser`
- ❌ `privileged: true` - Remove
- ❌ `volumes: - /:/host` - Remove
- ❌ `volumes: - /var/run/docker.sock:/var/run/docker.sock` - Remove
- ❌ `cap_add: ALL` - Drop all capabilities
- ✅ `security_opt: [no-new-privileges:true]` - Add
- ✅ `cap_drop: [ALL]` - Add

#### Step 13: Secret Management
**Never bake secrets into the Docker image:**

```yaml
# docker-compose.yml - WRONG
environment:
  - DATABASE_PASSWORD=supersecret  # ❌ Never do this

# docker-compose.yml - CORRECT
environment:
  - DATABASE_PASSWORD_FILE=/run/secrets/database_password

# Create secret at runtime
# echo "supersecret" | docker secret create database_password -
# OR use Docker Swarm/Kubernetes secrets
```

For simple deployments, use environment variables injected at runtime, not baked in.

#### Step 14: Database Isolation
Your benchmark has PostgreSQL exposed. For production:
- ✅ **Never expose PostgreSQL port 5432 to Internet**
- ✅ Use Cloudflare Tunnel internal only
- ✅ Configure Oracle NSG: port 5432 → ONLY app container IP
- ✅ Use environment variable `DATABASE_URL` without hardcoding password
- ✅ Consider managed database (Oracle RDS, Neon, etc.)

#### Step 15: Application-Level Security
Review your `hermes_shield/attack_path/correlation_engine.py` and `validation.py` fixes that were already applied:
- ✅ `claim_status.value` comparison fixed
- ✅ `e.get("verified", False)` for dict evidence
- ✅ Hypothesis generation from vulnerabilities
- ✅ Evidence matching and confidence calculation

---

### Phase 4: Testing & Validation

#### Step 16: Verify Deployment
```bash
# On your LOCAL machine:
curl - https://hermesshield.yourdomain.com

# Should show your web dashboard (index.html)

# Test API:
curl - https://hermesshield.yourdomain.com/api/status

# Should return 200 with service status
```

#### Step 17: Run Security Tests Remotely
```bash
# On your LOCAL machine:
ssh opc@YOUR_VM_IP "python -m pytest tests/attack_path/ -v"
ssh opc@YOUR_VM_IP "python -m pytest tests/security-boundary/ -v"
ssh opc@YOUR_VM_IP "python -m pytest tests/adversarial/ -v"
# Expected: 34/34 tests passing
```

#### Step 18: Inference Verification (Optional)
```bash
# If you have NEBIUS_API_KEY:
python scripts/verify_inference.py connectivity

# Should show:
# [PASS] api_key_present
# [PASS] api_key_valid
# [PASS] endpoint_reachable
# [PASS] model_availability
# [PASS] successful_inference
```

#### Step 19: Backup & Monitoring Setup
```bash
# Configure automated backups
# Set up monitoring for:
# - CPU utilization
# - RAM usage
# - Disk space
# - Container restarts
# - Cloudflare tunnel status
# - SSH authentication attempts

# Basic monitoring script:
#!/bin/bash
# /opt/monitor.sh
cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}')
ram=$(free -m | grep Mem | awk '{print $3 "/" $2}')
disk=$(df -h / | awk 'NR==2 {print $3 "/" $2 "/" $5}')

echo "[$(date)] CPU: $cpu | RAM: $ram | Disk: $disk" >> /var/log/monitor.log
```

Add to cron: `*/5 * * * * /opt/monitor.sh`

---

### Phase 5: Go-Live Checklist

#### Pre-Launch Verification
- [ ] Docker image built without vulnerabilities
- [ ] No secrets baked into image
- [ ] SSH restricted to admin IP only
- [ ] No inbound ports open on cloud firewall (except admin SSH)
- [ ] Cloudflare Tunnel running and accessible
- [ ] HTTPS working via Cloudflare
- [ ] All 34 tests passing remotely
- [ ] Backup strategy configured
- [ ] Monitoring enabled
- [ ] NEBIUS_API_KEY configured (optional)
- [ ] Domain DNS pointing to Cloudflare Tunnel
- [ ] Laptop can be turned OFF (verified)

#### Launch Steps
```bash
# 1. Ensure cloudflared tunnel is running on VM
# 2. Verify https://hermesshield.yourdomain.com loads
# 3. Confirm 34/34 tests pass via remote SSH
# 4. Turn off your laptop - verify app still works
# 5. Set up domain email/SSL renewal reminders
# 6. Document all passwords/keys in secure vault
```

#### Post-Launch Monitoring (First 24 Hours)
- [ ] Check Cloudflare dashboard for traffic patterns
- [ ] Review Oracle VM firewall logs
- [ ] Verify no unauthorized SSH attempts
- [ ] Monitor container health
- [ ] Check backup creation
- [ ] Review application logs for errors

---

## 🎯 Expected Outcomes

| Metric | Before | After |
|--------|--------|-------|
| **Tests Passing** | 34/34 (100%) | 34/34 (100%) |
| **Laptop Dependency** | Required for operation | **OFF - app runs 24/7** |
| **Source Code Privacy** | Partial (GitHub repo) | **Private - image not public** |
| **24/7 Availability** | Depends on laptop | **Yes - VPS runs continuously** |
| **Public URL** | None | **https://hermesshield.yourdomain.com** |
| **Attack Surface** | Local + potential exposure | **Minimized - Tunnel only** |
| **API Key Required** | Optional for full features | **Optional - AI features only** |

---

## 📝 Important Notes

1. **Your project works without NEBIUS_API_KEY** - all 34 tests pass regardless
2. **Cloudflare Tunnel requires outbound only** - no inbound ports needed on VM
3. **SSH is the ONLY open port** - restrict to your admin IP absolutely
4. **Database must remain private** - never expose 5432/3306/27017 to Internet
5. **Secrets must be runtime-injected** - never bake into Docker image
6. **Your web dashboard (index.html) is already ready** - just deploy the backend

---

## 🚀 Immediate Next Steps

### Path A: Quick Start (If you have some DevOps experience)
1. Provision Oracle Cloud VM (10-15 minutes)
2. Follow Steps 5-10 above
3. Deploy and verify
4. 🕐 Total time: ~30-45 minutes

### Path B: Secure Review First (Recommended)
1. Share your `Dockerfile` and `docker-compose.yml` (with secrets removed)
2. Perform configuration-level security review
3. Get hardened configurations
4. Then deploy
5. 🕐 Total time: ~15 min review + 30 min deployment

### Path C: Zero-Code Deployment
If you just want the web dashboard accessible:
1. Upload `index.html` to any static web host (Netlify, Vercel, Cloudflare Pages)
2. Keep HermesShield backend running locally or on the VPS
3. Minimal setup, but loses autonomous auditing features

---

## 📁 Required Files for Deployment

### New Files to Create:
1. **`Dockerfile`** - Application container definition
2. **`docker-compose.yml`** - Service orchestration
3. **`.env`** - Environment configuration (copy from `.env.example`)

### Existing Files:
- **`index.html`** - Redesigned web dashboard (already complete)
- **`hermes_shield/`** - Main Python package (34 tests passing)
- **`tests/`** - Test suites (all passing)
- **`benchmark/`** - Benchmark framework (with vulnerable lab - DO NOT deploy as-is)
- **`docs/`** - Documentation
- **`policies/`** - Security policies
- **`scripts/`** - Deployment scripts

---

## 🔐 Security Reminders

### DO:
- ✅ Use `USER appuser` in Dockerfile
- ✅ Restrict SSH to admin IP only
- ✅ Use Cloudflare Tunnel for all public access
- ✅ Inject secrets at runtime
- ✅ Run `cloudflared` as daemon on VM
- ✅ Monitor SSH authentication logs
- ✅ Test backups regularly

### DON'T:
- ❌ Expose Docker ports publicly (`ports: "0.0.0.0:..."`)
- ❌ Put secrets in Docker image or `.env` committed to Git
- ❌ Run container as root
- ❌ Mount Docker socket
- ❌ Allow SSH from 0.0.0.0/0
- ❌ Expose database ports
- ❌ Use `noTLSVerify: true` permanently
- ❌ Bake API keys into Docker image layers

---

## 📞 Support & Troubleshooting

### Common Issues:
1. **Cloudflare Tunnel not connecting**: Check `cloudflared tunnel run` logs
2. **Tests failing remotely**: Verify Docker container has access to audit_data volume
3. **SSH timeout**: Check Oracle Cloud firewall rules and NSG
4. **NEBIUS_API_KEY not working**: Verify `.env` file exists on VM and is sourced

### Verification Commands:
```bash
# Check container status
docker ps

# Check logs
docker logs hermesshield

# Check Cloudflare tunnel
cloudflared tunnel list

# Run tests on VM
ssh opc@YOUR_VM_IP "cd /app && python -m pytest tests/ -v"

# Check firewall
sudo iptables -L -n
```

---

## ✅ Deployment Complete

Once all steps are verified, your HermesShield deployment will be:
- **Accessible**: https://hermesshield.yourdomain.com
- **Secure**: No public ports, Cloudflare Tunnel only
- **Available 24/7**: Runs on Oracle Cloud Free Tier VM
- **Private**: Source code and Docker image not public
- **Monitored**: Basic monitoring and backup configured
- **Tested**: 34/34 security tests passing remotely