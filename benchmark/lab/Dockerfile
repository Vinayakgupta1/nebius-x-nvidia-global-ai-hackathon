# Synthetic Security Laboratory for HermesShield Benchmarking
# Contains 10 known vulnerabilities across multiple categories

FROM alpine:3.20

# Install required packages
RUN apk add --no-cache \
    openssh \
    openssl \
    python3 \
    py3-pip \
    postgresql \
    postgresql-client \
    sudo \
    cronie \
    samba \
    docker-cli \
    nmap \
    curl \
    netcat-openbsd \
    net-tools \
    procps \
    vim \
    ca-certificates \
    && rm -rf /var/cache/apk/*

# Create necessary directories
RUN mkdir -p /etc/ssh /app/config /opt/scripts /var/run/docker.sock /var/spool/cron/crontabs /var/lib/samba

# ============================================================================
# VULNERABILITY SETUP
# ============================================================================

# BENCH-001: Hardcoded SSH Private Key
RUN echo -e "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0+testkey1234567890abcdef\n-----END RSA PRIVATE KEY-----" > /etc/ssh/sshd_config

# BENCH-002: Weak SSH Configuration
RUN cat >> /etc/ssh/sshd_config << 'EOF'
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
MaxAuthTries 6
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
EOF

# BENCH-003: Exposed Internal HTTP API (port 8080)
# Create a simple Python HTTP server with admin endpoints
RUN cat > /app/admin_api.py << 'PYEOF'
from flask import Flask, jsonify, request
import os

app = Flask(__name__)

@app.route('/users')
def users():
    return jsonify({"users": [{"id": 1, "name": "admin"}, {"id": 2, "name": "user"}]})

@app.route('/config')
def config():
    return jsonify({"database": {"host": "localhost", "port": 5432}, "debug": True})

@app.route('/logs')
def logs():
    return jsonify({"logs": ["admin login", "config change", "db query"]})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
PYEOF

RUN pip3 install --no-cache-dir flask

# BENCH-004: Database credentials in world-readable file
RUN cat > /app/config/database.yml << 'YAMLEOF'
database:
  host: localhost
  port: 5432
  username: admin
  password: "SuperSecretPass123!"
  database: production
YAMLEOF
RUN chmod 644 /app/config/database.yml

# BENCH-005: PostgreSQL with default credentials
# Initialize PostgreSQL with default postgres/postgres
RUN mkdir -p /var/lib/postgresql/data && \
    chown -R postgres:postgres /var/lib/postgresql/data && \
    su - postgres -c 'initdb -D /var/lib/postgresql/data' && \
    echo "host all all 0.0.0.0/0 md5" >> /var/lib/postgresql/data/pg_hba.conf && \
    echo "listen_addresses = '*'" >> /var/lib/postgresql/data/postgresql.conf

# Set default password for postgres user
RUN echo "postgres:postgres" | chpasswd

# BENCH-006: Sudo NOPASSWD for www-data
RUN adduser -D -s /bin/sh www-data && \
    echo "www-data ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/www-data && \
    chmod 440 /etc/sudoers.d/www-data

# BENCH-007: Cron job with world-writable script
RUN mkdir -p /opt/scripts && \
    echo '#!/bin/sh\necho "Backup running at $(date)" >> /var/log/backup.log' > /opt/scripts/backup.sh && \
    chmod 777 /opt/scripts/backup.sh && \
    chown www-data:www-data /opt/scripts/backup.sh && \
    echo '0 * * * * root /opt/scripts/backup.sh' > /etc/cron.d/backup && \
    chmod 644 /etc/cron.d/backup

# BENCH-008: SMB share with anonymous access
RUN cat > /etc/samba/smb.conf << 'SMBCONF'
[global]
    workgroup = WORKGROUP
    security = user
    map to guest = Bad User
    guest account = nobody

[public]
    path = /srv/samba/public
    read only = yes
    guest ok = yes

[backup]
    path = /srv/samba/backup
    read only = yes
    guest ok = yes
SMBCONF

RUN mkdir -p /srv/samba/public /srv/samba/backup && \
    echo "Public file" > /srv/samba/public/readme.txt && \
    echo "Backup config" > /srv/samba/backup/config.bak && \
    chmod 755 /srv/samba/public /srv/samba/backup

# BENCH-009: Weak SSL/TLS (self-signed cert with weak config)
RUN mkdir -p /etc/ssl/certs /etc/ssl/private && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/selfsigned.key \
    -out /etc/ssl/certs/selfsigned.crt \
    -subj "/CN=localhost" 2>/dev/null

# BENCH-010: Docker socket (will be mounted at runtime)
# The socket is created by mounting at runtime

# ============================================================================
# SERVICE STARTUP SCRIPT
# ============================================================================
RUN cat > /start_services.sh << 'STARTEOF'
#!/bin/sh
set -e

# Start SSH
mkdir -p /var/run/sshd
/usr/sbin/sshd

# Start PostgreSQL
su - postgres -c 'pg_ctl -D /var/lib/postgresql/data -l /var/log/postgresql.log start'

# Start admin API
cd /app && python3 admin_api.py > /var/log/admin_api.log 2>&1 &

# Start Samba
mkdir -p /run/samba
smbd -D
nmbd -D

# Start cron
crond

# Keep container running
tail -f /dev/null
STARTEOF

RUN chmod +x /start_services.sh

# Create non-root user for testing
RUN adduser -D -s /bin/sh testuser

# Set up SSH keys for testuser (for BENCH-001 exploitation)
RUN mkdir -p /home/testuser/.ssh && \
    ssh-keygen -t rsa -b 2048 -f /home/testuser/.ssh/id_rsa -N "" && \
    cp /home/testuser/.ssh/id_rsa.pub /home/testuser/.ssh/authorized_keys && \
    chown -R testuser:testuser /home/testuser/.ssh && \
    chmod 700 /home/testuser/.ssh && \
    chmod 600 /home/testuser/.ssh/*

EXPOSE 22 8080 5432 445 443

ENTRYPOINT ["/start_services.sh"]