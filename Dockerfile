# Multi-stage Dockerfile for Ultimate CA Manager
# Optimized for production with security and minimal size
# Paths aligned with DEB/RPM packages: /opt/ucm/{backend,frontend,data}

# Stage 1: Frontend - the built interface is gitignored, so the image
# produces it. CI uses Node 20. vite.config.js reads VERSION from the
# repo root, one directory above frontend/.
FROM node:20-bookworm-slim AS frontend

WORKDIR /src
COPY VERSION /src/VERSION
COPY frontend/package.json frontend/package-lock.json /src/frontend/
WORKDIR /src/frontend
RUN npm ci
COPY frontend/ /src/frontend/
RUN npm run build

# Stage 2: Builder - Install dependencies and build environment
FROM python:3.13-slim-bookworm AS builder

# Install build dependencies (fallback for packages without prebuilt wheels)
# Note: pyjks is installed separately with --no-deps to skip `twofish`
# (sdist-only C ext, only used for BKS UBER format which UCM does not export).
# This means build-essential is no longer strictly required, but kept as a
# safety net for future deps that may need to compile.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    libkrb5-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment (same path as DEB/RPM)
RUN python -m venv /opt/ucm/venv
ENV PATH="/opt/ucm/venv/bin:$PATH"

# Copy only requirements first for better caching
COPY backend/requirements.txt /tmp/requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r /tmp/requirements.txt && \
    pip install --no-cache-dir --no-deps pyjks==20.0.0

# Stage 3: Runtime - Minimal production image
FROM python:3.13-slim-bookworm

LABEL maintainer="NeySlim <https://github.com/NeySlim>" \
      description="Ultimate CA Manager - Certificate Authority Management System" \
      org.opencontainers.image.source="https://github.com/NeySlim/ultimate-ca-manager"

# Install only runtime dependencies.
# SoftHSM stays as before. SmartCard-HSM remote provider needs pcscd, OpenSC
# (sc-hsm-tool), and the bookworm vpcd IFD handler (vsmartcard-vpcd registers
# libifdvpcd.so in /etc/reader.conf.d/vpcd against the default vpcd port).
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    openssl \
    openssh-client \
    softhsm2 \
    libkrb5-3 \
    postgresql-client \
    pcscd \
    opensc \
    opensc-pkcs11 \
    vsmartcard-vpcd \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security.
# pcscd's postinst asks systemd-sysusers for the pcscd user and group, then
# ignores failure. The slim base has no systemd-sysusers, so the group never
# appears and usermod would abort the build. Create it here when missing.
# The bridge talks to the PC/SC socket as a member of that group.
RUN if ! getent group pcscd >/dev/null; then groupadd --system pcscd; fi && \
    if ! getent passwd pcscd >/dev/null; then \
        useradd --system --gid pcscd --home-dir /run/pcscd \
            --shell /usr/sbin/nologin pcscd; \
    fi && \
    useradd -r -u 1000 -s /bin/false -d /opt/ucm ucm && \
    usermod -aG softhsm,pcscd ucm

# SoftHSM tokens live in the data volume, so a recreated container keeps its keys
RUN sed -i 's#^directories.tokendir.*#directories.tokendir = /opt/ucm/data/softhsm/tokens/#' /etc/softhsm/softhsm2.conf && \
    grep -q '^directories.tokendir = /opt/ucm/data/softhsm/tokens/$' /etc/softhsm/softhsm2.conf

# Confirm vpcd IFD is registered (package ships /etc/reader.conf.d/vpcd).
# Default CHANNELID 0x8C7B = TCP 35963; the bridge speaks the vpicc side to that port.
RUN test -f /usr/lib/pcsc/drivers/serial/libifdvpcd.so && \
    test -f /etc/reader.conf.d/vpcd

# Copy virtual environment from builder
COPY --from=builder /opt/ucm/venv /opt/ucm/venv

# Set working directory (same as DEB/RPM)
WORKDIR /opt/ucm

# Copy application files with proper ownership (same layout as packages)
COPY --chown=ucm:ucm VERSION /opt/ucm/VERSION
COPY --chown=ucm:ucm backend/ /opt/ucm/backend/
# Only the built interface. The frontend stage discards sources and
# node_modules; the server serves frontend/dist.
COPY --from=frontend --chown=ucm:ucm /src/frontend/dist/ /opt/ucm/frontend/dist/
COPY --chown=ucm:ucm wsgi.py /opt/ucm/wsgi.py
COPY --chown=ucm:ucm .env.docker.example /opt/ucm/.env.example

# Create data + log directories
# Listed one by one: this runs under /bin/sh, which does not expand braces on
# a Debian base image, and a single directory named after the whole list
# would be created instead of the nine wanted here
RUN for d in ca certs private crl scep backups sessions logs temp; do \
        mkdir -p "/opt/ucm/data/$d"; \
    done && \
    mkdir -p /var/log/ucm && \
    mkdir -p /etc/ucm && \
    chown -R ucm:ucm /opt/ucm /var/log/ucm /etc/ucm

# Set environment variables
ENV PATH="/opt/ucm/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UCM_DOCKER=1 \
    UCM_BASE_PATH=/opt/ucm \
    DATA_DIR=/opt/ucm/data

# Expose HTTPS port (and optional HTTP protocol port for CDP/OCSP).
# RAM_PORT (default 8444) is the SmartCard-HSM ram-client listener on the bridge.
EXPOSE 8443
EXPOSE 8080
EXPOSE 8444

# Declare persistent volumes.
# /etc/ucm holds master.key — the symmetric key that decrypts every private
# key in the database. If the container is recreated without this volume
# bind-mounted, master.key is destroyed and ALL encrypted CAs / certs / ACME
# / SSH-CA private keys in the DB become unrecoverable. ALWAYS bind-mount
# /etc/ucm to a host path or named volume before enabling encryption.
# /opt/ucm/data holds the SQLite DB, CA files, sessions, backups.
VOLUME ["/etc/ucm", "/opt/ucm/data"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f -k https://127.0.0.1:8443/health || exit 1

# Entrypoint runs as root so it can start pcscd, then drops to ucm for the
# RAM bridge and Gunicorn (see docker/entrypoint.sh). SoftHSM paths are unchanged.
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Default command - Gunicorn from /opt/ucm/backend (same as packages)
CMD ["sh", "-c", "cd /opt/ucm/backend && gunicorn -c gunicorn_config.py wsgi:app"]
