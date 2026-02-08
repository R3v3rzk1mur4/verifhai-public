# Verifhai Secure Container - Production Dockerfile
# 11-Layer Defense in Depth Architecture
#
# Stage 1 (builder):  Build Python wheel via hatchling
# Stage 2 (claude):   Install Claude Code via npm (NOT curl|bash)
# Stage 3 (runtime):  Minimal Chainguard Python runtime
#
# Security: Non-root (UID 10001), read-only rootfs, zero capabilities,
#           no-new-privileges, seccomp, AppArmor, no curl/wget/sudo

# =============================================================================
# Stage 1: Build the Python wheel
# =============================================================================
FROM cgr.dev/chainguard/python:latest-dev AS builder

USER root

# Install build dependencies
RUN pip install --no-cache-dir hatchling

# Copy source for wheel build
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ src/

# Build the wheel
RUN python -m hatchling build -t wheel && \
    ls -la dist/*.whl

# =============================================================================
# Stage 2: Install Claude Code via npm (pinned version, NOT curl|bash)
# =============================================================================
FROM node:22-slim AS claude-installer

# Pin Claude Code version - update this deliberately, not automatically
ARG CLAUDE_CODE_VERSION=1.0.3

# Install via npm with exact version pin
RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" && \
    # Verify installation
    claude --version && \
    # Remove npm cache to reduce layer size
    npm cache clean --force

# =============================================================================
# Stage 3: Production runtime (minimal attack surface)
# =============================================================================
FROM cgr.dev/chainguard/python:latest AS runtime

# Metadata labels
LABEL org.opencontainers.image.title="verifhai" \
      org.opencontainers.image.description="HAI Security Assessment Tool - Hardened Container" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.vendor="Verifhai Contributors" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/verifhai/verifhai" \
      io.verifhai.security.layers="11" \
      io.verifhai.security.non-root="true" \
      io.verifhai.security.read-only-rootfs="true" \
      io.verifhai.security.no-capabilities="true"

# Create non-root user (UID 10001 - above typical system range)
# Chainguard images already have a nonroot user, but we create our own for control
USER root
RUN addgroup -g 10001 verifhai 2>/dev/null || true && \
    adduser -u 10001 -G verifhai -D -h /home/verifhai verifhai 2>/dev/null || true

# Create application directories
RUN mkdir -p /opt/verifhai/semgrep \
             /opt/verifhai/skill \
             /opt/verifhai/templates \
             /opt/haiamm/practices \
             /opt/haiamm/questionnaires \
             /workspace \
             /tmp/.verifhai && \
    chown -R 10001:10001 /opt/verifhai /opt/haiamm /workspace /tmp/.verifhai

# Copy Python wheel from builder and install
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && \
    rm -f /tmp/*.whl

# Copy Claude Code from installer stage (node_modules only, no build tools)
COPY --from=claude-installer /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=claude-installer /usr/local/bin/claude /usr/local/bin/claude
COPY --from=claude-installer /usr/local/bin/node /usr/local/bin/node

# Copy Semgrep rules
COPY ci/semgrep/*.yml /opt/verifhai/semgrep/

# Copy Skill files and workflows
COPY SKILL.md /opt/verifhai/skill/
COPY workflows/ /opt/verifhai/skill/workflows/

# Copy templates
COPY templates/ /opt/verifhai/templates/

# Copy HAIAMM reference data (bundled at build time from pinned commit)
# These are copied from the build context - CI checks out HAIAMM at pinned SHA
COPY haiamm-data/practices/ /opt/haiamm/practices/
COPY haiamm-data/questionnaires/ /opt/haiamm/questionnaires/
COPY haiamm-data/HAIAMM-Handbook.md /opt/haiamm/

# Copy security configuration
COPY container/security/claude-permissions.json /opt/verifhai/claude-permissions.json

# Copy entrypoint and healthcheck scripts
COPY container/scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY container/scripts/healthcheck.sh /usr/local/bin/healthcheck.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck.sh

# Set ownership - everything under /opt is read-only for the app user
RUN chown -R root:root /opt/verifhai /opt/haiamm && \
    chmod -R 555 /opt/verifhai /opt/haiamm && \
    chown -R 10001:10001 /workspace /tmp/.verifhai /home/verifhai

# Environment configuration
ENV HAIAMM_DATA_DIR=/opt/haiamm \
    VERIFHAI_HOME=/opt/verifhai \
    VERIFHAI_WORKSPACE=/workspace \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NODE_ENV=production \
    # Claude Code configuration
    CLAUDE_CODE_SETTINGS_FILE=/opt/verifhai/claude-permissions.json

# Switch to non-root user (Layer 2)
USER 10001:10001
WORKDIR /workspace

# Health check (Layer 12 - validates all components)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/healthcheck.sh"]

# Entrypoint validates security invariants before exec
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["verifhai", "version"]
