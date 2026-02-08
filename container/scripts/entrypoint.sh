#!/bin/sh
# Verifhai Container Entrypoint
# Performs security validation before starting the application.
# Fails fast if any security invariant is violated.

set -e

HAIAMM_DIR="${HAIAMM_DATA_DIR:-/opt/haiamm}"

# --- Security Validations ---

# 1. Verify non-root execution
current_uid=$(id -u)
if [ "$current_uid" = "0" ]; then
    echo "FATAL: Container must not run as root (UID 0)" >&2
    echo "  Configure: runAsUser: 10001 or USER directive in Dockerfile" >&2
    exit 1
fi
echo "[entrypoint] Running as UID ${current_uid} (non-root) ✓"

# 2. Verify no dangerous capabilities
if [ -f /proc/1/status ]; then
    cap_eff=$(grep -i '^CapEff:' /proc/1/status 2>/dev/null | awk '{print $2}' || echo "unknown")
    if [ "$cap_eff" = "0000000000000000" ]; then
        echo "[entrypoint] Zero effective capabilities ✓"
    elif [ "$cap_eff" != "unknown" ]; then
        echo "WARNING: Non-zero capabilities detected: ${cap_eff}" >&2
        echo "  Configure: cap_drop: ALL in security context" >&2
    fi
fi

# 3. Verify no-new-privileges
if [ -f /proc/1/status ]; then
    no_new_privs=$(grep -i '^NoNewPrivs:' /proc/1/status 2>/dev/null | awk '{print $2}' || echo "unknown")
    if [ "$no_new_privs" = "1" ]; then
        echo "[entrypoint] no-new-privileges enforced ✓"
    elif [ "$no_new_privs" != "unknown" ]; then
        echo "WARNING: no-new-privileges not set" >&2
    fi
fi

# 4. Verify seccomp is active
if [ -f /proc/1/status ]; then
    seccomp_mode=$(grep -i '^Seccomp:' /proc/1/status 2>/dev/null | awk '{print $2}' || echo "unknown")
    if [ "$seccomp_mode" = "2" ]; then
        echo "[entrypoint] Seccomp filter mode active ✓"
    elif [ "$seccomp_mode" != "unknown" ]; then
        echo "WARNING: Seccomp not in filter mode (mode=${seccomp_mode})" >&2
    fi
fi

# 5. Verify HAIAMM data is present
if [ -d "${HAIAMM_DIR}/practices" ]; then
    practice_count=$(find "${HAIAMM_DIR}/practices" -name "*.md" -type f | wc -l | tr -d ' ')
    echo "[entrypoint] HAIAMM data: ${practice_count} practices loaded ✓"
else
    echo "FATAL: HAIAMM practices not found at ${HAIAMM_DIR}/practices" >&2
    exit 1
fi

# 6. Verify Claude permissions file does not allow bypassPermissions
CLAUDE_SETTINGS="/opt/verifhai/claude-permissions.json"
if [ -f "$CLAUDE_SETTINGS" ]; then
    if grep -q "bypassPermissions" "$CLAUDE_SETTINGS"; then
        echo "FATAL: bypassPermissions found in Claude settings" >&2
        echo "  This is a security violation. Use explicit allow-lists." >&2
        exit 1
    fi
    echo "[entrypoint] Claude Code allow-list mode ✓"
fi

# 7. Verify dangerous tools are not available
for cmd in curl wget sudo su; do
    if command -v "$cmd" >/dev/null 2>&1; then
        echo "WARNING: ${cmd} is available in container. Remove from image." >&2
    fi
done

# --- Initialization ---

# Create writable directories if they don't exist (for tmpfs mounts)
mkdir -p /tmp/.verifhai 2>/dev/null || true
mkdir -p /workspace 2>/dev/null || true

echo "[entrypoint] Security validation complete. Starting verifhai..."
echo ""

# Execute the passed command (default: interactive shell or verifhai CLI)
exec "$@"
