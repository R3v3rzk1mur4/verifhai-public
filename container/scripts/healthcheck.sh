#!/bin/sh
# Verifhai Container Health Check
# Validates: Python runtime, CLI availability, HAIAMM data integrity, Claude Code
# Exit 0 = healthy, Exit 1 = unhealthy

set -e

HAIAMM_DIR="${HAIAMM_DATA_DIR:-/opt/haiamm}"
EXPECTED_PRACTICES=75
EXPECTED_QUESTIONNAIRES=19

# 1. Python runtime
python3 -c "import sys; assert sys.version_info >= (3, 10)" 2>/dev/null || {
    echo "UNHEALTHY: Python 3.10+ not available"
    exit 1
}

# 2. Verifhai CLI responds
verifhai version >/dev/null 2>&1 || {
    echo "UNHEALTHY: verifhai CLI not responding"
    exit 1
}

# 3. HAIAMM data present and complete
if [ ! -d "${HAIAMM_DIR}/practices" ]; then
    echo "UNHEALTHY: HAIAMM practices directory missing"
    exit 1
fi

practice_count=$(find "${HAIAMM_DIR}/practices" -name "*.md" -type f | wc -l | tr -d ' ')
if [ "$practice_count" -lt "$EXPECTED_PRACTICES" ]; then
    echo "UNHEALTHY: Expected ${EXPECTED_PRACTICES}+ practices, found ${practice_count}"
    exit 1
fi

if [ ! -d "${HAIAMM_DIR}/questionnaires" ]; then
    echo "UNHEALTHY: HAIAMM questionnaires directory missing"
    exit 1
fi

questionnaire_count=$(find "${HAIAMM_DIR}/questionnaires" -name "*.md" -type f | wc -l | tr -d ' ')
if [ "$questionnaire_count" -lt "$EXPECTED_QUESTIONNAIRES" ]; then
    echo "UNHEALTHY: Expected ${EXPECTED_QUESTIONNAIRES}+ questionnaires, found ${questionnaire_count}"
    exit 1
fi

if [ ! -f "${HAIAMM_DIR}/HAIAMM-Handbook.md" ]; then
    echo "UNHEALTHY: HAIAMM Handbook missing"
    exit 1
fi

# 4. Claude Code available
command -v claude >/dev/null 2>&1 || {
    echo "UNHEALTHY: Claude Code CLI not found"
    exit 1
}

# 5. Claude permissions file exists and does NOT contain bypassPermissions
CLAUDE_SETTINGS="/opt/verifhai/claude-permissions.json"
if [ -f "$CLAUDE_SETTINGS" ]; then
    if grep -q "bypassPermissions" "$CLAUDE_SETTINGS" 2>/dev/null; then
        echo "UNHEALTHY: bypassPermissions detected in Claude settings"
        exit 1
    fi
fi

# 6. Semgrep rules present
if [ ! -d "/opt/verifhai/semgrep" ]; then
    echo "UNHEALTHY: Semgrep rules directory missing"
    exit 1
fi

echo "HEALTHY: All checks passed"
exit 0
