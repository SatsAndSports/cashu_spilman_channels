#!/bin/bash
# wait_for_mint.sh
# Waits for a MINT_READY marker in the mint log file.
#
# Usage: ./scripts/wait_for_mint.sh <log_file> [timeout_seconds]
#
# The marker is printed by run_temporary_mint.sh after the mint is fully
# configured and ready to accept requests (including all keysets created).
#
# On success: prints the marker line and exits 0
# On timeout: prints error to stderr and exits 1

set -e
set -u

LOG_FILE="${1:?Usage: wait_for_mint.sh <log_file> [timeout_seconds]}"
TIMEOUT="${2:-60}"

ELAPSED=0
MAX_STEPS=$((TIMEOUT * 2))
while [ $ELAPSED -lt $MAX_STEPS ]; do
    if grep -q "^MINT_READY " "$LOG_FILE" 2>/dev/null; then
        grep "^MINT_READY " "$LOG_FILE"
        exit 0
    fi
    if grep -q "MINT_READY_WITH_KEYSETS" "$LOG_FILE" 2>/dev/null; then
        grep "MINT_READY_WITH_KEYSETS" "$LOG_FILE"
        exit 0
    fi
    sleep 0.5
    ELAPSED=$((ELAPSED + 1))
done

echo "ERROR: MINT_READY marker not found in $LOG_FILE within ${TIMEOUT}s" >&2
exit 1
