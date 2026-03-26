#!/bin/bash
# run_with_mint.sh
# Runs a command with MINT_URL set, either using an external mint or spawning one.

set -e
set -u
set -o pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

print_mint_summary() {
    local source="$1"
    local mint_url="$2"
    local helper="$REPO_ROOT/scripts/print_mint_summary.py"

    if ! python3 "$helper" "$source" "$mint_url"; then
        echo "MINT_READY source=$source url=$mint_url name=\"unknown\" version=\"unknown\" units=[]"
    fi
}

is_mint_type() {
    case "$1" in
        standalone|cdk) return 0 ;;
        *) return 1 ;;
    esac
}

usage() {
    echo "Usage:" >&2
    echo "  $0 [standalone] <command...>" >&2
    echo "  MINT_URL=http://host:port $0 <command...>" >&2
    echo "" >&2
    echo "Examples:" >&2
    echo "  $0 cargo test -p rust-ascii-art --manifest-path Cargo.toml" >&2
    echo "  MINT_URL=http://localhost:3338 $0 make test-integration-python" >&2
}

if [ $# -eq 0 ]; then
    usage
    exit 1
fi

EXPLICIT_MINT_TYPE=false
MINT_TYPE="standalone"

if is_mint_type "$1"; then
    EXPLICIT_MINT_TYPE=true
    MINT_TYPE="$1"
    shift
fi

if [ $# -eq 0 ]; then
    usage
    exit 1
fi

if [ "$EXPLICIT_MINT_TYPE" = false ] && [ -n "${MINT_URL:-}" ]; then
    print_mint_summary "external" "$MINT_URL"
    exec "$@"
fi

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()')
LOG_DIR="$REPO_ROOT/testing"
mkdir -p "$LOG_DIR"
MINT_LOG="$LOG_DIR/mint-${MINT_TYPE}-${PORT}.log"
MINT_URL_LOCAL="http://127.0.0.1:$PORT"

echo "Starting $MINT_TYPE mint on port $PORT..."
echo "Mint logs: $MINT_LOG"

"$REPO_ROOT/scripts/run_temporary_mint.sh" "$MINT_TYPE" "$PORT" > "$MINT_LOG" 2>&1 &
MINT_PID=$!

cleanup() {
    local exit_code=$?
    echo "Stopping mint (PID $MINT_PID)..."
    kill "$MINT_PID" 2>/dev/null || true
    wait "$MINT_PID" 2>/dev/null || true
    if [ $exit_code -ne 0 ] && [ -f "$MINT_LOG" ]; then
        echo ""
        echo "=== Last 30 lines of mint log ($MINT_LOG) ==="
        tail -30 "$MINT_LOG"
    fi
}
trap cleanup EXIT INT TERM

"$REPO_ROOT/scripts/wait_for_mint.sh" "$MINT_LOG" 120

echo "Running: $*"
echo ""

MINT_URL="$MINT_URL_LOCAL" "$@"
