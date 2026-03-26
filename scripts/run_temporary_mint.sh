#!/bin/bash
# run_temporary_mint.sh
# Starts a temporary standalone test mint with auto-cleanup on exit.
#
# Usage: ./scripts/run_temporary_mint.sh [standalone] <port>
# Example: ./scripts/run_temporary_mint.sh standalone 12345
#          ./scripts/run_temporary_mint.sh 3338
#
# The mint runs in the foreground. Use & to background it.
# On exit (SIGTERM, SIGINT, or normal), temp directory is cleaned up.

set -e
set -u

MINT_TYPE="${1:-standalone}"
MINT_PORT="${2:-3338}"

# Locate repo root (script is in scripts/)
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

print_mint_summary() {
    local source="$1"
    local mint_url="$2"
    local helper="$REPO_ROOT/scripts/print_mint_summary.py"

    if ! python3 "$helper" "$source" "$mint_url"; then
        echo "MINT_READY source=$source url=$mint_url name=\"unknown\" version=\"unknown\" units=[]" >&2
    fi
}

MINT_WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/mint-${MINT_TYPE}.XXXXXX")

MINT_PID=""

cleanup() {
    if [ -n "$MINT_PID" ]; then
        kill "$MINT_PID" 2>/dev/null || true
        wait "$MINT_PID" 2>/dev/null || true
    fi
    rm -rf "$MINT_WORK_DIR"
}
trap cleanup EXIT INT TERM

case "$MINT_TYPE" in
    standalone|cdk)
        STANDALONE_MANIFEST="$REPO_ROOT/Cargo.toml"
        MINT_BIN="$REPO_ROOT/target/debug/cdk-spilman-test-mintd"

        echo "Building standalone test mint..." >&2
        cargo build -p cdk-spilman-test-mint --manifest-path "$STANDALONE_MANIFEST" >&2

        if [ ! -f "$MINT_BIN" ]; then
            echo "ERROR: $MINT_BIN not found after build." >&2
            exit 1
        fi

        MINT_URL_LOCAL="http://127.0.0.1:$MINT_PORT"

        "$MINT_BIN" --listen-port "$MINT_PORT" --base-url "$MINT_URL_LOCAL" &
        MINT_PID=$!
        
        # Wait for mint to respond
        # (The standalone test mint only binds once sat, msat, and usd keysets are ready.)
        for i in {1..60}; do
            if curl -s "$MINT_URL_LOCAL/v1/info" > /dev/null 2>&1; then
                print_mint_summary "spawned" "$MINT_URL_LOCAL" >&2
                break
            fi
            if [ $i -eq 60 ]; then
                echo "ERROR: standalone test mint did not start within 30 seconds" >&2
                exit 1
            fi
            sleep 0.5
        done
        
        wait "$MINT_PID"
        ;;

    *)
        echo "Unknown mint type: $MINT_TYPE (supported: standalone)" >&2
        echo "To test against an external mint, set MINT_URL instead." >&2
        exit 1
        ;;
esac
