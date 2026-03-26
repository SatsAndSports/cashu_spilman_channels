#!/bin/bash

# go-parallel-demo.sh
# Automated test for Spilman Go Demo with dynamic ports and parallel clients.
#
# Usage: ./scripts/go-parallel-demo.sh
#        MINT_URL=http://localhost:3338 ./scripts/go-parallel-demo.sh

set -e
set -u
set -o pipefail

# 1. Configuration
MINT_TYPE="${1:-standalone}"
USE_EXTERNAL_MINT=false
if [ $# -eq 0 ] && [ -n "${MINT_URL:-}" ]; then
    USE_EXTERNAL_MINT=true
fi

MINT_LABEL="$MINT_TYPE"
if [ "$USE_EXTERNAL_MINT" = true ]; then
    MINT_LABEL="external"
fi

LOG_DIR="./testing/go-demo-$MINT_LABEL"
SERVER_LOG="$LOG_DIR/server.log"
MINT_LOG="$LOG_DIR/mint.log"
CLIENT_COUNT=3
REPO_ROOT=$(pwd)
GO_DEMO_DIR="examples/go-ascii-art"

# Create log directory
mkdir -p "$LOG_DIR"

# 2. Cleanup function
cleanup() {
    echo ""
    echo "--- Cleaning up ---"
    # Kill background jobs (mint and server)
    JOBS=$(jobs -p)
    if [ -n "$JOBS" ]; then
        echo "Killing background processes: $JOBS"
        kill $JOBS || true
    fi
    echo "Cleanup complete. Logs available in $LOG_DIR"
}

# Register the cleanup function to run on exit (success or failure)
trap cleanup EXIT

# 3. Build Go demo
echo "--- Building Go demo ---"
(cd "$GO_DEMO_DIR" && LD_LIBRARY_PATH="$REPO_ROOT/target/debug" go build -tags spilman_dev -o main .)

# 4. Find free ports
echo "--- Finding free ports ---"
if [ "$USE_EXTERNAL_MINT" = true ]; then
    SERVER_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()')
    echo "MINT_URL:    $MINT_URL"
    echo "SERVER_PORT: $SERVER_PORT"
else
    read -r MINT_PORT SERVER_PORT < <(python3 -c 'import socket; s1=socket.socket(); s1.bind(("", 0)); s2=socket.socket(); s2.bind(("", 0)); print(f"{s1.getsockname()[1]} {s2.getsockname()[1]}"); s1.close(); s2.close()')
    echo "MINT_PORT:   $MINT_PORT"
    echo "SERVER_PORT: $SERVER_PORT"

    # 5. Start Mint
    echo "--- Starting $MINT_TYPE Mint (logging to $MINT_LOG) ---"
    ./scripts/run_temporary_mint.sh "$MINT_TYPE" "$MINT_PORT" > "$MINT_LOG" 2>&1 &

    # Wait for mint to be fully ready
    ./scripts/wait_for_mint.sh "$MINT_LOG" 120 || { echo "Mint log:"; cat "$MINT_LOG"; exit 1; }
    export MINT_URL="http://localhost:$MINT_PORT"
fi

# 6. Start Go Server
echo "--- Starting Go Server (logging to $SERVER_LOG) ---"
export PORT="$SERVER_PORT"
export SERVER_URL="http://localhost:$SERVER_PORT"
export LD_LIBRARY_PATH="$REPO_ROOT/target/debug"

cd "$GO_DEMO_DIR"
./main server > "$REPO_ROOT/$SERVER_LOG" 2>&1 &
cd "$REPO_ROOT"

# Wait for server to be ready
echo "Waiting for server to start on port $SERVER_PORT..."
for i in {1..20}; do
    if curl -s "http://localhost:$SERVER_PORT/channel/params" > /dev/null; then
        echo "Server is ready."
        break
    fi
    if [ $i -eq 20 ]; then
        echo "ERROR: Server failed to start."
        cat "$SERVER_LOG"
        exit 1
    fi
    sleep 0.5
done

# 7. Run Parallel Clients
echo "--- Running $CLIENT_COUNT Clients in Parallel (logging to $LOG_DIR/client_N.log) ---"

PIDS=()
for i in $(seq 1 $CLIENT_COUNT); do
    MSG="Go-Parallel-$i"
    LOG="$LOG_DIR/client_$i.log"
    echo "Starting Client $i with message: '$MSG'..."
    (cd "$GO_DEMO_DIR" && MINT_URL="$MINT_URL" SERVER_URL="http://localhost:$SERVER_PORT" LD_LIBRARY_PATH="$REPO_ROOT/target/debug" ./main client "$MSG" --close) > "$LOG" 2>&1 &
    PIDS+=($!)
done

# 8. Wait for all clients and check results
SUCCESS=true
for i in "${!PIDS[@]}"; do
    PID="${PIDS[$i]}"
    echo "Waiting for Client $((i+1)) (PID $PID)..."
    if ! wait "$PID"; then
        echo "ERROR: Client $((i+1)) failed! See $LOG_DIR/client_$((i+1)).log"
        SUCCESS=false
    else
        echo "Client $((i+1)) finished successfully."
    fi
done

# 9. Verify closure from server side
echo ""
echo "--- Verifying channel closure on server ---"
for i in $(seq 1 $CLIENT_COUNT); do
    LOG="$LOG_DIR/client_$i.log"
    CHANNEL_ID=$(grep -oP 'Full channel ID: \K[a-f0-9]+' "$LOG" | head -1 || true)
    
    if [ -n "$CHANNEL_ID" ]; then
        STATUS=$(curl -s "http://localhost:$SERVER_PORT/channel/$CHANNEL_ID/status")
        if echo "$STATUS" | grep -q '"closed":\s*true'; then
            echo "  Channel ${CHANNEL_ID:0:16} is closed. OK."
        else
            echo "  ERROR: Channel ${CHANNEL_ID:0:16} is NOT closed!"
            echo "  Status: $STATUS"
            SUCCESS=false
        fi
    fi
done

# 10. Final Result
if [ "$SUCCESS" = true ]; then
    echo ""
    echo "***********************************"
    echo "* ALL GO PARALLEL TESTS PASSED    *"
    echo "***********************************"
    echo ""
    exit 0
else
    echo ""
    echo "***********************************"
    echo "* SOME GO TESTS FAILED            *"
    echo "***********************************"
    echo ""
    exit 1
fi
