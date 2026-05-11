#!/bin/bash
set -o pipefail

echo "Starting Schema Test Runner Script..."

# Start WSD Agent in background
SOCKET_PATH="/tmp/wsd-test.sock"
echo "Starting WSD Agent in background..."
/app/agent --socket "$SOCKET_PATH" &
AGENT_PID=$!

echo "Waiting for socket to be ready..."
timeout 30s bash -c "until [ -S '$SOCKET_PATH' ]; do sleep 1; done"
if [ $? -ne 0 ]; then
    echo "ERROR: WSD Agent socket was not created in time."
    kill -9 $AGENT_PID || true
    exit 1
fi

echo "Running WSD API Signature Contract Tests..."
export WSD_SOCKET_PATH="$SOCKET_PATH"
/opt/venv/bin/pytest tests/integration/test_wsd_api_signatures.py -v
exit_code=$?

# Cleanup
echo "Cleaning up WSD Agent..."
kill $AGENT_PID || true
rm -f "$SOCKET_PATH"

echo "Schema Test Runner finished with exit code $exit_code"
exit $exit_code
