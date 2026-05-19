#!/bin/bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Drives the WSD HTTP API end-to-end against a remote KPS VM over gRPC.
# Starts /app/agent in KEY_PROTECTION_VM / SERVICE_ROLE_WSD mode, pointed at
# $KPS_IP, then exercises each gRPC-backed endpoint via curl on the unix
# socket and asserts the expected status / shape.

set -e
set -o pipefail

SOCKET_PATH="/tmp/wsd-grpc-e2e.sock"
AGENT_LOG="/tmp/wsd-grpc-e2e.log"

if [ -z "$KPS_IP" ]; then
    echo "ERROR: KPS_IP environment variable is required."
    exit 1
fi

echo "Waiting for KPS gRPC port at $KPS_IP:50050 to accept TCP..."
if ! timeout 120s bash -c "until (echo > /dev/tcp/$KPS_IP/50050) 2>/dev/null; do sleep 2; done"; then
    echo "ERROR: KPS at $KPS_IP:50050 did not become reachable within 120s."
    exit 1
fi

echo "Starting WSD agent (KEY_PROTECTION_VM, WSD role) pointed at KPS_IP=$KPS_IP"
KEY_PROTECTION_MECHANISM=KEY_PROTECTION_VM \
SERVICE_ROLE=SERVICE_ROLE_WSD \
KPS_IP="$KPS_IP" \
    /app/agent --socket "$SOCKET_PATH" --kps-vm-ip "$KPS_IP" \
    >"$AGENT_LOG" 2>&1 &
AGENT_PID=$!

cleanup() {
    echo "Cleaning up WSD agent (pid=$AGENT_PID)..."
    kill "$AGENT_PID" 2>/dev/null || true
    timeout 5s wait "$AGENT_PID" 2>/dev/null || kill -9 "$AGENT_PID" 2>/dev/null || true
    rm -f "$SOCKET_PATH"
    echo "--- Agent log ---"
    cat "$AGENT_LOG" || true
    echo "--- End agent log ---"
}
trap cleanup EXIT

echo "Waiting for WSD unix socket at $SOCKET_PATH ..."
if ! timeout 30s bash -c "until [ -S '$SOCKET_PATH' ]; do sleep 1; done"; then
    echo "ERROR: WSD socket was not created within 30s."
    exit 1
fi

echo "Checking for heartbeat success in agent log..."
# The agent should perform a heartbeat handshake with KPS
if ! timeout 30s bash -c "until grep -q 'Heartbeat handshake successful' '$AGENT_LOG'; do sleep 1; done"; then
    echo "ERROR: Heartbeat handshake not successful within 30s."
    exit 1
fi
echo "Heartbeat handshake successful!"

echo "Running python e2e tests..."
export SOCKET_PATH
if ! /opt/venv/bin/pytest -v /app/tests/test_grpc_wsd_e2e.py; then
    echo "ERROR: Python e2e tests failed."
    exit 1
fi

echo "KPM_GRPC_WSD_E2E_SUCCESS: all gRPC API steps passed against remote KPS"
exit 0
