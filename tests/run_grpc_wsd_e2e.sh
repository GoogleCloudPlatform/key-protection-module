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
    wait "$AGENT_PID" 2>/dev/null || true
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

CURL=(curl --silent --show-error --unix-socket "$SOCKET_PATH")

# --- 1. GET /v1/capabilities -> 200, mentions DHKEM_X25519
echo "Step 1: GET /v1/capabilities"
CAP_BODY=$("${CURL[@]}" --fail "http://localhost/v1/capabilities")
echo "$CAP_BODY" | grep -q "KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256" \
    || { echo "ERROR: capabilities missing DHKEM_X25519: $CAP_BODY"; exit 1; }

# --- 2. POST /v1/keys:generate_key -> 200, returns UUID handle
echo "Step 2: POST /v1/keys:generate_key"
GEN_REQ='{"algorithm":{"type":"kem","params":{"kem_id":"KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256"}},"lifespan":3600}'
GEN_BODY=$("${CURL[@]}" --fail -H "Content-Type: application/json" \
    -X POST --data "$GEN_REQ" "http://localhost/v1/keys:generate_key")
KEY_HANDLE=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['key_handle']['handle'])" "$GEN_BODY")
if ! [[ "$KEY_HANDLE" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
    echo "ERROR: generate_key returned bad handle: $GEN_BODY"
    exit 1
fi
echo "  generated KEM key handle: $KEY_HANDLE"

# --- 3. GET /v1/keys -> 200, contains our handle
echo "Step 3: GET /v1/keys (expect our key present)"
ENUM_BODY=$("${CURL[@]}" --fail "http://localhost/v1/keys")
python3 - "$ENUM_BODY" "$KEY_HANDLE" <<'PY' || exit 1
import json, sys
body, handle = sys.argv[1], sys.argv[2]
data = json.loads(body)
handles = [k["key_handle"]["handle"] for k in data.get("key_infos", [])]
if handle not in handles:
    print(f"ERROR: generated handle {handle} not in enumerate result: {handles}")
    sys.exit(1)
PY

# --- 4. POST /v1/keys:decap with bogus ciphertext -> 5xx (gRPC error propagated)
echo "Step 4: POST /v1/keys:decap (expect error for bogus ciphertext)"
DECAP_REQ=$(python3 -c '
import base64, json, sys
body = {
  "key_handle": {"handle": sys.argv[1]},
  "ciphertext": {
    "algorithm": "KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256",
    "ciphertext": base64.b64encode(b"bogus-ciphertext-for-e2e-test").decode(),
  },
  "aad": "",
}
print(json.dumps(body))' "$KEY_HANDLE")
DECAP_STATUS=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -H "Content-Type: application/json" \
    -X POST --data "$DECAP_REQ" "http://localhost/v1/keys:decap")
if [ "$DECAP_STATUS" = "200" ] || [ "$DECAP_STATUS" = "204" ]; then
    echo "ERROR: decap with bogus ciphertext returned success ($DECAP_STATUS)"
    exit 1
fi
echo "  decap rejected bogus ciphertext (HTTP $DECAP_STATUS)"

# --- 5. POST /v1/keys:destroy -> 204
echo "Step 5: POST /v1/keys:destroy"
DESTROY_REQ=$(python3 -c 'import json,sys; print(json.dumps({"key_handle":{"handle":sys.argv[1]}}))' "$KEY_HANDLE")
DESTROY_STATUS=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -H "Content-Type: application/json" \
    -X POST --data "$DESTROY_REQ" "http://localhost/v1/keys:destroy")
if [ "$DESTROY_STATUS" != "204" ]; then
    echo "ERROR: destroy returned HTTP $DESTROY_STATUS, expected 204"
    exit 1
fi

# --- 6. GET /v1/keys -> 200, does NOT contain our handle
echo "Step 6: GET /v1/keys (expect our key gone)"
ENUM_BODY2=$("${CURL[@]}" --fail "http://localhost/v1/keys")
python3 - "$ENUM_BODY2" "$KEY_HANDLE" <<'PY' || exit 1
import json, sys
body, handle = sys.argv[1], sys.argv[2]
data = json.loads(body)
handles = [k["key_handle"]["handle"] for k in data.get("key_infos", [])]
if handle in handles:
    print(f"ERROR: destroyed handle {handle} still present: {handles}")
    sys.exit(1)
PY

# --- 7. Second destroy on the same key -> 404 (mapping gone)
echo "Step 7: POST /v1/keys:destroy (second call expects 404)"
DESTROY2_STATUS=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -H "Content-Type: application/json" \
    -X POST --data "$DESTROY_REQ" "http://localhost/v1/keys:destroy")
if [ "$DESTROY2_STATUS" != "404" ]; then
    echo "ERROR: second destroy returned HTTP $DESTROY2_STATUS, expected 404"
    exit 1
fi

echo "KPM_GRPC_WSD_E2E_SUCCESS: all gRPC API steps passed against remote KPS"
exit 0
