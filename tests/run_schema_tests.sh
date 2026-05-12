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
