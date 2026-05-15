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

# This script monitors the serial console of a GCE VM to check for test completion.
# Usage: ./vm-test-monitor.sh <vm_name> <zone>

VM_NAME=$1
ZONE=$2

if [ -z "$VM_NAME" ] || [ -z "$ZONE" ]; then
  echo "Usage: $0 <vm_name> <zone>"
  exit 1
fi

# Configuration Constants
MAX_ATTEMPTS=60
POLL_INTERVAL_SECS=10

# Log Marker Constants
SUCCESS_MARKER="KPM_TEST_CONTAINER_EXITED_WITH_STATUS: 0"
EXIT_MARKER="KPM_TEST_CONTAINER_EXITED_WITH_STATUS:"

echo "Monitoring tests on $VM_NAME in $ZONE (polling serial console)..."
echo "Will poll up to $((MAX_ATTEMPTS * POLL_INTERVAL_SECS)) seconds."

for ((attempt=1; attempt<=MAX_ATTEMPTS; attempt++)); do
  # We use gcloud to fetch the serial port output.
  # We look for the specific marker string emitted by scripts/vm-test-startup.sh
  SERIAL_OUT=$(gcloud compute instances get-serial-port-output "$VM_NAME" --zone="$ZONE" 2>/dev/null || echo "")
  
  if echo "$SERIAL_OUT" | grep -q "${SUCCESS_MARKER}"; then
    echo "SUCCESS: All tests passed on VM."
    exit 0
  fi
  
  if echo "$SERIAL_OUT" | grep -q "${EXIT_MARKER}"; then
    EXIT_STATUS=$(echo "$SERIAL_OUT" | grep "${EXIT_MARKER}" | tail -n 1 | awk '{print $NF}')
    echo "FAILED: Test container exited with status $EXIT_STATUS."
    echo "--- SERIAL LOGS START ---"
    echo "$SERIAL_OUT"
    echo "--- SERIAL LOGS END ---"
    exit 1
  fi
  
  echo "Tests still running... (attempt ${attempt}/${MAX_ATTEMPTS})"
  sleep ${POLL_INTERVAL_SECS}
done

echo "TIMEOUT: VM tests did not complete within $((MAX_ATTEMPTS * POLL_INTERVAL_SECS)) seconds."
echo "--- SERIAL LOGS START ---"
# Re-fetch serial output one last time to have the latest state
SERIAL_OUT=$(gcloud compute instances get-serial-port-output "$VM_NAME" --zone="$ZONE" 2>/dev/null || echo "")
echo "$SERIAL_OUT"
echo "--- SERIAL LOGS END ---"
exit 1
