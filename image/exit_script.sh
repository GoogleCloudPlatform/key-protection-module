#!/usr/bin/env bash
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

set -e

if [ -f /usr/share/oem/kps/image.env ]; then
    source /usr/share/oem/kps/image.env
else
    echo "Error: Config file not found!"
    exit 1
fi


if ctr task ls | grep -q "$CONTAINER_NAME"; then
    echo "Stopping running task for $CONTAINER_NAME..."
    
    ctr task kill -s SIGTERM "$CONTAINER_NAME" || true
    
    sleep 5
    
    echo "Deleting the task..."
    ctr task rm -f "$CONTAINER_NAME" || true
else
    echo "No active task found for $CONTAINER_NAME."
fi
