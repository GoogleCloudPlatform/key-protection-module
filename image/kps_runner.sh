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

echo "=== Launching Key Protection Agent Container ==="


echo "Importing image from ${IMAGE_PATH}..."
if [ -f "$IMAGE_PATH" ]; then
    ctr images import "$IMAGE_PATH"
else
    echo "Error: Image file not found at $IMAGE_PATH"
    exit 1
fi

echo "Checking for existing container..."
if ctr container info "$CONTAINER_NAME" >/dev/null 2>&1; then
    echo "Removing existing container..."
    ctr container rm "$CONTAINER_NAME"
fi

ctr run --rm -net-host --mount "type=bind,src=/tmp/container_launcher/,dst=/run/container_launcher/,options=rbind:rw" --env SERVICE_ROLE="KPS" --env KEY_PROTECTION_MECHANISM="KEY_PROTECTION_VM" "$IMAGE_REF" "$CONTAINER_NAME"