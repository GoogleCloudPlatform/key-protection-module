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

# This script runs on the GCE VM as a startup script.
# It fetches the test image and location from the VM metadata and runs the test container.

set -e

echo "Starting KPM VM Test Startup Script..."

# Fetches configuration from VM metadata
# We use the metadata server to avoid hardcoding these values in the script.
LOCATION=$(curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/attributes/location)
IMAGE=$(curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/attributes/test_image)

if [ -z "$LOCATION" ] || [ -z "$IMAGE" ]; then
  echo "ERROR: Missing required metadata 'location' or 'test_image'."
  exit 1
fi

export DOCKER_CONFIG=/tmp/docker-config
mkdir -p "$DOCKER_CONFIG"

# Log in to Artifact Registry
echo "Logging into Artifact Registry at ${LOCATION}-docker.pkg.dev..."
docker-credential-gcr configure-docker --registries="${LOCATION}-docker.pkg.dev"

echo "Pulling test container: $IMAGE"
docker pull "$IMAGE"

echo "Starting test container..."
# memfd_secret requires seccomp=unconfined on some COS versions or kernel configs
docker run --rm --security-opt seccomp=unconfined "$IMAGE"
exit_code=$?

echo "KPM_TEST_CONTAINER_EXITED_WITH_STATUS: $exit_code"
