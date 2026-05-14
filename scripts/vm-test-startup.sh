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
# It fetches the container image, environment variables, and extra arguments 
# from VM metadata and runs the container.

set -e

echo "Starting KPM VM Test Startup Script ..."

# Constants
METADATA_BASE_URL="http://metadata.google.internal/computeMetadata/v1/instance/attributes"
METADATA_HEADER="Metadata-Flavor: Google"
DOCKER_CONFIG_DIR="/tmp/docker-config"

# Fetches configuration from VM metadata
# We use the metadata server to avoid hardcoding these values in the script.
LOCATION=$(curl -s -H "${METADATA_HEADER}" "${METADATA_BASE_URL}/location")

# Try 'image' first, fallback to 'test_image' for backward compatibility
IMAGE=$(curl -s -f -H "${METADATA_HEADER}" "${METADATA_BASE_URL}/image") || \
IMAGE=$(curl -s -f -H "${METADATA_HEADER}" "${METADATA_BASE_URL}/test_image")

DOCKER_ENV=$(curl -s -f -H "${METADATA_HEADER}" "${METADATA_BASE_URL}/docker_env" || true)
DOCKER_ARGS=$(curl -s -f -H "${METADATA_HEADER}" "${METADATA_BASE_URL}/docker_args" || true)
TEST_COMMAND=$(curl -s -f -H "${METADATA_HEADER}" "${METADATA_BASE_URL}/test_command" || true)

if [ -z "$LOCATION" ] || [ -z "$IMAGE" ]; then
  echo "ERROR: Missing required metadata 'location' or 'image'/'test_image'."
  exit 1
fi

export DOCKER_CONFIG="${DOCKER_CONFIG_DIR}"
mkdir -p "${DOCKER_CONFIG}"

# Log in to Artifact Registry
echo "Logging into Artifact Registry at ${LOCATION}-docker.pkg.dev..."
docker-credential-gcr configure-docker --registries="${LOCATION}-docker.pkg.dev"

echo "Pulling container: $IMAGE"
pull_success=false
for i in {1..3}; do
  if docker pull "$IMAGE"; then
    pull_success=true
    break
  fi
  echo "WARNING: docker pull failed (attempt $i/3), retrying in 5 seconds..."
  sleep 5
done

if [ "$pull_success" = false ]; then
  echo "ERROR: Failed to pull docker image after 3 attempts."
  echo "KPM_TEST_CONTAINER_EXITED_WITH_STATUS: 125"
  exit 1
fi

# Parse DOCKER_ENV into array of -e flags
ENV_ARGS=()
if [ -n "$DOCKER_ENV" ]; then
  for env in $DOCKER_ENV; do
    ENV_ARGS+=("-e" "$env")
  done
fi

# Parse DOCKER_ARGS into array
EXTRA_ARGS=()
if [ -n "$DOCKER_ARGS" ]; then
  for arg in $DOCKER_ARGS; do
    EXTRA_ARGS+=("$arg")
  done
fi

echo "Starting container..."
# memfd_secret requires seccomp=unconfined on some COS versions or kernel configs
set +e
if [ -n "$TEST_COMMAND" ]; then
  echo "Running custom test command: $TEST_COMMAND"
  docker run --rm --security-opt seccomp=unconfined --entrypoint /bin/bash "$IMAGE" -c "$TEST_COMMAND"
else
  docker run --rm --security-opt seccomp=unconfined "${ENV_ARGS[@]}" "${EXTRA_ARGS[@]}" "$IMAGE"
fi
exit_code=$?
set -e

echo "KPM_TEST_CONTAINER_EXITED_WITH_STATUS: $exit_code"
exit "$exit_code"
