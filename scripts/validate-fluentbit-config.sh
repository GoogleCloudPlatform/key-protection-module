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

# Validates image/fluent-bit-kps.conf against a real Fluent Bit.
#
# `--dry-run` checks section syntax and plugin names, but silently accepts
# misspelled plugin properties: a typo'd `Mem_Buf_Limit` passes it and would ship
# with unbounded memory buffering. Only a real startup rejects unknown properties,
# so we do both.
#
# Neither check verifies the Systemd_Filter unit names. Only a booted KPS VM can.

set -euo pipefail

# Pinned by digest: what each check catches is version-dependent.
readonly FLUENT_BIT_IMAGE="fluent/fluent-bit:4.2.7@sha256:32167e0953eb8e8865823fc7e779df6c56297db457a3fcb840466579923ad784"
readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly CONFIG_DIR="${REPO_ROOT}/image"
readonly CONFIG_NAME="fluent-bit-kps.conf"
readonly STARTUP_SECS=8

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Otherwise a stopped daemon surfaces as "--dry-run rejected the config".
docker info >/dev/null 2>&1 || fail "Docker is not available; cannot validate ${CONFIG_NAME}"

# The systemd input needs this to exist before it can create its cursor DB.
db_dir="$(mktemp -d)"
log_file="$(mktemp)"
container="fluent-bit-validate-$$"
cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  rm -rf "${db_dir}" "${log_file}"
}
trap cleanup EXIT

echo "==> Checking syntax and plugin names (--dry-run)"
docker run --rm \
  -v "${CONFIG_DIR}:/cfg:ro" \
  "${FLUENT_BIT_IMAGE}" \
  --dry-run -c "/cfg/${CONFIG_NAME}" \
  || fail "--dry-run rejected ${CONFIG_NAME}"

echo "==> Checking plugin properties (real startup, ${STARTUP_SECS}s)"
docker run --rm --name "${container}" \
  -v "${CONFIG_DIR}:/cfg:ro" \
  -v "${db_dir}:/var/log/google-fluentbit" \
  "${FLUENT_BIT_IMAGE}" \
  -c "/cfg/${CONFIG_NAME}" >"${log_file}" 2>&1 &
docker_pid=$!

sleep "${STARTUP_SECS}"
docker rm -f "${container}" >/dev/null 2>&1 || true
wait "${docker_pid}" 2>/dev/null || true

# Matched narrowly: connection failures to the workload VM are expected, not errors.
if grep -qE "unknown configuration property|initialization failed|\[error\] \[config\]" "${log_file}"; then
  grep -E "unknown configuration property|initialization failed|\[error\] \[config\]" "${log_file}" >&2
  fail "Fluent Bit rejected the configuration at startup"
fi

# Assert the intended pipeline materialized, not just that no error appeared.
for probe in \
  "input:systemd:systemd.0" \
  "input:systemd:systemd.1" \
  "output:forward:forward.0"; do
  grep -q "${probe}" "${log_file}" || {
    cat "${log_file}" >&2
    fail "expected '${probe}' to initialize, but it did not appear in the log"
  }
done

echo "==> OK: ${CONFIG_NAME} is valid and instantiates 2 systemd inputs + 1 forward output"
