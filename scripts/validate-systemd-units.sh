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

# Runs `systemd-analyze verify` over the unit files in image/, catching unknown
# directives, malformed values, and unresolvable dependencies.
#
# `verify` exits 0 on an unknown key or an unparseable value -- it warns and
# carries on -- so its exit code alone would miss the typos that matter most.
# A clean unit emits nothing, so any output is treated as a failure.
#
# The units reference binaries and units that exist only on the KPS VM, and
# verify treats both as errors. We stub them so that a failure means the unit is
# actually wrong, rather than that we are not running on the KPS VM. That trade
# is why this does not check whether /usr/bin/fluent-bit really ships in the
# ACOS base image -- only a booted VM can.

set -euo pipefail

readonly DEBIAN_IMAGE="debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df"
readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

docker info >/dev/null 2>&1 || fail "Docker is not available; cannot verify systemd units"

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT
cp "${REPO_ROOT}"/image/*.service "${work_dir}/"

cat > "${work_dir}/verify.sh" << 'INNER'
set -eu
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq --no-install-recommends systemd >/dev/null 2>&1
cd /units

# containerd.service lives on the KPS VM, not here. Without a stub, every unit
# that Requires= it fails to resolve.
cat > containerd.service << 'EOF'
[Unit]
Description=containerd (stub for verification)
[Service]
ExecStart=/bin/true
EOF

# `verify` rejects an ExecStart whose binary is absent, so stub each referenced
# path. This validates the directives, not the binaries.
grep -hoE '^Exec[A-Za-z]*=-?/[^ ]+' ./*.service \
  | sed -E 's/^Exec[A-Za-z]*=-?//' \
  | sort -u \
  | while read -r bin; do
      [ -e "${bin}" ] && continue
      mkdir -p "$(dirname "${bin}")"
      printf '#!/bin/sh\n' > "${bin}"
      chmod +x "${bin}"
    done

rc=0
for unit in ./*.service; do
  [ "${unit}" = "./containerd.service" ] && continue
  name="${unit#./}"
  echo "==> ${name}"
  # Warnings ("Unknown key ... ignoring", "Failed to parse ... ignoring") exit 0.
  # A clean unit is silent, so treat any output as a failure.
  if ! output="$(systemd-analyze verify "/units/${name}" 2>&1)"; then
    rc=1
  elif [ -n "${output}" ]; then
    rc=1
  fi
  if [ -n "${output}" ]; then
    printf '%s\n' "${output}" | sed 's/^/    /'
  fi
done
exit "${rc}"
INNER

docker run --rm -v "${work_dir}:/units" "${DEBIAN_IMAGE}" bash /units/verify.sh \
  || fail "systemd-analyze verify rejected one or more units in image/"

echo "==> OK: all image/*.service verify clean"
