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

main() {
  # Set IMA policy
  if [[ -f /usr/share/oem/ima-policy ]]; then
    cp /usr/share/oem/ima-policy /sys/kernel/security/ima/policy
  fi

  # Configure sysctls.
  sysctl -w kernel.kexec_load_disabled=1

  # Copy service files.
  cp /usr/share/oem/kps/keymanager.service /etc/systemd/system/keymanager.service
  cp /usr/share/oem/kps/attestation.service /etc/systemd/system/attestation.service
  cp /usr/share/oem/kps/fluent-bit-kps.service /etc/systemd/system/fluent-bit-kps.service

  mkdir -p /etc/fluent-bit
  cp /usr/share/oem/kps/fluent-bit-kps.conf /etc/fluent-bit/fluent-bit-kps.conf

  mkdir /tmp/container_launcher
  chmod +rw /tmp/container_launcher

  # Configure static IP for tap device using systemd-networkd.
  if [[ -f /usr/share/oem/kps/network_setup.sh ]]; then
    /usr/share/oem/kps/network_setup.sh
    systemctl restart systemd-networkd
  fi

  # Allow incoming TCP packets on port 50050 for KPS and 50051 for attestation service.
  iptables -I INPUT -d 192.168.100.3 -p tcp  -m multiport --dports 50050,50051 -j ACCEPT

  systemctl daemon-reload
  systemctl enable keymanager.service
  systemctl enable attestation.service
  systemctl start keymanager.service
  systemctl start attestation.service

  # Last, so a failing relay cannot stop the KPS from serving keys. Nothing is
  # missed: these units log to journald, and Read_From_Tail=False reads the
  # journal from the beginning.
  systemctl enable fluent-bit-kps.service
  systemctl start fluent-bit-kps.service

  # Type=simple reports a successful start once exec'd, so a config fluent-bit
  # rejects on load would otherwise go unnoticed.
  if ! systemctl is-active --quiet fluent-bit-kps.service; then
    echo "ERROR: fluent-bit-kps.service did not start; KPS telemetry is disabled" > /dev/console
    systemctl status --no-pager fluent-bit-kps.service > /dev/console 2>&1
  fi
}

main
