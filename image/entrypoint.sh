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

is_debug_mode() {
  local -a tokens
  if ! read -r -a tokens < /proc/cmdline; then
    return 1
  fi

  local count_false=0
  local count_true=0
  local count_other=0

  for token in "${tokens[@]}"; do
    case "$token" in
      confidential-space.hardened=false)
        ((count_false++))
        ;;
      confidential-space.hardened=true)
        ((count_true++))
        ;;
      confidential-space.hardened=*)
        ((count_other++))
        ;;
    esac
  done

  if [[ $count_false -eq 1 && $count_true -eq 0 && $count_other -eq 0 ]]; then
    return 0
  fi

  return 1
}

main() {
  if is_debug_mode; then
    exec >/dev/console 2>&1
  fi
  echo "=== starting keymanager entrypoint ==="

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
  iptables -C INPUT -d 192.168.100.3 -p tcp -m multiport --dports 50050,50051 -j ACCEPT 2>/dev/null || \
  iptables -I INPUT 1 -d 192.168.100.3 -p tcp -m multiport --dports 50050,50051 -j ACCEPT

  # Enable debug configuration if the VM is running a debug image.
  if is_debug_mode; then
    echo "=== Running debug VM configurations ==="


    # Load the QEMU fw_cfg kernel module
    modprobe qemu_fw_cfg 2>/dev/null || true

    fwcfg_dir="/sys/firmware/qemu_fw_cfg/by_name/opt/kpm_debug_ssh"
    keys_file="${fwcfg_dir}/authorized_keys/raw"
    keys_size_file="${fwcfg_dir}/authorized_keys/size"
    sentinel_file="${fwcfg_dir}/kpm_debug_ssh_v1/raw"

    keys_size=0
    if [[ -r "$keys_size_file" ]]; then
      keys_size=$(cat "$keys_size_file" 2>/dev/null || echo 0)
    fi

    if [[ -r "$keys_file" && "$keys_size" -gt 0 ]] &&
       [[ -r "$sentinel_file" ]] &&
       grep -qx "kpm_debug_ssh_v1" "$sentinel_file"; then

      if mkdir -p /run/kpm-debug-ssh && chmod 700 /run/kpm-debug-ssh; then
        tmp_keys="$(mktemp /run/kpm-debug-ssh/authorized_keys.XXXXXX)"
        if install -m 600 "$keys_file" "$tmp_keys" && mv "$tmp_keys" /run/kpm-debug-ssh/authorized_keys; then
          iptables -N KPM_DEBUG_SSH 2>/dev/null || true
          iptables -F KPM_DEBUG_SSH
          iptables -A KPM_DEBUG_SSH -s 192.168.100.2/32 -j ACCEPT
                    iptables -A KPM_DEBUG_SSH -j DROP
          iptables -C INPUT -d 192.168.100.3/32 -p tcp --dport 22 -j KPM_DEBUG_SSH 2>/dev/null || \
            iptables -I INPUT 1 -d 192.168.100.3/32 -p tcp --dport 22 -j KPM_DEBUG_SSH
          echo "Successfully imported debug SSH authorized_keys from fw_cfg"

          # Configure sshd to permit root public-key login in debug mode
          for service in sshd ssh; do
            mkdir -p "/run/systemd/system/${service}.service.d"
            printf '[Service]\nExecStart=\nExecStart=/usr/sbin/sshd -D -e -o PermitRootLogin=prohibit-password -o PubkeyAuthentication=yes -o PasswordAuthentication=no -o AuthorizedKeysFile=/run/kpm-debug-ssh/authorized_keys\n' > "/run/systemd/system/${service}.service.d/kpm-debug.conf"
          done
          systemctl daemon-reload
          systemctl restart sshd.service || systemctl restart ssh.service || true
        else
          rm -f "${tmp_keys:-}"
          echo "Failed to install debug SSH authorized_keys"
        fi
      else
        echo "Failed to prepare writable /run/kpm-debug-ssh directory"
      fi
    else
      echo "Failed to find or validate debug SSH keys in fw_cfg"
    fi
  fi

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
