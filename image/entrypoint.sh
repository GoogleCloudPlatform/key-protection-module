#!/bin/bash

main() {
  # Configure sysctls.
  sysctl -w kernel.kexec_load_disabled=1

  # Copy service files.
  cp /usr/share/oem/kps/keymanager.service /etc/systemd/system/keymanager.service
  cp /usr/share/oem/kps/attestation.service /etc/systemd/system/attestation.service

  mkdir /tmp/container_launcher
  chmod +rw /tmp/container_launcher

  systemctl daemon-reload
  systemctl enable keymanager.service
  systemctl enable attestation.service
  systemctl start keymanager.service
  systemctl start attestation.service
}

main