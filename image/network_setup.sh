#!/bin/bash
mkdir -p /run/systemd/network/

cat << 'EOF' > /run/systemd/network/00-dhcp-tap.network
[Match]
Driver=virtio_net

[Network]
DHCP=yes
EOF
