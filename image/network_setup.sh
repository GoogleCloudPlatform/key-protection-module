#!/bin/bash
mkdir -p /etc/systemd/network/

cat << 'INNER_EOF' > /etc/systemd/network/00-static-tap.network
[Match]
Driver=virtio_net

[Network]
Address=192.168.100.3/24

[Route]
Gateway=192.168.100.1
INNER_EOF
