#!/bin/sh

set -eu

if command -v systemctl > /dev/null && [ "$(systemctl is-system-running)" != "offline" ]; then
    # load new oinit-ca.service file
    systemctl daemon-reload
    systemctl enable oinit-ca
    systemctl start oinit-ca
    
fi

test -d /etc/oinit || mkdir -p /etc/oinit/
test -e /etc/oinit/user-ca || ssh-keygen -t ed25519 -f /etc/oinit/user-ca -N "" > /dev/null
test -e /etc/oinit/host-ca || ssh-keygen -t ed25519 -f /etc/oinit/host-ca -N "" > /dev/null
