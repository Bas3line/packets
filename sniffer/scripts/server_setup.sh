#!/bin/bash

echo "Setting up Packet Sniffer Server..."

if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

./scripts/build.sh

if [ ! -f "bin/packet_sniffer" ]; then
    echo "Build failed. Cannot proceed with setup."
    exit 1
fi

echo "Opening firewall port 8888..."
ufw allow 8888/tcp 2>/dev/null || iptables -A INPUT -p tcp --dport 8888 -j ACCEPT 2>/dev/null

echo "Server setup complete!"
echo "To start the sniffer: sudo ./bin/packet_sniffer"