#!/bin/bash

echo "Setting up Packet Sniffer Client..."

./scripts/build.sh

if [ ! -f "bin/packet_client" ]; then
    echo "Build failed. Cannot proceed with setup."
    exit 1
fi

echo "Client setup complete!"
echo "To connect to server: ./bin/packet_client <server_ip>"
echo "Example: ./bin/packet_client 192.168.1.100"