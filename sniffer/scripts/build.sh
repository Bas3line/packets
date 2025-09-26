#!/bin/bash

echo "Building Packet Sniffer..."

mkdir -p bin

gcc -Wall -Wextra -O2 -o bin/packet_sniffer src/packet_sniffer.c
if [ $? -eq 0 ]; then
    echo "Server built successfully: bin/packet_sniffer"
else
    echo "Server build failed"
    exit 1
fi

gcc -Wall -Wextra -O2 -o bin/packet_client src/packet_client.c
if [ $? -eq 0 ]; then
    echo "Client built successfully: bin/packet_client"
else
    echo "Client build failed"
    exit 1
fi

echo ""
echo "Build complete!"
echo ""
echo "Usage:"
echo "  Server: sudo ./bin/packet_sniffer"
echo "  Client: ./bin/packet_client <server_ip>"