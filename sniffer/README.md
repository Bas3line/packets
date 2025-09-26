# Packet Sniffer

**Educational packet sniffer for network understanding and learning purposes only.**

A client-server packet sniffer implementation in C that captures network packets on a server and streams them to a remote client for analysis.

## Features

- Raw packet capture using raw sockets
- Protocol analysis: TCP, UDP, ICMP with flag parsing
- MAC address extraction from Ethernet frames
- Packet hexdump display
- Real-time statistics (packet counts, bytes transferred)
- Multi-client support (up to 5 concurrent clients)
- TTL and flag analysis
- Microsecond timestamps

## Architecture

- **Server** (`packet_sniffer.c`): Runs on the target machine, captures packets and serves them to clients
- **Client** (`packet_client.c`): Connects to the server and displays captured packets in real-time

## Quick Setup

### On Your Debian Server

```bash
# Clone and setup
git clone https://github.com/Bas3line/packets
cd packets/sniffer

# Build and setup server (requires root)
sudo ./scripts/server_setup.sh

# Start packet sniffer (requires root for raw sockets)
sudo ./bin/packet_sniffer
```

### On Your Local PC

```bash
# Setup client
./scripts/client_setup.sh

# Connect to your server (replace with your server's IP)
./bin/packet_client YOUR_SERVER_IP
```

## Manual Build

```bash
# Using make
make build

# Or using build script
./scripts/build.sh

# Or manually
gcc -o bin/packet_sniffer src/packet_sniffer.c
gcc -o bin/packet_client src/packet_client.c
```

## Usage

1. **Start the server** on your Debian cloud server:
   ```bash
   sudo ./bin/packet_sniffer
   ```

2. **Connect from your PC**:
   ```bash
   ./bin/packet_client 192.168.1.100  # Replace with server IP
   ```

3. **View packets** in real-time on your local machine

## Requirements

- **Server**: Linux system with root access (for raw socket creation)
- **Client**: Any system with network connectivity
- **Network**: Port 8888 must be open between client and server

## Sample Output

```
[12:34:56.789] TCP aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66 192.168.1.10:443 -> 192.168.1.100:52345 (1460 bytes, TTL:64) SYN ACK
    HEX: 45 00 05 b4 1a 2b 40 00 40 06 d4 6c c0 a8 01 0a c0 a8 01 64 01 bb cc 89 ...

STATS: Total: 15847 | TCP: 12453 | UDP: 2891 | ICMP: 234 | Other: 269 | Bytes: 18394752
----------------------------------------------------------------------
```

## Security Notes

- **Educational use only** - Use only on networks you own or have permission to monitor
- Requires root privileges for raw socket access
- Opens TCP port 8888 for client connections
- No encryption - packets are transmitted in plaintext

## Legal Notice

This tool is provided for educational purposes only. Users are responsible for complying with all applicable laws and regulations. Only use on networks you own or have explicit permission to monitor.