# Packet Sniffer Setup Guide

## Prerequisites

### Server (Debian Cloud Server)
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install build essentials
sudo apt install build-essential gcc make -y

# Install git (if not already installed)
sudo apt install git -y
```

### Client (Local PC)
```bash
# Install gcc and build tools
sudo apt install build-essential gcc -y  # Ubuntu/Debian
# OR
sudo yum install gcc make -y             # CentOS/RHEL
# OR
sudo pacman -S gcc make -y               # Arch Linux
```

## Installation

### On Server (Debian Cloud)
```bash
# Clone repository
git clone https://github.com/Bas3line/packets
cd packets/sniffer

# Build server
sudo ./scripts/server_setup.sh

# OR manual build
make build
# OR
./scripts/build.sh
```

### On Client (Local PC)
```bash
# Clone repository
git clone https://github.com/Bas3line/packets
cd packets/sniffer

# Build client
./scripts/client_setup.sh

# OR manual build
make build
# OR
./scripts/build.sh
```

## Firewall Configuration

### Server Firewall (Port 8888)
```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 8888/tcp

# iptables (Generic Linux)
sudo iptables -A INPUT -p tcp --dport 8888 -j ACCEPT

# Cloud Provider Security Groups
# Add inbound rule: TCP port 8888 from your IP
```

## Running the Packet Sniffer

### 1. Start Server
```bash
# On your Debian cloud server
cd packets
sudo ./bin/packet_sniffer
```

Output should show:
```
Packet sniffer listening on port 8888
Packet sniffer started. Press Ctrl+C to stop.
```

### 2. Connect Client
```bash
# On your local PC
cd packets
./bin/packet_client YOUR_SERVER_IP

# Example:
./bin/packet_client 192.168.1.100
```

Output should show:
```
Connected to packet sniffer server at 192.168.1.100:8888
Receiving packet data...
----------------------------------------------------------------------
```

## Sample Output

### Server Terminal
```
Packet sniffer listening on port 8888
Packet sniffer started. Press Ctrl+C to stop.
Client connected: 192.168.1.50
12:34:56.789 [TCP] 192.168.1.1 -> 192.168.1.100 (SYN) 60 bytes
12:34:56.790 [TCP] 192.168.1.100 -> 192.168.1.1 (SYN ACK) 60 bytes
```

### Client Terminal
```
Connected to packet sniffer server at 192.168.1.100:8888
Receiving packet data...
----------------------------------------------------------------------
[12:34:56.789] TCP aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66 192.168.1.1:443 -> 192.168.1.100:52345 (60 bytes, TTL:64) SYN
    HEX: 45 00 00 3c 1a 2b 40 00 40 06 d4 6c c0 a8 01 01 c0 a8 01 64 01 bb cc 89
[12:34:56.790] TCP 11:22:33:44:55:66 -> aa:bb:cc:dd:ee:ff 192.168.1.100:52345 -> 192.168.1.1:443 (60 bytes, TTL:64) SYN ACK
    HEX: 45 00 00 3c 00 00 40 00 40 06 ef 97 c0 a8 01 64 c0 a8 01 01 cc 89 01 bb

STATS: Total: 1247 | TCP: 892 | UDP: 234 | ICMP: 12 | Other: 109 | Bytes: 1847392
----------------------------------------------------------------------
```

## Troubleshooting

### Permission Denied (Raw Socket)
```bash
# Server must run as root
sudo ./bin/packet_sniffer

# Check if running as root
whoami  # Should show: root
```

### Connection Refused
```bash
# Check if server is running
sudo netstat -tlnp | grep :8888
# OR
sudo ss -tlnp | grep :8888

# Check firewall
sudo ufw status
sudo iptables -L | grep 8888

# Test connectivity
telnet YOUR_SERVER_IP 8888
```

### No Packets Captured
```bash
# Check network interface
ip link show

# Generate test traffic
ping google.com        # ICMP packets
curl google.com        # TCP packets
nslookup google.com    # UDP packets
```

### Build Errors
```bash
# Install missing headers
sudo apt install linux-headers-$(uname -r)
sudo apt install libc6-dev

# Check gcc version
gcc --version
```

## Network Interface Selection

### Find Network Interfaces
```bash
# List all interfaces
ip link show
# OR
ifconfig -a

# Common interfaces:
# eth0, ens33, enp0s3 - Ethernet
# wlan0, wlp2s0 - WiFi
# lo - Loopback (127.0.0.1)
```

### Capture on Specific Interface (Optional)
Modify `packet_sniffer.c` to bind to specific interface:
```c
// Add before socket creation
struct sockaddr_ll sll;
sll.sll_family = AF_PACKET;
sll.sll_ifindex = if_nametoindex("eth0");  // Change interface name
sll.sll_protocol = htons(ETH_P_ALL);

// Bind to interface
bind(raw_socket, (struct sockaddr*)&sll, sizeof(sll));
```

## Security Notes

### Server Security
- Only run on trusted networks
- Monitor who connects to port 8888
- Use firewall to restrict client IPs
- Run with minimal privileges where possible

### Legal Compliance
- Only capture traffic on networks you own
- Inform users if monitoring shared networks
- Follow local privacy laws and regulations
- Use for educational/debugging purposes only

## Stopping the Sniffer

### Graceful Shutdown
```bash
# Press Ctrl+C on both server and client
# Server will show:
^C
Packets captured: 1247
Total bytes: 1847392

# Client will show:
^C
Client disconnected
```

### Force Kill (if needed)
```bash
# Find process ID
ps aux | grep packet_sniffer
sudo kill -9 <PID>

# OR kill all
sudo pkill packet_sniffer
```