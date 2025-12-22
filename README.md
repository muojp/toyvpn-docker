# ToyVpn-docker (Linux Server & Ping Client)

This repository provides a Docker-based environment for ToyVPN with additional testing utilities.

**Note**: The ToyVPN implementation itself is from Google's [Android ToyVPN sample](https://android.googlesource.com/platform/development/+/master/samples/ToyVpn/). This repository is an independent wrapper that:
- Packages ToyVPN in Docker containers for easy deployment and testing
- Adds testing utilities (UDP echo server, multiple client support)
- Provides a simple docker-compose configuration for local development

The core VPN implementation provides a simple VPN using TUN/TAP devices and UDP encapsulation.

## Components

- **ToyVpnServer**: A C++ implementation of a VPN server that creates a `tun` interface and forwards packets between the tunnel and UDP sockets. (from Google's AOSP)
- **ToyVpnPing**: A C client that simulates a VPN connection and sends ICMP Echo Requests (ping) through the tunnel to a target destination (added in this repository)
- **UDP Echo Server**: A testing utility using `socat` for UDP traffic verification (added in this repository)
- **Docker Compose Setup**: Multi-container orchestration with support for simultaneous client connections (added in this repository)

## Prerequisites

- Docker and Docker Compose
- Linux host (required for TUN/TAP and iptables features used in the container)

## Usage

### 1. Start the VPN Server

The server runs as a daemon. It will set up the `tun0` interface and configure iptables for NAT.

```bash
docker compose up -d vpn-server
```

The VPN server listens on UDP port 8000 and handles:
- Client handshake and virtual IP assignment
- Packet forwarding between VPN tunnel and physical network
- NAT configuration for outbound traffic
- Simultaneous connections from multiple clients

### 2. Run the Ping Client (One-time Task)

The client is configured as a "one-time" service. You can run it manually to test the VPN connection. By default, it pings `192.168.0.1`.

```bash
docker compose run --rm vpn-client-icmp-ping
```

You can also specify a custom target to ping:

```bash
docker compose run --rm vpn-client-icmp-ping foo.example.com
```

This will:
1. Connect to the `vpn-server`.
2. Perform a handshake.
3. Start sending pings to the target IP or hostname through the VPN.

### 3. UDP Echo Server (Testing Utility)

A UDP echo server is available for testing UDP traffic through the VPN tunnel:

```bash
docker compose up -d udp-echo-server
```

The echo server uses `socat` to echo back any UDP packets sent to it. By default it listens on port 22840, but you can configure it:

```bash
UDP_ECHO_PORT=12345 docker compose up -d udp-echo-server
```

The server is accessible at `172.25.0.5` within the Docker network.

### 4. Testing Multiple Simultaneous Clients

The `--profile client` option allows you to start multiple VPN clients simultaneously to test concurrent connections:

```bash
docker compose --profile client up
```

This will start:
- `vpn-client-1` (172.25.0.3, VPN IP: 172.31.0.2)
- `vpn-client-2` (172.25.0.4, VPN IP: 172.31.0.3)

Both clients will ping the server simultaneously, allowing you to verify that:
- The server correctly handles multiple concurrent connections
- Each client receives its own virtual IP address
- Ping responses are correctly routed back to the originating client
- No packet interference occurs between clients

To view logs from both clients:
```bash
docker compose --profile client logs -f
```

### 5. Viewing Logs

To see the server logs:
```bash
docker compose logs -f vpn-server
```

### 6. Cleanup

To stop and remove the server and network:
```bash
docker compose down
```

## Network Configuration

- **Docker Network**: `172.25.0.0/24`
  - Server IP: `172.25.0.2`
  - Client 1 IP: `172.25.0.3`
  - Client 2 IP: `172.25.0.4`
  - UDP Echo Server IP: `172.25.0.5`
- **VPN Virtual Subnet**: `172.31.0.0/24`
  - Server Virtual IP: `172.31.0.1`
  - Client 1 Virtual IP: `172.31.0.2`
  - Client 2 Virtual IP: `172.31.0.3`

## Security Warning

This is a **demonstration project** from the Android Open Source Project. It does **not** provide encryption or strong authentication. **Do not use this for securing sensitive data.**
