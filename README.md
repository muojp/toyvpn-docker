# ToyVpn-mod (Rust Server + C Client)

A Docker-based VPN testing environment with a Rust server implementation.

**Note**: Originally based on Google's [Android ToyVpn sample](https://android.googlesource.com/platform/development/+/master/samples/ToyVpn/), the server has been completely rewritten in Rust to fix stability issues in testing. This repository provides:
- **Rust VPN Server**: Async server with IP pool management and robust session handling
- **C VPN Client**: Lightweight testing client (from original AOSP implementation)
- **Docker Environment**: Easy deployment with docker-compose
- **Testing Utilities**: UDP echo server, multiple concurrent client support

The VPN uses TUN/TAP devices and UDP encapsulation for packet transport.

## Components

- **ToyVpnServer (Rust)**: A Rust + tokio implementation of a VPN server with improved session management and IP pool handling. Fixes long-running stability issues found in the original C++ version. (rewritten for this repository)
- **ToyVpnPing**: A C client that simulates a VPN connection and sends ICMP Echo Requests (ping) through the tunnel to a target destination (added in this repository)
- **UDP Echo Server**: A testing utility using `socat` for UDP traffic verification (added in this repository)
- **Docker Compose Setup**: Multi-container orchestration with support for simultaneous client connections (added in this repository)

### Rust Rewrite Improvements

The server has been rewritten in Rust with the following improvements:

- **IP Pool with Reuse**: Automatically reuses freed IP addresses, preventing exhaustion even after thousands of client reconnections
- **Robust Session Management**: Properly handles NAT remapping and UDP port changes without creating duplicate sessions
- **Configurable Timeout**: 5-minute session timeout (vs. 60 seconds in C++ version) reduces false disconnections
- **Async I/O**: Async packet processing with tokio for better performance and zero idle CPU usage
- **Memory Safety**: Rust guarantees prevent buffer overflows and memory leaks
- **Comprehensive Testing**: Full unit test coverage for IP pool, session management, and protocol handling

## Project Structure

```
toyvpn-mod/
├── rust/              # Rust implementation (active)
│   ├── Cargo.toml
│   └── src/
├── legacy/            # C/C++ implementation (deprecated, kept for client)
│   ├── ToyVpnServer.cpp
│   ├── ToyVpnPing.c
│   └── Makefile
└── docker/            # Docker configurations
    ├── server/        # Builds from rust/
    └── client/        # Builds from legacy/
```

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
- Client handshake with automatic virtual IP assignment
- Packet forwarding between VPN tunnel and physical network
- NAT configuration for outbound traffic
- Simultaneous connections from multiple clients (VIPs are automatically allocated sequentially)

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
2. Perform a handshake and receive an automatically assigned virtual IP.
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
- `vpn-client-1` (Docker IP: 172.25.0.3, VPN IP: automatically assigned, typically 172.31.0.2)
- `vpn-client-2` (Docker IP: 172.25.0.4, VPN IP: automatically assigned, typically 172.31.0.3)

Both clients will ping the server simultaneously, allowing you to verify that:
- The server correctly handles multiple concurrent connections
- Each client receives its own automatically assigned virtual IP address
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

To enable debug logging:
```bash
RUST_LOG=debug docker compose up vpn-server
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
  - Client Virtual IPs: Automatically assigned starting from `172.31.0.2` (increments for each new client)

## iptables Configuration (Automatic)

The VPN server automatically configures iptables for routing and NAT when started. The configuration is handled by `docker/server/server_entrypoint.sh` and includes:

### 1. Enable IP Forwarding
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

### 2. Create and Configure TUN Interface
```bash
ip tuntap add dev tun0 mode tun
ip addr add 172.31.0.1/24 dev tun0
ip link set tun0 up
```

### 3. Configure NAT with MASQUERADE
```bash
iptables -t nat -A POSTROUTING -s 172.31.0.0/24 -o eth0 -j MASQUERADE
```

This MASQUERADE rule enables NAT for packets from the VPN subnet (`172.31.0.0/24`) going out through the `eth0` interface, allowing VPN clients to access external networks.

### Systemd Installation (Recommended for Production)

For running the VPN server as a systemd service on a Linux host (outside Docker), use the provided installation script. The script will build the binary as your regular user, then request sudo privileges only for the installation steps:

```bash
# Install and configure the server as a systemd service (no sudo needed initially)
./install-server.sh
```

This will:
- Build the Rust binary in release mode
- Install the binary to `/opt/toyvpn-server/`
- Create a systemd service file at `/etc/systemd/system/toyvpn-server.service`
- Configure IP forwarding permanently
- Set up automatic TUN interface creation and iptables NAT rules

After installation:
```bash
# Start the service
sudo systemctl start toyvpn-server

# Check status
sudo systemctl status toyvpn-server

# View logs
sudo journalctl -u toyvpn-server -f

# Stop the service
sudo systemctl stop toyvpn-server
```

To uninstall:
```bash
sudo ./uninstall-server.sh
```

**Important**: Before installing, check your external network interface name (e.g., `eth0`, `ens33`, `enp0s3`) and edit the `EXTERNAL_INTERFACE` variable in `install-server.sh` if needed. You can find your interface name with:
```bash
ip addr show
```

### Manual Configuration (Outside Docker)

If you prefer to run the server manually without systemd, you need to configure these settings yourself:

```bash
# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Create TUN interface
sudo ip tuntap add dev tun0 mode tun
sudo ip addr add 172.31.0.1/24 dev tun0
sudo ip link set tun0 up

# Configure NAT (replace eth0 with your external interface)
sudo iptables -t nat -A POSTROUTING -s 172.31.0.0/24 -o eth0 -j MASQUERADE

# Run the server
sudo ./target/release/toyvpn-server tun0 8000 test -m 1400 -a 172.31.0.2 32 -d 8.8.8.8 -r 0.0.0.0 0
```

To make IP forwarding persistent across reboots, edit `/etc/sysctl.conf`:
```bash
net.ipv4.ip_forward = 1
```

Then apply the changes:
```bash
sudo sysctl -p
```

## Development

### Local Rust Development

```bash
# Build and test
cd rust
cargo build --release
cargo test

# Run locally (requires root for TUN device)
sudo ./target/release/toyvpn-server tun0 8000 test a,172.31.0.2,32 m,1400 r,0.0.0.0,0
```

### Docker Development

```bash
# Rebuild server after code changes
docker compose build vpn-server
docker compose up vpn-server

# Rebuild client
docker compose build vpn-client-icmp-ping
```

### Directory Structure

- `rust/` - Rust server implementation (active development)
- `legacy/` - Original C/C++ code (kept for client compatibility)
- `docker/` - Docker build configurations

## Contributing

Pull requests are welcome! Please ensure:
- All Rust tests pass: `cd rust && cargo test`
- Code is formatted: `cargo fmt`
- No clippy warnings: `cargo clippy`

## Security Warning

This is a **demonstration project** originally from the Android Open Source Project. The server has been rewritten in Rust for improved stability, but the core protocol remains unchanged.

This implementation does **not** provide encryption or strong authentication. **Do not use this for securing sensitive data.**

## Credits

- **Original Implementation**: Google's Android Open Source Project (AOSP) - [ToyVpn sample](https://android.googlesource.com/platform/development/+/master/samples/ToyVpn/)
- **Rust Server Rewrite**: This repository (fixes long-running stability issues)
- **Client Implementation**: Based on AOSP ToyVpn client
- **Docker Integration**: This repository
