#!/bin/bash
# install-server.sh - Install ToyVPN Rust server as a systemd service

set -e

# Configuration variables
INSTALL_DIR="/opt/toyvpn-server"
BIN_NAME="toyvpn-server"
SERVICE_NAME="toyvpn-server"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
USER="root"  # VPN server needs root for TUN device and iptables

# VPN Configuration
TUN_DEVICE="tun0"
VPN_PORT="8000"
VPN_SECRET="test"
VPN_SUBNET="172.31.0.0/24"
VPN_SERVER_IP="172.31.0.1"
VPN_CLIENT_START_IP="172.31.0.2"
MTU="1400"
DNS_SERVER="8.8.8.8"
EXTERNAL_INTERFACE="eth0"  # Change this to your external interface (e.g., ens33, enp0s3)

echo "=== ToyVPN Server Installation ==="
echo ""

# Step 1: Build the Rust binary (as regular user, no sudo needed)
echo "[1/6] Building Rust binary..."

if [ ! -f "rust/Cargo.toml" ]; then
    echo "Error: rust/Cargo.toml not found. Please run this script from the project root directory."
    exit 1
fi

if ! command -v cargo &> /dev/null; then
    echo "Error: Rust/Cargo is not installed or not in PATH."
    echo "Please install Rust first:"
    echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    echo "  source ~/.cargo/env"
    echo ""
    echo "Or if Rust is already installed, add it to your PATH:"
    echo "  source ~/.cargo/env"
    exit 1
fi

cd rust
cargo build --release
cd ..

if [ ! -f "rust/target/release/${BIN_NAME}" ]; then
    echo "Error: Build failed. Binary not found at rust/target/release/${BIN_NAME}"
    exit 1
fi

echo "Build successful!"
echo ""

# Now check for root privileges for installation steps
if [ "$EUID" -ne 0 ]; then
    echo "Installation requires root privileges."
    echo "Please enter your password to continue with installation..."
    echo ""
    exec sudo "$0" "$@"
    exit $?
fi

# Step 2: Create installation directory
echo "[2/6] Creating installation directory at ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"

# Step 3: Copy binary
echo "[3/6] Installing binary..."
cp "rust/target/release/${BIN_NAME}" "${INSTALL_DIR}/"
chmod +x "${INSTALL_DIR}/${BIN_NAME}"

# Step 4: Create systemd service file
echo "[4/6] Creating systemd service file..."
cat > "${SERVICE_FILE}" << EOF
[Unit]
Description=ToyVPN Server (Rust)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${USER}
WorkingDirectory=${INSTALL_DIR}
Environment="RUST_LOG=info"

# Pre-start script to configure network
ExecStartPre=/bin/sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
ExecStartPre=/bin/sh -c 'ip tuntap add dev ${TUN_DEVICE} mode tun || true'
ExecStartPre=/bin/sh -c 'ip addr add ${VPN_SERVER_IP}/24 dev ${TUN_DEVICE} || true'
ExecStartPre=/bin/sh -c 'ip link set ${TUN_DEVICE} up'
ExecStartPre=/bin/sh -c 'iptables -C FORWARD -i ${TUN_DEVICE} -j ACCEPT 2>/dev/null || iptables -I FORWARD -i ${TUN_DEVICE} -j ACCEPT'
ExecStartPre=/bin/sh -c 'iptables -C FORWARD -o ${TUN_DEVICE} -j ACCEPT 2>/dev/null || iptables -I FORWARD -o ${TUN_DEVICE} -j ACCEPT'
ExecStartPre=/bin/sh -c 'iptables -t nat -C POSTROUTING -s ${VPN_SUBNET} -o ${EXTERNAL_INTERFACE} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s ${VPN_SUBNET} -o ${EXTERNAL_INTERFACE} -j MASQUERADE'

# Start the VPN server
ExecStart=${INSTALL_DIR}/${BIN_NAME} ${TUN_DEVICE} ${VPN_PORT} ${VPN_SECRET} -m ${MTU} -a ${VPN_CLIENT_START_IP} 32 -d ${DNS_SERVER} -r 0.0.0.0 0

# Post-stop cleanup
ExecStopPost=/bin/sh -c 'iptables -D FORWARD -o ${TUN_DEVICE} -j ACCEPT 2>/dev/null || true'
ExecStopPost=/bin/sh -c 'iptables -D FORWARD -i ${TUN_DEVICE} -j ACCEPT 2>/dev/null || true'
ExecStopPost=/bin/sh -c 'iptables -t nat -D POSTROUTING -s ${VPN_SUBNET} -o ${EXTERNAL_INTERFACE} -j MASQUERADE 2>/dev/null || true'
ExecStopPost=/bin/sh -c 'ip link set ${TUN_DEVICE} down 2>/dev/null || true'
ExecStopPost=/bin/sh -c 'ip tuntap del dev ${TUN_DEVICE} mode tun 2>/dev/null || true'

Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

# Step 5: Enable IP forwarding permanently
echo "[5/6] Configuring permanent IP forwarding..."
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p > /dev/null
fi

# Step 6: Reload systemd and enable service
echo "[6/6] Enabling systemd service..."
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Configuration:"
echo "  Install directory: ${INSTALL_DIR}"
echo "  Service name: ${SERVICE_NAME}"
echo "  TUN device: ${TUN_DEVICE}"
echo "  VPN port: ${VPN_PORT}"
echo "  VPN subnet: ${VPN_SUBNET}"
echo "  External interface: ${EXTERNAL_INTERFACE}"
echo ""
echo "Usage:"
echo "  Start:   sudo systemctl start ${SERVICE_NAME}"
echo "  Status:  sudo systemctl status ${SERVICE_NAME}"
echo "  Logs:    sudo journalctl -u ${SERVICE_NAME} -f"
echo "  Stop:    sudo systemctl stop ${SERVICE_NAME}"
echo ""
echo "Note: If your external interface is not '${EXTERNAL_INTERFACE}',"
echo "      please edit ${SERVICE_FILE}"
echo "      and change the EXTERNAL_INTERFACE variable, then run:"
echo "      sudo systemctl daemon-reload"
echo ""
