#!/bin/bash
# uninstall-server.sh - Uninstall ToyVPN Rust server systemd service

set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

# Configuration variables (must match install-server.sh)
INSTALL_DIR="/opt/toyvpn-server"
SERVICE_NAME="toyvpn-server"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
TUN_DEVICE="tun0"
VPN_SUBNET="172.31.0.0/24"
EXTERNAL_INTERFACE="eth0"  # Should match your installation

echo "=== ToyVPN Server Uninstallation ==="
echo ""

# Step 1: Stop the service if running
echo "[1/6] Stopping service (if running)..."
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    systemctl stop "${SERVICE_NAME}"
    echo "  Service stopped."
else
    echo "  Service is not running."
fi

# Step 2: Disable the service
echo "[2/6] Disabling service..."
if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
    systemctl disable "${SERVICE_NAME}"
    echo "  Service disabled."
else
    echo "  Service is not enabled."
fi

# Step 3: Clean up network configuration
echo "[3/6] Cleaning up network configuration..."

# Remove iptables NAT rule
if iptables -t nat -C POSTROUTING -s "${VPN_SUBNET}" -o "${EXTERNAL_INTERFACE}" -j MASQUERADE 2>/dev/null; then
    iptables -t nat -D POSTROUTING -s "${VPN_SUBNET}" -o "${EXTERNAL_INTERFACE}" -j MASQUERADE
    echo "  iptables NAT rule removed."
else
    echo "  iptables NAT rule not found (already removed or different interface)."
fi

# Remove TUN device
if ip link show "${TUN_DEVICE}" &>/dev/null; then
    ip link set "${TUN_DEVICE}" down 2>/dev/null || true
    ip tuntap del dev "${TUN_DEVICE}" mode tun 2>/dev/null || true
    echo "  TUN device removed."
else
    echo "  TUN device not found (already removed)."
fi

# Step 4: Remove systemd service file
echo "[4/6] Removing systemd service file..."
if [ -f "${SERVICE_FILE}" ]; then
    rm -f "${SERVICE_FILE}"
    systemctl daemon-reload
    echo "  Service file removed."
else
    echo "  Service file not found."
fi

# Step 5: Remove installation directory
echo "[5/6] Removing installation directory..."
if [ -d "${INSTALL_DIR}" ]; then
    rm -rf "${INSTALL_DIR}"
    echo "  Installation directory removed."
else
    echo "  Installation directory not found."
fi

# Step 6: Ask about IP forwarding
echo "[6/6] IP forwarding configuration..."
echo ""
echo "Note: IP forwarding is still enabled in /etc/sysctl.conf"
echo "      (net.ipv4.ip_forward=1)"
echo ""
read -p "Do you want to disable IP forwarding? (y/N): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Remove or comment out the IP forwarding line
    sed -i '/^net.ipv4.ip_forward=1/d' /etc/sysctl.conf
    sysctl -w net.ipv4.ip_forward=0 > /dev/null
    echo "  IP forwarding disabled."
else
    echo "  IP forwarding kept enabled."
fi

echo ""
echo "=== Uninstallation Complete ==="
echo ""
echo "The ToyVPN server has been removed from your system."
echo ""
