#!/bin/bash
# client_entrypoint.sh

# Use environment variables if set, otherwise use defaults
SERVER_IP=${VPN_SERVER_IP:-vpn-server}
SERVER_PORT=${VPN_SERVER_PORT:-8000}
SECRET=${VPN_SECRET:-test}
TARGET=${1:-192.168.0.1}

# Resolve hostname to IP if needed
if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    # Already an IP address
    REMOTE_VIP="$TARGET"
    echo "Target is already an IP address: ${REMOTE_VIP}"
else
    # Use dig to resolve hostname
    echo "Resolving hostname: ${TARGET}..."
    REMOTE_VIP=$(dig +short "$TARGET" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1)

    if [ -z "$REMOTE_VIP" ]; then
        echo "ERROR: Failed to resolve hostname '${TARGET}'"
        exit 1
    fi

    echo "Resolved ${TARGET} to ${REMOTE_VIP}"
fi

echo "Pinging ${REMOTE_VIP} via VPN server ${SERVER_IP}:${SERVER_PORT}..."
echo "Note: Local virtual IP will be automatically assigned by the server"
exec ./ToyVpnPing "$SERVER_IP" "$SERVER_PORT" "$SECRET" "$REMOTE_VIP"
