#!/bin/bash
# server_entrypoint.sh

# IPフォワーディング有効化
echo 1 > /proc/sys/net/ipv4/ip_forward

# TUNインターフェースの作成と設定
ip tuntap add dev tun0 mode tun
ip addr add 172.31.0.1/24 dev tun0
ip link set tun0 up

# NAT (MASQUERADE) 設定
iptables -t nat -A POSTROUTING -s 172.31.0.0/24 -o eth0 -j MASQUERADE

# サーバーの起動
echo "Starting ToyVpnServer on tun0..."
exec ./ToyVpnServer tun0 8000 test -m 1400 -a 172.31.0.2 32 -d 8.8.8.8 -r 0.0.0.0 0
