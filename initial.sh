#!/usr/bin/env bash
setcap 'cap_net_bind_service=+ep' $(which dnsproxy)
setcap 'cap_net_bind_service=+ep' $(which tun2socks)
echo 1 > /proc/sys/net/ipv4/ip_forward