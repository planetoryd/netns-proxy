#!/usr/bin/env bash
setcap 'cap_net_bind_service=ep' $(which dnsproxy)
setcap -v 'cap_net_bind_service=ep' $(which dnsproxy) # -v does not change caps.
setcap 'cap_net_bind_service=ep' $(which tun2socks)
setcap -v 'cap_net_bind_service=ep' $(which tun2socks)
# echo 1 > /proc/sys/net/ipv4/ip_forward