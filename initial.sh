#!/usr/bin/env bash
setcap 'cap_net_bind_service=+ep' $(which dnsproxy)
setcap 'cap_net_bind_service=+ep' $(which tun2socks)