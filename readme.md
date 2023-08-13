# Containerized Networking for Proxying

> _identity isolation_ because environ-variable based proxying is not safe for that.

- set your firewall to allow `10.27.0.0/16` of incoming connections (input)
- install the following, make them available in $PATH
  - [tun2socks](https://github.com/xjasonlyu/tun2socks)
  - [dnsproxy](https://github.com/AdguardTeam/dnsproxy)
- for building
  - `libnftnl`
  - `libmnl`
  - `clang` 

## features

1. Configure a few persistent Network Namespaces.
2. Watch for new flatpak processes and configure Network Namespaces for them

Network namespace is more secure than netfilter-only approaches, or `proxychains` the tool. When netns-proxy stops/crashes, or before it configures your app, the internet is disconnected in the netns.

The default profile (like the `"base_p": {}` below) configures the associated NetNSes to be proxied by a socks5 proxy listening on `host_ip:9909`. Typically you can set your proxy to listen on `0.0.0.0:9909`, and secure it with a firewall.

**Notice**: You need set flatpak applications to have `Network` _disabled_, in Flatseal, in order to use this tool. Netns-proxy would try to disable it automatically too.

## usage

start it under a working directory with `secret.json` and `netnsp.json` (optionally) present.

```json
{
  "params": {
    "base_p": {},
    "proxy-a": {
      "cmd": {
        "program": "gost",
        "argv": [
          "-L=socks5://localhost:1080",
          "-F=socks5://$ip_vh:9909",
          "-F=socks5://user:pass@ip:port"
        ]
      },
      "chain": true
    },
    "alt-dns": {
      "dns_argv": [
        "-l",
        "127.0.0.1",
        "-l",
        "127.0.0.53",
        "-l",
        "::1",
        "-p",
        "53",
        "-u",
        "https://dns.google/dns-query",
        "-b",
        "tcp://1.1.1.1:53"
      ]
    }
  },
  "flatpak": {
    "io.github.NhekoReborn.Nheko": "base_p"
  }
}
```

example `secret.json`.

1. It configures several profiles, and they will be instantiated as persistent NetNSes if you run `netnsp-main --pre`.
2. It matches flatpak process by app ID as they start, which you can see by `flatpak list` or `flatpak ps`, and applies the profiles.
3. Arguments may be specified in combination to override internal defaults.

```bash
cargo b
./initial.sh # set capabilities
./setsuid.sh # run this every build
netnsp-main # starts the flatpak watcher, only
netnsp-main --pre # configures the persistent namespaces, and starts the flatpak watcher
netnsp-main exec --ns base_p # enter a shell in netns.
netnsp-main exec --ns base_p --cmd bash # specify the command to execute
```

with `netns-main exec --ns target_ns` it can start a process with everything unchanged but netns.
`sudo` with `ip netns exec` would mess up a lot of things.

- use [opensnitch firewall](https://github.com/evilsocket/opensnitch) as the second layer of defense, in case you do anything wrong, like launching an app outside netns.

Some socks proxies support UDP, and some do not. The dnsproxy it starts by default runs on TCP.

## use with mullvad-browser

0. enter netns with `netnsp-main exec --ns base_p`
1. run `./start-mullvad-browser.desktop -p` and create your profiles, name them, `i2p` and `base_p`
2. use `./start-mullvad-browser.desktop -p base_p` next time

using the tarball of mullvadbrowser seems better than other packagings, for now.

## use with Nym, chaining proxies

```json
{
  "params": {
    "base_p": {},
    "gw": {
      "cmd": {
        "program": "/space/Apps/nym-socks5-client",
        "argv": ["run", "--id", "netnx"]
      },
      "su_cmd": {
        "program": "/usr/bin/bash",
        "argv": ["nym.sh"]
      }
    },
    "sub": {
      "connect": "gw",
      "tun2socks": false,
      "dnsproxy": false
    }
  },
  "flatpak": {
    "io.github.NhekoReborn.Nheko": "base_p",
    "com.belmoussaoui.Decoder": "sub"
  }
}

```

1. Initialize Nym as they said. 
2. The nftables script for port redirection is provided in this repo. (their socks client can't change listen address for now)
3. `gw` is the container for Nym client, with the TUN connected to the first layer of proxy. 
4. `sub` can be instantiated to one container per app.

## random

you probably need application state isolation, for different identities.

so that, for example, IPFS does not use the same peerID with and without VPN. that achieves anonymity, even though IPFS has no anonymity whatever.

It's possible to have network namespaces recursively, but directly running this script would run into file name conflicts. You need some kind of filesystem sandbox, or modify the script to use a different directory.

- https://github.com/nixpak/nixpak
- https://sr.ht/~fgaz/nix-bubblewrap/

todo

- socks proxy tester
  - does it support udp, tcp by ip, tcp by host
- replace veth pair with socks proxy forwarder
  - http for i2p
  - if veth, block forward in netns