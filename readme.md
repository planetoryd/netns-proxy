# Netns-based selective proxying, for identity isolation

- set your firewall to allow `10.27.0.0/16`
- install the following, make them available in $PATH
  - [tun2socks](https://github.com/xjasonlyu/tun2socks)
  - [dnsproxy](https://github.com/AdguardTeam/dnsproxy)
- for building
  - `libnftnl`
  - `libmnl`

## features

1. Configure a few persistent Network Namespaces
2. Watch for new flatpak processes and configure Network Namespaces for them

Network namespace is more secure than netfilter-only approaches.

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
    }
  },
  "flatpak": {
    "io.github.NhekoReborn.Nheko": "base_p"
  }
}
```

example `secret.json`

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

## use with mullvad-browser

0. enter netns with `netnsp-main exec --ns base_p`
1. run `./start-mullvad-browser.desktop -p` and create your profiles, name them, `i2p` and `base_p`
2. use `./start-mullvad-browser.desktop -p base_p` next time

using the tarball of mullvadbrowser seems better than other packagings, for now.

## random

you probably need application state isolation, for different identities.

so that, for example, IPFS does not use the same peerID with and without VPN. that achieves anonymity, even though IPFS has no anonymity whatever.

It's possible to have network namespaces recursively, but directly running this script would run into file name conflicts. You need some kind of filesystem sandbox, or modify the script to use a different directory.

- https://github.com/nixpak/nixpak
- https://sr.ht/~fgaz/nix-bubblewrap/
