# netns-based selective proxying, identity isolation

> Automated configuration script written in Rust, because Bash sucks.

aka

- Netns with default gateways to VPNs
- VPN without making it the default gateway 

it configures a few network namespaces i need, and starts `tun2socks` in some of them to turn socks proxies into VPNs. 
`dnsproxy` is chosen and used in every netns. `gost` for chaining proxies, although it is be possible with nftables.

do:

- set your firewall to allow 10.0.0.0/8
- run [REPO/initial.sh](./initial.sh)
- read the code

why:

- everything is in foreground, at your will
- netns is lightweight
- ability to do everything, to be as root, while being and only being proxied (no further sandboxing by itself)
    - so this is not a particular sandbox for specific flatpak-apps
    - so you can do package updates
- everything JUST works, the execution environment is untampered.

example `secret.json`

```json
{
  "proxies": {
    "clean_ipv6": ["socks5://example.com:8080"]
  }
}
```

## use with mullvad-browser

0. enter netns with `netnsp-main exec --ns base_p`
1. run `./start-mullvad-browser.desktop -p` and create your profiles, name them, `i2p` and `base_p`
2. use `./start-mullvad-browser.desktop -p base_p` next time

using the tarball of mullvadbrowser seems better than other packagings, for now.

options

1. run mullvad-browser in `base_p` and use proxy container addon for second-hop 
  - this is subject to random webrtc leaks and such. anyway more defenses against shitcode the better
2. run browser in `clean_ip1`

## setup

some are todos

1. `base_p`, configured for the base proxy. intended to be a basis, crossing firewalls
2. `clean_ip1` and `clean_ipv6`, for second-hops, as vpn exits tend to be ip-blacklisted
3. `i2p`, netns that can only access i2p
4. `lokins`, not sure how to do this

## make it SUID, and the exec feature

make it SUID, and with `netns-proxy exec --ns target_ns` it can start a process with everything unchanged but netns

minimally obtrusive, while `sudo` messes with a lot of things

by default it starts `fish`

- you can use it to enter netns, but (probably) programs cant use it to escape a netns

## security

- when configuring, it stores the inode number of root netns in netns.json 
- when `exec`-ing, it checks if current netns matches the recorded inode number
- if it matches, the process is in the root netns, it proceeds to enter the desired netns
