# netns-based selective proxying, identity isolation

> Automated configuration script written in Rust, because Bash sucks.

aka

- Netns with default gateways to VPNs
- VPN without making it the default gateway 

it configures a few network namespaces i need, and starts `tun2socks` in some of them to turn socks proxies into VPNs. 
`dnsproxy` is chosen and used in every netns. `gost` for chaining proxies, although it is be possible with nftables.

do:

- set your firewall to allow 10.0.0.0/8
- read the code
- install the following, make them available in $PATH
  - [tun2socks](https://github.com/xjasonlyu/tun2socks)
  - [gost](https://github.com/go-gost/gost)
  - [dnsproxy](https://github.com/AdguardTeam/dnsproxy) 
  - iproute2

why:

- everything is in foreground, at your will
- netns is lightweight
- ability to do everything, to be as root, while being and only being proxied (no further sandboxing by itself)
    - so this is not a particular sandbox for specific flatpak-apps
    - so you can do package updates
- everything JUST works, the execution environment is untampered.
- it's hard to do this safely with only nftables (as far as I know. the interfaces go down and traffic may leak)

## usage

```bash
cargo b
./initial.sh # set capabilities
./setsuid.sh # run this every build
netnsp-main # configures the OS, and supervises the daemons. run it under the project root directory
netnsp-main exec --ns base_p # enter a shell in netns.
```

with `netns-main exec --ns target_ns` it can start a process with everything unchanged but netns

minimally obtrusive, while `sudo` messes with a lot of things

by default it starts `fish`

## available NetNSes

1. `base_p`, configured for the base proxy. intended to be a basis, crossing firewalls
    - you need a socks5 proxy in the root namespace, listening on `0.0.0.0:9909` 
2. `clean_ip1` and `clean_ipv6`, for second-hops, as vpn exits tend to be ip-blacklisted
    - configure [secret.json](./secret.json)
3. (todo) `i2p`, netns that can only access i2p
4. (todo) `lokins`

example `secret.json`

```json
{
  "proxies": {
    "clean_ipv6": ["socks5://example.com:8080"]
  }
}
```

- `netnsp-main` may be run repeatedly without issues. ignore the errors and warnings
    - in case of altered OS config state, try to reboot, or manually remove the NetNSes and `netnsp-main stop` to kill orphan processes

## security

- when configuring, it stores the inode number of root netns in netns.json 
- when `exec`-ing, it checks if current netns matches the recorded inode number
- if it matches, the process is in the root netns, it proceeds to enter the desired netns

## use with Flatpak

> It's possible to use it with Flatpaks, since it is maximally non-obtrusive anyway. 
>
> I'm not sure about the security implications. 

```bash
netnsp-main exec --ns base_p # enter a shell in netns.
flatpak run tld.app.some
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


## alternatives

- Application configured with proxies through environment variables
  - insecure, prone to misconfiguration and DNS leaks, catastrophic to anonymity
- Netfilter, firewalls
  - manual iptables fwmark + tun2socks, works but needs careful hardening
  - (kinda planned) opensnitch https://github.com/evilsocket/opensnitch/issues/437
  - portmaster, which doesnt meet my needs, https://github.com/safing/portmaster/issues/1153
- if only firejail supports specifying TUNs https://github.com/netblue30/firejail/issues/1814
- if only flatpak/bubblewrap supports NetNSes 
  - https://github.com/flatpak/flatpak/issues/1202
  - https://github.com/containers/bubblewrap/issues/361
- LXC. for me, netns is enough, and sandboxing is better done by other tooling.

## tip

- use [opensnitch firewall](https://github.com/evilsocket/opensnitch) as the second layer of defense, in case you do anything wrong, like launching an app outside netns.

## random

- https://github.com/nixpak/nixpak
- https://sr.ht/~fgaz/nix-bubblewrap/

you probably need application state isolation, for different identities.

so that, for example, IPFS does not use the same peerID with and without VPN.

that achieves anonymity, even though IPFS has no anonymity whatever.