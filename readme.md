# netns-based selective proxying, identity isolation

> Automated configuration script written in Rust, because Bash sucks.

aka

- Netns with default gateways to VPNs
- VPN without making it the default gateway 

do:

- set your firewall to allow 10.0.0.0/8
- run [REPO/initial.sh](./initial.sh)
- read the code

why:

- everything is in foreground, at your will
- netns is lightweight

example `secret.json`

```json
{
  "proxies": {
    "clean_ipv6": ["socks5://example.com:8080"]
  }
}
```