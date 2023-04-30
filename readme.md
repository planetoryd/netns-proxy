# netns-based selective proxying, identity isolation

> Automated configuration script written in Rust, because Bash sucks.

aka

- Netns with default gateways to VPNs
- VPN without making it the default gateway 

do:

- set your firewall to allow 10.0.0.0/8
- read the code

why:

- everything is in foreground, at your will
- netns is lightweight