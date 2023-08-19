# Containerized solution to network proxying

> It only sandboxes the network and *nothing* else.

`nsproxy` is a single binary that can run as a SUID daemon, or to control the daemon, along with some netns related utilities. 

- set your firewall to allow `10.0.0.0/8` of incoming connections (input)
- install the following, make them available in $PATH
  - [tun2socks](https://github.com/xjasonlyu/tun2socks)
  - [dnsproxy](https://github.com/AdguardTeam/dnsproxy)
- for building
  - `libnftnl`
  - `libmnl`
  - `clang` 

## TUN, TAP, SOCKS5

Many of the VPNs only expose a TUN interface, which can not be directly used in a containerized setup. You need at least a TAP. If you run the VPN in a net NS, you have to make internet open to it, with a lot of configuration, which may lessen security of the sandbox. You can try https://github.com/jamesmcm/vopono but it looks complex.

In the case of *netns-proxy*, the sandboxing part is entirely handled by a small trusted codebase. You don't need to trust the VPN vendor to decide when to route through a proxy and when not, and for what applications.

### I2P

I2P can only be used through its HTTP proxy (similar to SOCKS) because it doesn't have the traditional addresseing and domain-naming of World-Wide-Web.

### Lokinet

Lokinet provides a TUN, which can not be used with netns-proxy. They [plan](https://github.com/oxen-io/lokinet/issues/2140) to do selective routing through GID.

## Security

I haven't reviewed my code. The sockets, config files should be protected with correct perms.

- remove other addrs for a dev

## Related

- https://github.com/stevenengler/socksns

- A user can't just delete state file. the mess has to be cleaned up.