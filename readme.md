# Containerized solution to network proxying

`nsproxy` is a single binary that can run as a SUID daemon, or to control the daemon, along with some netns related utilities. 

- set your firewall to allow `10.0.0.0/8` of incoming connections (input)
- install the following, make them available in `$PATH`
  - [tun2socks](https://github.com/xjasonlyu/tun2socks)
  - [dnsproxy](https://github.com/AdguardTeam/dnsproxy)
- for building
  - `libnftnl`
  - `libmnl`
  - `clang` 

## TUN, TAP, SOCKS5

Many VPNs only expose a TUN interface, which can not be directly used in a containerized setup. You need at least a TAP. If you run the VPN in a net NS, you have to make internet open to it, with a lot of configuration, which may lessen security of the sandbox. You can try https://github.com/jamesmcm/vopono but it looks complex.

In the case of *netns-proxy*, the sandboxing part is entirely handled by a small trusted codebase. You don't need to trust the VPN vendor to decide when to route through a proxy and when not, and for what applications.

### Socks5, HTTP ✅

Netns-proxy can create a pair of veth, between your application netns and the root netns, which is a small opening of the sandbox.

There are two ways of using SOCKS5, or HTTP proxy

- Manual DNS resolution with local `dnsproxy`, with IP address passed to the proxy.
  - *netns-proxy* maintains a `dnsproxy` and `tun2socks` for each sandbox. The DNS queries will go through `tun2socks` which directs the traffic through your configured proxy.
    - You can configure `dnsproxy` to use UDP or more secure protocols
  - Compatible with applications without proxy support.
- DNS-less usage of SOCKS5 / HTTP proxy
  - Both protocols can be used without DNS. 
  - You need to expose the proxy by having it to listen on `0.0.0.0` and configure applications to use the proxy.

### I2P, Tor ✅

I2P can only be used through its HTTP proxy (similar to SOCKS) because it doesn't have the traditional addresseing and domain-naming of World-Wide-Web.

### Lokinet

Lokinet provides a TUN, which can not be used with netns-proxy. They [plan](https://github.com/oxen-io/lokinet/issues/2140) to do selective routing through GID, which is out of scope for *netns-proxy*.

## Security

If you are aiming for anonymity, it may be not enough as the sandboxing is limited to network, and not anything else. A program can leak identity-rich information through any other channel, causing another program to start outside of the intended Net NS.

I haven't reviewed my code. The sockets, config files should be protected with correct perms.

### Comparison with alternatives

- `proxychains` may fail without visible indication, which leaks your traffic for some programs.
- `sudo <blah> ip netns exec <blah>` with hand-configured netns. `sudo` will break a lot of programs in this setting.
- *netfilter* in general. It varies, and in the worst case traffic may leak.
- [opensnitch](https://github.com/evilsocket/opensnitch). It's recommened as the second line of defense.

## Related

- https://github.com/stevenengler/socksns
