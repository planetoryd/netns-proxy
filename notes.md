# unstructured whims


- Package for Nix
- Handle DNS better. 
    - In-NS netfilter redirection. refer to /etc/resolvd
    - `/etc/resolv.conf` by default doesnt point to 127.0.0.53, but 192.168.x.x which will go nowhere.
- Check deps

`RUST_LIB_BACKTRACE=1` for backtrace
`RUST_LOG=trace`

### Debugging

```bash

sudo ./setsuid.sh $(which lldb-server)
lldb-server p --server --listen "*:2222"

# have to attach to child processes

# LLDB ext in vscode has bugs. so no.

gdbserver --no-startup-with-shell 10.27.0.1:2222 ./target/debug/test-sub

# it hangs with shell. no idea.

set follow-fork-mode child # parent

```

```
RUSTFLAGS='-C force-frame-pointers=yes -Zinstrument-mcount -Cpasses=ee-instrument<post-inline>'
```

- If it appears to hang, it may be a deadlock (unlikely), or the error result of some coroutine is not logged.

- `key must be string`

I used NSRef for keys of a map. NSRef has non unit variants which most serde formats do not support.

## Networking

- An app connects to a host
    - DNS requests are handled by dnsproxy
    - IP packets are handled by Tun2socks, which directs traffic through a veth to an external socks5proxy
    - This provides compatibility but is not as efficient as the direct-socks5 way
    - Many apps either don't support socks5 proxy, or leak traffic/DNS.
- An app with sock5 proxy support
    - Two ways
        1. App connects to the socks proxy through a veth
        2. App connects to the IP endpoint in NS, and Netns-proxy forwards it to the provided socks proxy
- An app with HTTP proxy support
    - Works with I2P
        1. Veth
        2. Userspace proxy

- Ideal situation
    - The app connects to the socks5/http proxy endpoint in NS, and any leaked traffic is handled by tun2socks. Direct connection to socks proxy avoids the roundtrips of in-NS local DNS. The upstream socks5 proxy resolves hosts through proxy servers.


### DNS

By default, DNS requests (all traffic with port 53) are directed to the `dnsproxy` in NS. 

It may be problematic if an app uses its own DNS, as its traffic gets redirected elsewhere.

## Security

- How much security do I gain from this setup ?

I don't know how netfilter works, but netns seems relatively clear to me.
The tool puts applications into individual netns-es, connected with each other by veths.

Netns is foolproof. Netfilter can get messed up by other firewalls, mistakes. Interfaces go down and packets get sent through unexpected routes.

- proxychains uses LD_PRELOAD, which can fail for certain binaries.

## On decentralized protocols

They should stay away from conventional IP stack. They are out of scope for netns-proxy.

Yggdrasil should not expose an IP interface (TUN). It should just expose a unix socket.

## todo

- test ns setups
- test dns
- proxy chaining with go-gost
- explainer socks socks5h
- profile creation wizard
- live reload config
- check all sockets have root perms
    - root owned sockets can only be connected by root procs

instead of tun2socks+dnsproxy, I should use tun2proxy which resolves domains to fake IPs and they are handled by our TUN. alternatively use some LD_PRELOAD magic to hook functions.

## Conception

- `Settings` is the seed configuration, which contains all user input ever needed. 
    - It fully specifies the significant details of configuration of each subject.
- `Derivative` is produced from `Settings`. 
- Each `Subject` has a corresponding `SubjectNS`
    - It can be created from scratch by netnsp, like named ones.
    - It can refer to an existing NS that belongs to a process.

By running netns-proxy, a fresh run stores its process-current netns inode into the `Derivative` file, which acts as a state store.

Any newly added `subjects` are derived, each start or reload, and put into `Derivative`. If a derivative exists, the changes are ignored.

An example of `Derivative` is the IP addresses of a veth pair.

Applying a subject takes `SubjectInfo` which is its `Derivative` which also contains a snapshot of its `SubjectProfile`.

Applications of subjects are separate, not dependent on each other, and order-insensitive.

All netns-es exist before any application. 

which means, at the start of each run

- Non-existent NSes are removed 
- Named NSes are created
- NSes associated with processes exist, and nothing needs to be done

Applying a subject, accepts arbitrary dirty system state, and achieves the desired state for the said subject, and does not interfere with other subjects.

which implies, you can remove a subject from `Derivative` to re-derivate it from the `SubjectProfile`

Any applicatoin must happen after all derivations have happened. An application of `SubjectInfo` can only have `NSRef` to already derived subjects.

```
pub enum NSRef {
    Root,
    Pid(Pid),
    Named(ProfileName),
}
```

- All named NSes are created at the beginning of each run
- NSes about pids exist, apriori
- Root NS sure exists

When deriving, resolution happens recursively. It may draw any from the global state.

- Same derivation should produce same outcome
- Settings + Derivation should cover all details.
- Settings covers the significant details.

Profile + Runtime/Instance-specific-info = Derivation

### Recorded inode in state file

On start of each main_task, NSIDs should be checked that, their paths and inodes match. 

- If paths exist, and inodes mismatch, derivatives are rejected, GCed.
- If paths pointed files do not exist, they are created and derivatives are reused.

It's always safe to create new empty NSes and instrument them. And the program should error less.

---

```rust
impl<V: VSpecifics> SubjectInfo<V> {
    /// places the veth and adds addrs. generic over V
    pub async fn apply_veths(
```

Sometimes changes to netlink do not take effect immediate, resulting in problems.


---

The work will be similar to Sagernet/Singbox, but I will have an emphasis on security and anonymity

Any domain name -> Virtual IP -> Any byte stream transport

- Cross-NS fd passing. Proxied socket opening.
- Transports
    - Lokinet, Tor, I2P, Nym
- Transport interface
    - Socket FD
    - UDP/TCP socket
    - Socks5 (easily extensible, but more copying)

Or, no, just fork singbox


https://github.com/keith-packard/fdpassing

> The sender constructs a mystic-looking sendmsg(2) call, placing the file descriptor in the control field of that operation. The kernel pulls the file descriptor out of the control field, allocates a file descriptor in the target process which references the same file object and then sticks the file descriptor in a queue for the receiving process to fetch. The receiver then constructs a matching call to recvmsg that provides a place for the kernel to stick the new file descriptor.


### NSID

- User configures an NS to have some config, `NSIDFrom::Named(some_ns)`.
- Derived and inode stored.
- Changes happen
- Restart daemon, Inode mismatch

Security should be based on intention. 

- The user may intend to use the new named ns
    - usually happens afte a reboot
    - creating a new ns is always safe
- The user may intend to restore network connection as it was. 
    
If it exists and inode mismatch, it may be created by `ip netns`, or some other tool.

The NSIDFrom is always considered the intention, as it is the source. 