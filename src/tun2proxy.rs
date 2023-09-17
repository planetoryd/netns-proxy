use std::os::fd::{FromRawFd, RawFd};

use simple_stream::{
    frame::{FrameBuilder, SimpleFrame, SimpleFrameBuilder},
    Blocking, Plain,
};

use crate::data::TUN2DNS;
use crate::{
    data::TUN2ProxyE,
    netlink::Fcntl,
    sub::{FDRes, FdPre},
    util::from_vec_internal,
};
use anyhow::Result;
use smoltcp::phy::TunTapInterface;
use tun2proxy::{tun_to_proxy, NetworkInterface, Options, Proxy};

pub fn tuntap(fd: RawFd) -> Result<()> {
    use std::os::unix::net::UnixStream;
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    fd.set_cloexec()?;
    let mut f: Plain<UnixStream, SimpleFrameBuilder> = Plain::new(stream);
    let k = f.b_recv()?;
    let args: TUN2ProxyE = from_vec_internal(&k.payload())?;
    let k = f.b_recv()?;
    let dev: FdPre = from_vec_internal(&k.payload())?;

    let proxy = Proxy::from_url(&args.source.url)?;
    let mut opts = Options::new();
    match args.source.dns {
        TUN2DNS::Proxy => opts = opts.with_virtual_dns(),
        TUN2DNS::Upstream(a) => opts = opts.with_dns_over_tcp().with_dns_addr(Some(a)),
    }
    if args.source.ipv6 {
        opts = opts.with_ipv6_enabled()
    }

    let mtu = match dev.kind {
        FDRes::TUN(mtu) => mtu,
        FDRes::TAP(mtu) => mtu,
        _ => unreachable!(),
    };
    opts = opts.with_mtu(mtu as usize);

    let mut ttp = tun_to_proxy(&NetworkInterface::Fd(dev.fd), &proxy, opts)?;
    ttp.run()?; // starts the event loop

    Ok(())
}
