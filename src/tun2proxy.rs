use std::os::fd::{FromRawFd, RawFd};

use netlink_ops::netns::Fcntl;
use simple_stream::{
    frame::{FrameBuilder, SimpleFrame, SimpleFrameBuilder},
    Blocking, Plain,
};

use crate::util::*;
use crate::{
    tasks::{TUN2Proxy, TUN2DNS},
    util::ns::*,
};
use anyhow::Result;
use smoltcp::phy::TunTapInterface;
use tun2proxy::{tun_to_proxy, NetworkInterface, Options, Proxy};

pub fn tuntap(args: TUN2Proxy, dev: RawFd) -> Result<()> {
    let proxy = Proxy::from_url(&args.url)?;
    let mut opts = Options::new();
    match args.dns {
        TUN2DNS::Proxy => opts = opts.with_virtual_dns(),
        TUN2DNS::Upstream(a) => opts = opts.with_dns_over_tcp().with_dns_addr(Some(a)),
    }
    if args.ipv6 {
        opts = opts.with_ipv6_enabled()
    }

    opts = opts.with_mtu(args.mtu as usize);

    let mut ttp = tun_to_proxy(&NetworkInterface::Fd(dev), &proxy, opts)?;
    ttp.run()?; // starts the event loop

    Ok(())
}
