use anyhow::Result;

use anyhow::Ok;
use futures::SinkExt;
use netns_proxy::data::*;
use netns_proxy::sub::handle;
use netns_proxy::sub::ToSub;
use netns_proxy::util::PidAwaiter;
use netns_proxy::util::TaskCtx;
use rtnetlink::NetworkNamespace;
use tokio::net::UnixStream;
use tokio_util::codec::Framed;
use tokio_util::codec::LengthDelimitedCodec;

use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::{self};

use netns_proxy::netlink::*;
use netns_proxy::util::Awaitor;

// binary for testing configuration within a single NS

fn main() -> Result<()> {
    let e = env_logger::Env::new().default_filter_or("error,netns_proxy=debug");
    env_logger::init_from_env(e);

    netns_proxy::util::branch_out()?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut ro: PathBuf = env!("CARGO_MANIFEST_DIR").parse()?;
            ro.push("testing");
            let mut derivative: PathBuf = ro.clone();
            let _ = std::fs::create_dir(&ro);
            derivative.push("sub_derivative.json");
            let mut settings: PathBuf = ro.clone();
            settings.push("geph1.json");
            let mut sock: PathBuf = ro.clone();
            sock.push("sock");
            let _ = std::fs::create_dir(&sock);

            let paths = Arc::new(ConfPaths {
                settings,
                derivative,
                sock,
            });
            let pn = ProfileName("geph1".to_owned());
            if NSID::exists(pn.clone())? {
                NSID::del(pn.clone()).await?;
            }
            let id = NSID::from_name(pn).await?;
            let _state: NetnspState = NetnspState::load(paths.clone()).await?;
            let mut dae = Awaitor::new();
            let pid_wait = PidAwaiter::new();
            let ctx = TaskCtx {
                dae: dae.sender.clone(),
                pid: pid_wait.sx,
            };
            let mn: MultiNS = MultiNS::new(paths.clone(), ctx).await?;
            let nl = mn.get_nl(id.clone()).await?;
            let mut ns = ConnRef::new(Arc::new(nl)).to_netns(id).await?;
            dbg!(&ns);

            tests(&mut ns).await?;

            dae.wait().await?;
            Ok(())
        })?;

    Ok(())
}

// setns seems to not affect existing threads / child threads ?
// ok this needs more empirical study and analysis.
// I should move the child process in as early as possible
// but new processes (as observed) inherit the setns ns.

async fn tests(ns: &mut Netns) -> Result<()> {
    assert!(ns.netlink.links.len() == 1);
    assert!(ns.netlink.links_index.len() == 1);

    // Check that the link with name "lo" exists
    assert!(ns.netlink.links.contains_key(&"lo".parse()?));

    // Retrieve the "lo" link and assert its properties
    let lo_link = ns.netlink.links.get(&"lo".parse()?).unwrap();
    assert!(!lo_link.up); // Link is not up
    assert_eq!(lo_link.name, "lo");
    assert!(lo_link.addrs.is_empty()); // No addresses associated with the link
    assert_eq!(lo_link.index, 1);
    assert!(lo_link.pair.is_none()); // Link does not have a pair

    let k = Link::get(&mut ns.netlink, "non_exis".parse()?).await;
    k.expect_err("link should not exist");

    let prev_len = ns.netlink.links.len();
    let vp: VPairKey = "test".parse()?;
    dbg!(&ns.netlink);
    VethPair::new(&mut ns.netlink, vp.clone()).await?;
    assert!(ns.netlink.links.len() - prev_len == 2);
    assert!(ns.netlink.links.contains_key(&vp.link(true)));
    assert!(ns.netlink.links.contains_key(&vp.link(false)));
    dbg!(&ns.netlink);

    let la = ns.netlink.links.get_mut(&vp.link(true)).unwrap();
    la.add_addr("1.1.1.1/15".parse()?).await?;
    let e = la.add_addr("::1/22".parse()?).await;
    assert!(e.is_err());
    la.add_addr("fefe::1/32".parse()?).await?;
    la.up(ns.netlink.conn.get()).await?;
    ns.refresh().await?;
    dbg!(&ns.netlink);

    let rm = vp.link(true);
    ns.netlink.remove_link(&rm).await?;
    assert!(!ns.netlink.links.contains_key(&rm));
    assert!(matches!(ns.netlink.veths.get(&vp).unwrap(), VethPair::None));
    ns.refresh().await?;

    dbg!(&ns.netlink);
    assert!(!ns.netlink.links.contains_key(&rm));
    assert!(ns.netlink.links.get(&rm).is_none());

    Ok(())
}
