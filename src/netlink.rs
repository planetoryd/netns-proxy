use derivative::Derivative;
use ron::ser::PrettyConfig;

use crate::{
    data::*,
    nft::{redirect_dns, Mergeable, NftState},
    schedule::{
        DerivationEvent, FnPlan, NMap, NSIDs, NSMap, NSWaitfree, RsrcReqList, SATVar, SubjectT,
    },
    sub::{NsubState, Sub, ToSub},
    util::{flatpak_perms_checkup, perms::get_non_priv_user, TaskCtx, TaskOutput},
};

use futures::{future::Ready, Future, FutureExt, SinkExt, StreamExt, TryFutureExt};
use ipnetwork::IpNetwork;

use serde::{Deserialize, Serialize};

use tokio::{
    io::AsyncWriteExt,
    process::Command,
    sync::{oneshot, RwLock},
};

use crate::{
    data::Pid,
    sub::{self, SubHub},
    util::{self, convert_strings_to_strs},
};

use anyhow::{anyhow, bail, Ok, Result};

use nix::{fcntl::FdFlag, sched::CloneFlags};

use std::{
    any::{Any, TypeId},
    collections::{BTreeMap, BTreeSet, HashSet},
    default,
    fmt::Debug,
    hash::Hash,
    net::Ipv6Addr,
    ops::{Deref, Index},
    os::fd::FromRawFd,
    pin::Pin,
    process::Stdio,
    str::FromStr,
    sync::Arc,
};

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::{
    ffi::OsString,
    net::Ipv4Addr,
    os::fd::RawFd,
    path::{Path, PathBuf},
};
use tokio::{self, fs::File, io::AsyncReadExt};

use crate::util::ns::*;

use rtnetlink::{
    netlink_packet_route::{nlas::link::InfoKind, rtnl::link::nlas, IFF_LOWER_UP},
    netlink_proto::{new_connection_from_socket, NetlinkCodec},
    netlink_sys::{protocols::NETLINK_ROUTE, AsyncSocket, TokioSocket},
};

use crate::util::error::*;
use crate::util::*;

use crate::state::*;
use fixed_map::{Key, Map};

pub macro nl_ctx {
    ( $sub:ident, $conn:ident, $nl:expr ) => {
        let (mut $sub, mut $conn) = $nl.$sub();
    },
    ( $sub:ident, $conn:ident, $nl:expr, $body:tt ) => {{
        let (mut $sub, mut $conn) = $nl.$sub();
        $body
    }}
}

use futures::stream::TryStreamExt;
use rtnetlink::netlink_packet_route::{rtnl::link::LinkMessage, AddressMessage, IFF_UP};
use rtnetlink::{Handle, NetworkNamespace};

/// Stateless connection
pub struct NLHandle {
    /// this handle may be proxied
    pub handle: Handle,
}

use crate::nft;
use async_recursion::async_recursion;

#[derive(Debug)]
pub struct Netns {
    pub id: NSID,
    pub netlink: NLStateful, // veths: HashMap<String, VethPair>
}

pub mod flags {
    use bitflags::bitflags;

    bitflags! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct NSCreate: u8 {
            const Path = 1;
            const Named = 2;
        }
    }
}
pub use flags::*;

impl NSIDFrom {
    /// Ensures that the result is validated
    #[async_recursion]
    pub async fn to_id(self, create: NSCreate) -> Result<NSID> {
        let path = self.path();
        let p2 = path.clone();
        if !path.exists() {
            if (create.intersects(NSCreate::Named) && matches!(self, NSIDFrom::Named(_)))
                || (create.intersects(NSCreate::Path) && matches!(self, NSIDFrom::Path(_)))
            {
                tokio::task::spawn_blocking(move || NetworkNamespace::add_w_path(&path)).await??;
            } else {
                bail!("Ns does not exist, creation disabled");
            }
        }
        Ok(NSID {
            inode: Self::ino(&p2).await?,
            from: self,
            validated: true,
            path: p2.into(),
        })
    }
    pub async fn ino(path: &Path) -> Result<u64> {
        let file = tokio::fs::File::open(path).await?;
        let stat = nix::sys::stat::fstat(file.as_raw_fd())?;
        Ok(stat.st_ino)
    }
    pub fn ino_sync(path: &Path) -> Result<u64> {
        let file = std::fs::File::open(path)?;
        let stat = nix::sys::stat::fstat(file.as_raw_fd())?;
        Ok(stat.st_ino)
    }
    /// Ensures that the result is validated
    pub fn to_id_sync(self, create: NSCreate) -> Result<NSID> {
        let path = self.path();
        if !path.exists() {
            if (create.intersects(NSCreate::Named) && matches!(self, NSIDFrom::Named(_)))
                || (create.intersects(NSCreate::Path) && matches!(self, NSIDFrom::Path(_)))
            {
                NetworkNamespace::add_w_path(&path)?;
            } else {
                bail!("Ns does not exist, creation disabled");
            }
        }
        Ok(NSID {
            inode: Self::ino_sync(&path)?,
            from: self,
            validated: true,
            path: path.to_owned().into(),
        })
    }
    pub fn path(&self) -> PathBuf {
        match &self {
            NSIDFrom::Named(p) => p.clone().ns_path(),
            NSIDFrom::Pid(p) => PathBuf::from(format!("/proc/{}/ns/net", p.0)),
            NSIDFrom::Path(path) => path.to_owned(),
            NSIDFrom::Root => {
                // currently, perceivable, most "root" ns I can get
                NSIDFrom::Pid(Pid(1)).path()
            }
            NSIDFrom::Thread => PathBuf::from("/proc/self/ns/net"),
        }
    }
    pub fn open_sync(&self) -> Result<NsFile<std::fs::File>> {
        let p = self.path();
        let f = std::fs::File::open(p)?;
        Ok(NsFile::<std::fs::File>(f))
    }
    pub fn del(&self) -> Result<()> {
        let p = self.path();
        NetworkNamespace::del_path(&p)?;
        Ok(())
    }
    pub fn exist(&self) -> Result<bool> {
        let p = self.path();
        Ok(p.exists())
    }
}

impl NSID {
    /// Ensure the NS is validated, create if allowed
    pub async fn ensure(&mut self) -> Result<()> {
        let redo = self.from.clone().to_id(NSCreate::Named).await?;
        if redo.inode != self.inode {
            match &self.from {
                NSIDFrom::Named(_) => (),
                _ => bail!("NS inode continuum breakage"),
            }
        }
        *self = redo;
        Ok(())
    }
    pub fn ensure_sync(&mut self) -> Result<()> {
        let redo = self.from.clone().to_id_sync(NSCreate::Named)?;
        if redo.inode != self.inode {
            match &self.from {
                // Creating new named ns from source is allowed
                NSIDFrom::Named(_) => (),
                // Generic over all NSID values, as continuum is usually preferable
                _ => bail!("NS inode continuum breakage"),
            }
        }
        *self = redo;
        Ok(())
    }
    /// Remove if its our duty
    pub fn remove_if_duty(&self) -> Result<()> {
        match self.from {
            NSIDFrom::Named(_) => {
                self.from.del()?;
            }
            _ => (),
        }
        Ok(())
    }
    pub fn open_sync(&self) -> Result<NsFile<std::fs::File>> {
        if self.validated && let Some(path) = &self.path {
            // validated implies path Some
            let f = std::fs::File::open(path)?;
            Ok(NsFile::<_>(f))
        } else {
            bail!("NSID hasn't been validated. Programming error")
        }
    }
    pub async fn open(&self) -> Result<NsFile<tokio::fs::File>> {
        if self.validated && let Some(path) = &self.path {
            // validated implies path Some
            let f = tokio::fs::File::open(path).await?;
            Ok(NsFile::<_>(f))
        } else {
            bail!("NSID hasn't been validated. Programming error")
        }
    }
}

pub struct NsFile<F: AsRawFd>(pub F);

impl<F: AsRawFd> NsFile<F> {
    pub fn enter(&self) -> Result<()> {
        nix::sched::setns(self.0.as_raw_fd(), CloneFlags::CLONE_NEWNET)?;
        Ok(())
    }
    pub fn set_cloexec(&self) -> Result<i32> {
        self.0.set_cloexec()
    }
    pub fn unset_cloexec(&self) -> Result<i32> {
        self.0.unset_cloexec()
    }
}

pub trait Fcntl: AsRawFd {
    /// This flag specifies that the file descriptor should be closed when an exec function is invoked
    fn set_cloexec(&self) -> Result<i32> {
        nix::fcntl::fcntl(
            self.as_raw_fd(),
            nix::fcntl::FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC),
        )
        .map_err(anyhow::Error::from)
    }
    fn unset_cloexec(&self) -> Result<i32> {
        nix::fcntl::fcntl(
            self.as_raw_fd(),
            nix::fcntl::FcntlArg::F_SETFD(FdFlag::empty()),
        )
        .map_err(anyhow::Error::from)
    }
}

impl<F: AsRawFd> Fcntl for F {}

#[derive(Derivative)]
#[derivative(PartialEq, Eq, Debug)]
/// Netlink manipulator with locally duplicated state
pub struct NLStateful {
    /// private
    #[derivative(PartialEq = "ignore")]
    #[derivative(Debug = "ignore")]
    conn: NLTracked,
    pub veths: BTreeMap<VPairKey, VethPair>,
    /// msg.header.index
    pub links_index: BTreeMap<u32, LinkKey>,
    /// Do not use this directly.
    links: BTreeMap<LinkKey, Existence<LinkAttrs>>,
    link_kind: HashMap<u32, nlas::InfoKind>,
    routes: HashMap<RouteFor, Existence<()>>,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub enum RouteFor {
    TUNIpv4,
    TUNIpv6,
}

#[derive(Clone)]
pub struct NLTracked {
    handle: Arc<NLHandle>,
}

impl NLTracked {
    #[inline]
    pub fn h(&self) -> &NLHandle {
        &self.handle
    }
    pub async fn to_netns(self, id: NSID) -> Result<Netns> {
        let mut nl: NLStateful = NLStateful::new(self).await?;
        nl.fill().await?;
        let ns = Netns::new(id, nl);
        Ok(ns)
    }
    pub async fn set_up(&self, link: &mut LinkAttrs) -> Result<()> {
        if link.up.get() == Some(&true) {
            Ok(())
        } else {
            self.handle.set_link_up(link.index).await?;
            link.up.trans_to(Exp::Expect(true))?;
            Ok(())
        }
    }
    pub async fn add_addr(&mut self, link: &mut LinkAttrs, ip: IpNetwork) -> Result<()> {
        if let Result::Ok(k) = link.addrs.filled()?.not_absent(&ip)
            && (matches!(k, Existence::Exist(_)) || matches!(k, Existence::ShouldExist)) {
            // we don't error here.
        } else {
            link.addrs.filled()?.trans_to(&ip, LExistence::ShouldExist).await?;
            self.handle.add_addr_dev(ip, link.index).await?;
        }
        Ok(())
    }
    pub async fn remove_addr(&mut self, link: &mut LinkAttrs, addr: IpNetwork) -> Result<()> {
        let msg = link.addrs.filled()?.not_absent(&addr)?;
        let swap = msg.trans_to(LExistence::ExpectAbsent).await?;

        self.handle
            .handle
            .address()
            .del(swap.exist()?)
            .execute()
            .await?;
        Ok(())
    }
    pub async fn remove_addrs(
        &mut self,
        link: &mut LinkAttrs,
        addrs: Vec<IpNetwork>,
    ) -> Result<()> {
        for addr in addrs {
            self.remove_addr(link, addr).await?;
        }
        Ok(())
    }

    pub async fn ensure_addrs_46(
        &mut self,
        link: &mut LinkAttrs,
        v4: IpNetwork,
        v6: IpNetwork,
    ) -> Result<()> {
        self.add_addr(link, v4).await?;
        self.add_addr(link, v6).await?;
        let mut pending: Vec<IpNetwork> = Default::default();
        for (k, msg) in link.addrs.filled()? {
            if *k != v4 && *k != v6 && matches!(msg, Existence::Exist(_)) {
                pending.push(k.clone());
            }
        }
        self.remove_addrs(link, pending).await?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Hash, PartialEq, Eq, Clone, Debug, PartialOrd, Ord)]
pub struct LinkKey(String);

impl FromStr for LinkKey {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.len() > 15 {
            bail!("Link name too long");
        }
        Result::Ok(LinkKey(s.to_owned()))
    }
}

impl From<LinkKey> for String {
    fn from(value: LinkKey) -> Self {
        value.0
    }
}

#[derive(Serialize, Deserialize, Hash, PartialEq, Eq, Clone, Debug, PartialOrd, Ord)]
pub struct VPairKey(String);

impl FromStr for VPairKey {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.len() > 11 {
            bail!("Veth base name too long");
        }
        Result::Ok(VPairKey(s.to_owned()))
    }
}

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Key, Copy)]
pub enum LinkAB {
    /// Subject
    A,
    /// Target
    B,
}

impl VPairKey {
    pub fn link(&self, ab: LinkAB) -> LinkKey {
        // Invariant, self.name is valid
        let basename = &self.0;

        LinkKey(match ab {
            LinkAB::A => format!("{basename}_a"),
            LinkAB::B => format!("{basename}_b"),
        })
    }
    pub fn parse(k: &LinkKey) -> Option<(VPairKey, LinkAB)> {
        let name = &k.0;
        let tr = name.split_at(name.len() - 2).0.to_owned();
        if name.ends_with("_a") {
            Some((VPairKey(tr), LinkAB::A))
        } else if name.ends_with("_b") {
            Some((VPairKey(tr), LinkAB::B))
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub enum VPairP {
    A,
    B,
    Both,
}

impl Trans for LinkKey {
    fn trans(&self, to: &Self) -> bool {
        self == to
    }
}

fn new_link_ctx<'m>(
    links: &'m mut BTreeMap<LinkKey, Existence<LinkAttrs>>,
    link_kind: &'m HashMap<u32, InfoKind>,
    veths: &'m mut BTreeMap<VPairKey, VethPair>,
) -> NLCtx<
    'm,
    LinkKey,
    BTreeMap<LinkKey, Existence<LinkAttrs>>,
    impl FnMut(&LinkKey, Option<&mut Existence<LinkAttrs>>) + 'm,
> {
    NLCtx {
        map: links,
        set: |k, v| {
            if let Some((vp, ab)) = VPairKey::parse(k) {
                if let Some(v) = v {
                    match v {
                        Existence::Exist(att) => {
                            let pass = if let Some(k) = link_kind.get(&att.index) {
                                matches!(k, InfoKind::Veth)
                            } else {
                                true
                            };
                            if pass {
                                att.pair = Some(vp.clone());
                            }
                        }
                        _ => (),
                    }
                    veths.set_dep(&vp, &ab, v.to(k.to_owned()));
                } else {
                    veths.set_absent_dep(&vp, &ab);
                }
            }
        },
        _k: Default::default(),
    }
}

impl NLStateful {
    /// Get a context to manipulate link objects
    /// Loans many references out.
    pub fn link<'m>(
        &'m mut self,
    ) -> (
        NLCtx<
            'm,
            LinkKey,
            BTreeMap<LinkKey, Existence<LinkAttrs>>,
            impl FnMut(&LinkKey, Option<&mut Existence<LinkAttrs>>) + 'm,
        >,
        &mut NLTracked,
    ) {
        (
            new_link_ctx(&mut self.links, &self.link_kind, &mut self.veths),
            &mut self.conn,
        )
    }
}

impl NLStateful {
    /// retrieves the list of links and info for ns
    pub async fn new(netlink: NLTracked) -> Result<NLStateful> {
        let nsnl = NLStateful {
            links: BTreeMap::new(),
            veths: BTreeMap::new(),
            links_index: BTreeMap::new(),
            conn: netlink,
            link_kind: HashMap::new(),
            routes: Default::default(),
        };

        Ok(nsnl)
    }
    pub async fn fill(&mut self) -> Result<()> {
        let netlink = self.conn.h();
        let mut links = netlink.handle.link().get().execute();
        while let Some(link) = links.try_next().await? {
            use rtnetlink::netlink_packet_route::rtnl::link::nlas::Nla;

            let mut name = None;
            let up = link.header.flags & IFF_UP != 0;
            let index = link.header.index;

            for n in link.nlas {
                match n {
                    Nla::IfName(n) => name = Some(n),
                    Nla::OperState(s) => match s {
                        _ => (),
                    },
                    Nla::Info(k) => {
                        for i in k {
                            match i {
                                nlas::Info::Kind(x) => {
                                    self.link_kind.insert(index, x);
                                }
                                _ => (),
                            }
                        }
                    }
                    _ => (),
                }
            }
            let name = name.ok_or(DevianceError)?;
            let mut li = LinkAttrs {
                up: Exp::Confirmed(up),
                index,
                addrs: Default::default(),
                pair: None,
            };
            li.addrs.to_filled()?;
            let Self {
                links,
                link_kind,
                veths,
                ..
            } = self;
            let mut link = new_link_ctx(links, link_kind, veths);
            let lk: LinkKey = name.parse()?;
            link.fill(&lk, Existence::Exist(li))?;
            let k = self.links_index.insert(index, lk);
            assert!(k.is_none());
        }
        // the filter is not done by kernel. hence just do it here.
        let addrs = netlink.handle.address().get().execute();
        let addrs: Vec<AddressMessage> = addrs.try_collect().await?;
        for addr in addrs.into_iter() {
            let index_of_the_link_too = addr.header.index.clone(); // as observed.
            let mut ipnet: Option<IpNetwork> = None;
            for msg in addr.nlas.iter() {
                match msg {
                    rtnetlink::netlink_packet_route::address::Nla::Address(a) => {
                        // one addr msg for one addr I guess ?
                        if ipnet.is_some() {
                            log::warn!("More than one address in one AddressMessage, {:?}", addr);
                            break;
                        }
                        if a.len() == 4 {
                            let con: [u8; 4] = a.to_owned().try_into().unwrap();
                            let ip4: Ipv4Addr = con.into();
                            ipnet = Some(IpNetwork::new(ip4.into(), addr.header.prefix_len)?);
                        } else if a.len() == 16 {
                            let con: [u8; 16] = a.to_owned().try_into().unwrap();
                            let ip6: Ipv6Addr = con.into();
                            ipnet = Some(IpNetwork::new(ip6.into(), addr.header.prefix_len)?);
                        }
                    }
                    _ => (),
                }
            }
            let exp = util::btreemap_chain_mut(
                &mut self.links_index,
                &mut self.links,
                &index_of_the_link_too,
            )
            .unwrap()
            .exist_mut()?
            .addrs
            .to_filled()?;
            if let Some(ip) = ipnet {
                exp.fill(&ip, Existence::Exist(addr))?;
            }
        }
        Ok(())
    }

    // Some methods change state of self, which are therefore placed here
    pub async fn remove_link<'at>(&'at mut self, k: &'at LinkKey) -> Result<LinkAttrs> {
        // we want to reflect the state of links as that vector
        log::trace!("remove link {:?}", k);
        nl_ctx!(link, conn, self, {
            // It needs link.index
            let link_removed = link
                .not_absent_then_set(k, Existence::ExpectAbsent)?
                .exist()?;
            conn.h().rm_link(link_removed.index).await?;
            Ok(link_removed)
        })
    }
    /// move link from this ns to dst
    pub async fn move_link_to_ns(&mut self, k: &LinkKey, dst: &mut Netns, fd: RawFd) -> Result<()> {
        log::trace!("move link {:?} to {:?}", k, dst.id);
        self.get_link(k.to_owned()).await?;
        nl_ctx!(link, conn, self, {
            let v = link
                .not_absent_then_set(k, Existence::ExpectAbsent)?
                .exist()?;
            conn.h().ip_setns_by_fd(fd, v.index).await?;
        });

        nl_ctx!(link, _conn, dst.netlink, {
            link.trans_to(k, LExistence::ShouldExist).await?;
        });

        Ok(())
    }
    pub async fn get_link(&mut self, name: LinkKey) -> Result<()> {
        log::trace!("refresh {:?}", name);
        nl_ctx!(link, conn, self, {
            let n = link
                .trans_to(
                    &name,
                    LExistence::Exist(LazyVal::Todo(Box::pin(async {
                        let k = conn.h().get_link(name.clone()).await?;
                        let mut la: LinkAttrs = k.into();
                        let addrs = conn.h().get_link_addrs(la.index).await?;
                        la.fill_addrs(addrs)?;
                        Ok(la)
                    }))),
                )
                .await;
            match n {
                Err(e) => {
                    if let Some(_) = e.downcast_ref::<MissingError>() {
                        link.set_absent(&name);
                    } else {
                        return Err(e);
                    }
                }
                _ => (),
            }
        });

        Ok(())
    }
    pub async fn get_veth(&mut self, base: &VPairKey) -> Result<()> {
        let lka = base.link(LinkAB::A);
        let lkb = base.link(LinkAB::B);
        for link_name in [lka, lkb] {
            let result = self.get_link(link_name).await;
            if let Err(ref e) = result {
                if let Some(_e) = e.downcast_ref::<MissingError>() {
                    // ignore
                } else {
                    return result;
                }
            }
        }
        Ok(())
    }
    /// Errors if something already exists
    pub async fn new_veth_pair(&mut self, name: VPairKey) -> Result<()> {
        log::debug!("Create new veth pair, {:?}", name);
        if let Some(v) = self.veths.g(&name) {
            bail!("programming error: Veth already exists. {:?}", v);
        }

        nl_ctx!(link, conn, self, {
            conn.h().add_veth_pair(&name).await?;
            link.trans_to(&name.link(LinkAB::A), LExistence::ShouldExist)
                .await?;
            link.trans_to(&name.link(LinkAB::B), LExistence::ShouldExist)
                .await?;
        });

        Ok(())
    }
    pub async fn ip_add_route(
        &mut self,
        index: u32,
        dst: Option<IpNetwork>,
        v4: Option<bool>,
        purpose: RouteFor,
    ) -> Result<()> {
        self.routes
            .trans_to(&purpose, LExistence::ShouldExist)
            .await?;
        self.conn.h().ip_add_route(index, dst, v4).await
    }
}

// invariant: Netns struct exists ==> Netns exists in root ns
// so we can partially check the code before compiling
// we get an Netns obj to perform ops on it
// and we get a VethPair obj inside, and add addrs to it
impl Netns {
    /// enter a ns
    pub async fn enter(entry: NSID) -> Result<Netns> {
        let f = entry.open().await?;
        f.enter()?;
        let netlink = NLTracked::new(Arc::new(NLHandle::new_in_current_ns()));
        let netlink = NLStateful::new(netlink).await?;
        Ok(Netns { id: entry, netlink })
    }
    pub async fn thread() -> Result<Netns> {
        let id = NSIDFrom::Thread.to_id(NSCreate::empty()).await?;
        let mut netlink =
            NLStateful::new(NLTracked::new(Arc::new(NLHandle::new_in_current_ns()))).await?;
        netlink.fill().await?;
        Ok(Netns { id, netlink })
    }
    pub fn new(ns: NSID, netlink: NLStateful) -> Self {
        Self { id: ns, netlink }
    }
    // 'x is shorter than 'a
    pub async fn refresh<'x>(&'x mut self) -> Result<()> {
        // will just rebuild that struct based on the handle
        log::trace!("refresh local netlink expectation for {:?}", self.id);
        let c: NLTracked = self.netlink.conn.clone();
        let mut new_nl: NLStateful = NLStateful::new(c).await?;
        new_nl.fill().await?;
        self.netlink = new_nl;
        Ok(())
    }
}
#[derive(Derivative)]
#[derivative(Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct LinkAttrs {
    pub up: Exp<bool>,
    pub index: u32,
    #[derivative(Hash = "ignore")]
    #[derivative(PartialEq = "ignore")]
    #[derivative(PartialOrd = "ignore")]
    #[derivative(Ord = "ignore")]
    pub addrs: ExpCollection<HashMap<IpNetwork, Existence<AddressMessage>>>,
    /// associated veth pair if any
    pub pair: Option<VPairKey>,
}

impl LinkAttrs {
    pub fn fill_addrs(&mut self, msgs: Vec<AddressMessage>) -> Result<()> {
        let exp = self.addrs.to_filled()?;
        for addr in msgs.into_iter() {
            let mut ipnet: Option<IpNetwork> = None;
            for msg in addr.nlas.iter() {
                match msg {
                    rtnetlink::netlink_packet_route::address::Nla::Address(a) => {
                        // one addr msg for one addr I guess ?
                        if ipnet.is_some() {
                            log::warn!("More than one address in one AddressMessage, {:?}", addr);
                            break;
                        }
                        if a.len() == 4 {
                            let con: [u8; 4] = a.to_owned().try_into().unwrap();
                            let ip4: Ipv4Addr = con.into();
                            ipnet = Some(IpNetwork::new(ip4.into(), addr.header.prefix_len)?);
                        } else if a.len() == 16 {
                            let con: [u8; 16] = a.to_owned().try_into().unwrap();
                            let ip6: Ipv6Addr = con.into();
                            ipnet = Some(IpNetwork::new(ip6.into(), addr.header.prefix_len)?);
                        }
                    }
                    _ => (),
                }
            }
            if let Some(ip) = ipnet {
                exp.fill(&ip, Existence::Exist(addr))?;
            }
        }
        Ok(())
    }
}

impl Trans for AddressMessage {
    fn trans(&self, to: &Self) -> bool {
        self == to
    }
}

impl Trans for LinkAttrs {
    /// What is allowed to change when perceiving changes
    fn trans(&self, to: &Self) -> bool {
        self.up.trans(&to.up)
    }
}

impl DependentEMap<VPairKey, LinkAB, VethPair> for BTreeMap<VPairKey, VethPair> {}
impl DepedentEMapE<VPairKey, LinkAB, LinkKey, VethPair> for BTreeMap<VPairKey, VethPair> {}

type VethPair = Map<LinkAB, Existence<LinkKey>>;

impl NLTracked {
    #[inline]
    pub fn new(value: Arc<NLHandle>) -> Self {
        Self { handle: value }
    }
}

impl From<LinkMessage> for LinkAttrs {
    fn from(msg: LinkMessage) -> Self {
        let up = msg.header.flags & IFF_UP != 0;
        LinkAttrs {
            up: Exp::Confirmed(up),
            addrs: Default::default(),
            index: msg.header.index.into(),
            pair: None,
        }
    }
}

impl NLHandle {
    pub fn new_in_current_ns() -> Self {
        use rtnetlink::new_connection;
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);

        Self { handle }
    }
    pub async fn rm_link(&self, index: u32) -> Result<()> {
        self.handle
            .link()
            .del(index)
            .execute()
            .await
            .map_err(anyhow::Error::from)
    }
    pub async fn get_link(&self, name: LinkKey) -> Result<LinkMessage> {
        let mut links = self.handle.link().get().match_name(name.into()).execute();
        if let Some(link) = links.try_next().await? {
            Ok(link)
        } else {
            Err(MissingError.into())
        }
    }
    pub async fn get_link_addrs(&self, index: u32) -> Result<Vec<AddressMessage>> {
        let addrs = self
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();
        let addrs: Vec<AddressMessage> = addrs.try_collect().await?;
        Ok(addrs)
    }
    pub async fn set_link_up(&self, index: u32) -> Result<()> {
        self.handle
            .link()
            .set(index)
            .up()
            .execute()
            .await
            .map_err(anyhow::Error::from)
    }
    pub async fn add_veth_pair(&self, base_name: &VPairKey) -> Result<()> {
        self.handle
            .link()
            .add()
            .veth(
                base_name.link(LinkAB::A).into(),
                base_name.link(LinkAB::B).into(),
            )
            .execute()
            .await
            .map_err(|e| anyhow!("adding {base_name:?} veth pair fails. {e}"))
    }
    pub async fn add_addr_dev(&self, addr: IpNetwork, dev: u32) -> Result<()> {
        // assuming the desired IP has not been added
        self.handle
            .address()
            .add(dev, addr.ip(), addr.prefix())
            .execute()
            .await
            .map_err(anyhow::Error::from)
    }
    pub async fn del_addr(&self, addr: AddressMessage) -> Result<()> {
        self.handle
            .address()
            .del(addr)
            .execute()
            .await
            .map_err(anyhow::Error::from)
    }
    pub async fn ip_setns_by_fd(&self, fd: RawFd, dev: u32) -> Result<()> {
        self.handle
            .link()
            .set(dev)
            .setns_by_fd(fd)
            .execute()
            .await
            .map_err(anyhow::Error::from)
    }
    // one of dst and v4 must be Some
    // XXX must have run once in exec paths
    pub async fn ip_add_route(
        &self,
        index: u32,
        dst: Option<IpNetwork>,
        v4: Option<bool>,
    ) -> Result<()> {
        let req = self.handle.route().add().output_interface(index);
        match dst {
            Some(IpNetwork::V4(ip)) => req
                .v4()
                .destination_prefix(ip.ip(), ip.prefix())
                .execute()
                .await
                .map_err(anyhow::Error::from),
            Some(IpNetwork::V6(ip)) => req
                .v6()
                .destination_prefix(ip.ip(), ip.prefix())
                .execute()
                .await
                .map_err(anyhow::Error::from),
            _ => {
                if v4.is_some() {
                    if v4.unwrap() {
                        req.v4().execute().await.map_err(anyhow::Error::from)
                    } else {
                        req.v6().execute().await.map_err(anyhow::Error::from)
                    }
                } else {
                    unreachable!()
                }
            }
        }
    }
}

nix::ioctl_write_int!(tunsetowner, 'T', 204);
nix::ioctl_write_int!(tunsetpersist, 'T', 203);

// prepare a TUN for tun2socks, so it doesn't need root privs.
pub fn tun_ops(tun: tidy_tuntap::Tun) -> Result<()> {
    let fd = tun.as_raw_fd();

    // as tested, the line below is needless.
    // unsafe { tunsetowner(fd, 1000)? };
    unsafe { tunsetpersist(fd, 1)? }; // works if uncommented

    Ok(())
}
#[derive(Clone)]
/// About multiple ns-es
pub struct NetnsMap<N: NMap<V = Netns>> {
    /// Take mut reference when operating on an NS.
    map: Arc<N>,
    paths: Arc<ConfPaths>,
    pub ctx: TaskCtx,
    pub subs: SubHub<NSWaitfree<Sub, NSID>>,
}

impl ConfPaths {
    pub fn sock4netlink(&self) -> PathBuf {
        self.sock.join("netlink.sock")
    }
    pub fn sock4rpc(&self) -> PathBuf {
        self.sock.join("nsp_rpc.sock")
    }
    pub fn sock4ctrl(&self) -> PathBuf {
        self.sock.join("nsp.sock")
    }
}

impl<N: NMap<V = Netns, K = NSID> + Default> NSMap for NetnsMap<N> {
    type Inner = N;
    type V = Netns;
    async fn get<'r, Fut: Future<Output = Result<Self::V>>>(
        &'r self,
        k: &<Self::Inner as NMap>::K,
    ) -> Result<(
        <Self::Inner as NMap>::ReadGuard<'r>,
        fn(&'r <Self::Inner as NMap>::ReadGuard<'r>) -> &'r Self::V,
        bool,
    )> {
        self.map
            .get(k, async move |ns| self.init_ns(ns).await)
            .await
    }
    async fn get_mut<'w, Fut: Future<Output = Result<Self::V>>>(
        &'w self,
        k: &<Self::Inner as NMap>::K,
    ) -> Result<(
        <Self::Inner as NMap>::WriteGuard<'w>,
        fn(&'w mut <Self::Inner as NMap>::WriteGuard<'w>) -> &'w mut Self::V,
        bool,
    )>
    where
        Self::V: 'w,
    {
        self.map
            .get_mut(k, async move |ns| self.init_ns(ns).await)
            .await
    }
}

impl<N: NMap<V = Netns, K = NSID> + Default> NetnsMap<N> {
    pub fn new(
        paths: Arc<ConfPaths>,
        ctx: TaskCtx,
        subs: SubHub<NSWaitfree<Sub, NSID>>,
    ) -> Result<Self> {
        let mn = NetnsMap {
            map: Default::default(),
            paths,
            ctx,
            subs,
        };

        Ok(mn)
    }
    pub async fn init_ns(&self, id: &NSID) -> Result<Netns> {
        match id.from {
            // root is assumed to = thread
            NSIDFrom::Root | NSIDFrom::Thread => Netns::thread().await,
            // the rest needs separate processes
            _ => {
                let (g, sub, _): (_, _, _) = self.subs.get_mut(id).await?;
                let sub = sub(&mut g);
                let fd = sub.get_fd(sub::FDReq::Netlink(NETLINK_ROUTE)).await?;
                let ts = unsafe { TokioSocket::from_raw_fd(fd.fd) };
                let (conn, handle, _m) = new_connection_from_socket::<_, _, NetlinkCodec>(ts);

                let (t, _r) = TaskOutput::immediately(
                    async move {
                        conn.await;
                        Ok(())
                    },
                    "netlink-conn-".to_owned() + &id.inode.to_string(), // this waits on the conn. it ends when the conn ends
                );

                self.ctx
                    .pm
                    .send(PidOp::Add(
                        ProcessGroup::Subject(id.as_key()),
                        TaskKind::Task(t),
                    ))
                    .unwrap();
                let rth = Handle::new(handle);
                let nc = NLHandle { handle: rth };
                let nl = NLTracked::new(Arc::new(nc));
                let ns = nl.to_netns(self.clone()).await?;
                Ok(ns)
            }
        }
    }
}

pub trait Subject {
    async fn assure_in_ns(&self) -> Result<()>;
    async fn may_run_tun2socks(&self, state: &mut NsubState) -> Result<()>;
    async fn may_run_dnsproxy(&self, state: &mut NsubState) -> Result<()>;
}

impl<V: VSpecifics> Subject for SubjectInfo<V> {
    fn assure_in_ns(&self) -> Result<()> {
        let c = NSIDFrom::Thread.to_id_sync(NSCreate::empty())?;
        anyhow::ensure!(c == self.ns);
        Ok(())
    }
    /// These two methods return shortly. Tasks are passed to the awaiter
    /// Conforms to PidAwaiter
    async fn may_run_tun2socks(&self, st: &mut NsubState) -> Result<()> {
        use crate::netlink::*;
        use crate::util::watch_log;

        if let Some(addr) = self.tun2socks {
            log::info!("Run tun2socks for {}", self.ns);
            let mut tun2 = std::process::Command::new("tun2socks");
            tun2.uid(st.non_priv_uid.into())
                .gid(st.non_priv_gid.into())
                .groups(&[st.non_priv_gid.into()]);
            let prxy = format!("socks5://{}", addr.to_string());
            tun2.args(&["-device", TUN_NAME, "-proxy", &prxy]);
            let mut tun2_async: Command = tun2.into();
            tun2_async.stdout(Stdio::piped());
            let mut tun2h = tun2_async.spawn()?;
            let pid = Pid(tun2h.id().ok_or(anyhow!("Tun2socks stopped"))?);
            st.ctx.reg(ProcessGroup::Subject(self.ns.clone()), TaskKind::Process(pid));
            use tokio_stream::wrappers::LinesStream;
            let stdout = tun2h.stdout.take().unwrap();
            let reader = LinesStream::new(tokio::io::BufReader::new(stdout).lines());
            let (tx, rx) = tokio::sync::oneshot::channel();
            let pre = format!("{}/tun2socks", self.id);
            tokio::spawn(watch_log(Box::pin(reader), Some(tx), pre.clone()));
            rx.await?; // wait for first line to appear
            let tunk: LinkKey = TUN_NAME.parse()?;
            let tun = {
                nl_ctx!(link, conn, st.ns.netlink, {
                    let tun = link.not_absent(&tunk)?.exist_mut()?;
                    conn.set_up(tun).await?;
                    tun.index
                })
            };
            _ = st
                .ns
                .netlink
                .ip_add_route(tun, None, Some(true), RouteFor::TUNIpv4)
                .await;
            _ = st
                .ns
                .netlink
                .ip_add_route(tun, None, Some(false), RouteFor::TUNIpv6)
                .await;
        }

        Ok(())
    }
    async fn may_run_dnsproxy(&self, state: &mut NsubState) -> Result<()> {
        use crate::netlink::*;

        match self.dnsproxy {
            DNSProxyR::Disabled => (),
            DNSProxyR::Enabled(ref conf) => {
                log::info!("Run dnsproxy for {}", self.ns);
                let mut dns1 = std::process::Command::new("dnsproxy");
                dns1.uid(state.non_priv_uid.into())
                    .gid(state.non_priv_gid.into())
                    .groups(&[state.non_priv_gid.into()]);
                if let Some(ref k) = conf.args {
                    dns1.args(k);
                }
                let mut dns2: Command = dns1.into();
                dns2.stdout(Stdio::piped());
                dns2.stderr(Stdio::piped());
                let mut dns3 = dns2.spawn()?;
                let pid = Pid(dns3.id().ok_or(anyhow!("Dnsproxy stopped"))?);
                state.ctx
                    .pm
                    .send(PidOp::Add(
                        ProcessGroup::Subject(self.ns.clone()),
                        TaskKind::Process(pid),
                    ))
                    .unwrap();
                let (tx, rx) = tokio::sync::oneshot::channel();
                let pre = format!("{}/dnsproxy", self.id);
                watch_both(&mut dns3, pre.clone(), Some(tx))?;
                rx.await?; // wait for first line to appear
            }
        }

        Ok(())
    }
}

impl VethConn {
    /// Adaptive application of Veth connection, accepting dirty state
    pub async fn apply<'n>(&self, subject_ns: &'n mut Netns, t_ns: &'n mut Netns) -> Result<()> {
        let t_fd = t_ns.id.open_sync()?;
        log::info!(
            "Apply VethConn S{} -> T{}. {:?}",
            subject_ns.id,
            t_ns.id,
            self.key
        );
        if subject_ns.id == t_ns.id {
            bail!("Invalid VethConn, subject and target NS can not be the same");
        }
        let mut redo = false;
        let (mut a, mut b) = (false, false);
        let mut a_in_t = false;
        if let Some(v) = subject_ns.netlink.veths.g(&self.key) {
            if v.lenient(&LinkAB::A) {
                a = true;
                if v.lenient(&LinkAB::B) {
                    subject_ns
                        .netlink
                        .move_link_to_ns(&self.key.link(LinkAB::B), t_ns, t_fd.0.as_raw_fd())
                        .await?;
                    t_ns.netlink.get_link(self.key.link(LinkAB::B)).await?;
                }
            } else {
                redo = true;
            }
        } else {
            redo = true;
        }
        if let Some(v) = t_ns.netlink.veths.g(&self.key) {
            if v.lenient(&LinkAB::B) {
                b = true;
                if v.lenient(&LinkAB::A) {
                    // Weird situation. Just redo
                    redo = true;
                    a_in_t = true;
                }
            }
        }
        if !(a && b) {
            redo = true;
        }
        if redo {
            if a {
                subject_ns
                    .netlink
                    .remove_link(&self.key.link(LinkAB::A))
                    .await?;
            }
            if a_in_t {
                t_ns.netlink.remove_link(&self.key.link(LinkAB::A)).await?;
            }
            if b {
                t_ns.netlink.remove_link(&self.key.link(LinkAB::B)).await?;
            }
            subject_ns.netlink.new_veth_pair(self.key.clone()).await?;
            subject_ns
                .netlink
                .move_link_to_ns(&self.key.link(LinkAB::B), t_ns, t_fd.0.as_raw_fd())
                .await?;
        }
        Ok(())
    }
    pub async fn apply_addr_up<'n>(
        &self,
        subject_ns: &'n mut Netns,
        t_ns: &'n mut Netns,
    ) -> Result<()> {
        subject_ns
            .netlink
            .get_link(self.key.link(LinkAB::A))
            .await?;
        nl_ctx!(link, conn, subject_ns.netlink, {
            let la = link.not_absent(&self.key.link(LinkAB::A))?.exist_mut()?;
            conn.set_up(la).await?;
            conn.ensure_addrs_46(la, self.ip_va, self.ip6_va).await?;
        });
        nl_ctx!(link, conn, t_ns.netlink, {
            let lk = self.key.link(LinkAB::B);
            let la = link.not_absent(&lk)?.exist_mut()?;
            conn.set_up(la).await?;
            conn.ensure_addrs_46(la, self.ip_vb, self.ip6_vb).await?;
        });
        Ok(())
    }
}
