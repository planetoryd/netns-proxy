use dashmap::{mapref::one::RefMut, try_result::TryResult, DashMap};
use log::debug;

use crate::{
    data::*,
    nft::redirect_dns,
    sub::ToSub,
    util::{open_wo_cloexec, perms::get_non_priv_user, DaemonSender, TaskOutput, TaskCtx},
};

use futures::{FutureExt, SinkExt, StreamExt, TryFutureExt};
use ipnetwork::IpNetwork;

use serde::{Deserialize, Serialize};

use tokio::{
    io::AsyncWriteExt,
    sync::{oneshot, RwLock},
};

use crate::{
    data::Pid,
    nft::IncrementalNft,
    sub::{self, SubHub},
    util::{self, convert_strings_to_strs},
};

use anyhow::{anyhow, bail, ensure, Context, Ok, Result};

use nix::sched::CloneFlags;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{format, Debug},
    net::Ipv6Addr,
    ops::Index,
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

use rtnetlink::netlink_packet_route::{nlas::link::InfoKind, rtnl::link::nlas, IFF_LOWER_UP};

use crate::util::error::*;

impl NetnspState {
    pub async fn clean_net(&self, netlink: &NetlinkConn) -> Result<()> {
        // remove veth in the root ns
        log::info!("Removing relevant link devices in root ns");
        let pnames = self.pers_links_in_root().await?;
        for pl in pnames {
            let mut links = netlink.handle.link().get().match_name(pl.0).execute();
            if let Result::Ok(Some(link)) = links.try_next().await {
                let i = link.header.index;
                netlink.handle.link().del(i).execute().await?;
            }
        }
        log::info!("Removing persisted network namespaces");
        // remove persistent NSes
        for ns in self.settings.profiles.keys() {
            let nso = netns_rs::NetNs::get(&ns.0);
            if nso.is_ok() {
                NetworkNamespace::del(ns.0.clone()).await?;
            }
        }
        Ok(())
    }
    // for nftables
    pub async fn pers_links_in_root(&self) -> Result<Vec<LinkKey>> {
        let base_names: Vec<&VPairKey> = self
            .derivative
            .named_ns
            .iter()
            .flat_map(|(_p, info)| {
                info.vaddrs.iter().filter_map(|(k, v)| {
                    if matches!(k, NSRef::Root) {
                        Some(&v.key)
                    } else {
                        None
                    }
                })
            })
            .collect();

        // a for subject, b for target=root
        // VConn always connects from subject ns to other ns. Subject ns can not be root ns. Therefore it's always `false`.
        let veth_host: Vec<LinkKey> = base_names.iter().map(|base| base.link(false)).collect();
        Ok(veth_host)
    }
    // do a full sync of firewall intention
    /// Caveat, do this before applying other nft
    pub async fn initial_nft(&mut self) -> Result<()> {
        let inames = self.pers_links_in_root().await?;
        let inames = inames.into_iter().map(|s| s.0).collect::<Vec<_>>();
        let x = convert_strings_to_strs(&inames);
        log::info!(
            "Apply nftables rules to block forwarding of {:?} in root_ns",
            &x
        );
        nft::apply_block_forwad(&x).await?;
        // added the tables and chains
        self.nft_refresh_once = true;
        // after that only individual rules need to be added for each flatpak
        Ok(())
    }
    /// places empty defaults if they dont exist
    pub async fn load(paths: Arc<ConfPaths>) -> Result<NetnspState> {
        log::info!("Loading state from {:?}", paths);
        let path = Path::new(&paths.settings);
        let sett: Settings;
        if path.exists() {
            let mut file = File::open(path).await?;
            let mut contents = String::new();
            file.read_to_string(&mut contents).await?;
            sett = serde_json::from_str(&contents)?;
        } else {
            sett = Default::default();
            log::info!("Generating default settings");
            let serialized = serde_json::to_string_pretty(&sett)?;
            let mut file = tokio::fs::File::create(path).await?;
            file.write_all(serialized.as_bytes()).await?;
            log::warn!("Blank settings written to {:?}", &path);
        }

        let path = Path::new(&paths.derivative);
        let deri: Derivative = if path.exists() {
            let mut file = File::open(path).await?;
            let mut contents = String::new();
            file.read_to_string(&mut contents).await?;
            let mut k: Derivative = serde_json::from_str(&contents)?;
            k.update_rootns()?;
            k
        } else {
            // allow it to not exist
            let mut n = Derivative::default();
            n.init().await?;
            n
        };

        let r = Self {
            derivative: deri,
            settings: sett,
            paths,
            nft_refresh_once: false,
            ids: Default::default(),
            incre_nft: Default::default(),
        };

        Ok(r)
    }

    pub fn load_sync(paths: Arc<ConfPaths>) -> Result<NetnspState> {
        use std::fs::{self, File};
        use std::io::{self, Read, Write};
        log::info!("Loading state from {:?}", paths);
        let path = Path::new(&paths.settings);

        let sett: Settings;

        if path.exists() {
            let mut file = File::open(path)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            sett = serde_json::from_str(&contents)?;
        } else {
            sett = Default::default();
            log::info!("Generating default settings");
            let serialized = serde_json::to_string_pretty(&sett)?;
            let mut file = std::fs::File::create(path)?;
            file.write_all(serialized.as_bytes())?;
            log::info!("Blank settings written to {:?}", &path);
        }

        let path = Path::new(&paths.derivative);
        let deri: Derivative = if path.exists() {
            let mut file = File::open(path)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            let mut k: Derivative = serde_json::from_str(&contents)?;
            k.update_rootns()?;
            k
        } else {
            // allow it to not exist
            let mut n = Derivative::default();
            n.update_rootns()?;
            n
        };

        let r = Self {
            derivative: deri,
            settings: sett,
            paths,
            nft_refresh_once: false,
            ids: Default::default(),
            incre_nft: Default::default(),
        };

        Ok(r)
    }
    /// derive for named ns that are not not yet derived
    pub async fn derive_all_named(&mut self) -> Result<()> {
        for ns in self.settings.profiles.keys() {
            match self.derivative.named_ns.get(&ns) {
                None => {
                    self.ids.new_unique(ns.clone());
                    let p = self.settings.profiles.get(&ns).ok_or(DevianceError)?;
                    let res = p
                        .resolve_g(&self, self.ids.get_unique().unwrap(), &NamedV(ns.clone()))
                        .await?;
                    log::info!("Derive for {}", res.ns);
                    self.derivative.named_ns.insert(ns.to_owned(), res);
                }
                Some(n) => {
                    log::info!("Derivative for {} exists. Will not override", n.ns);
                    // Skip if there is a persisted version
                }
            }
        }
        Ok(())
    }
    /// derive or get existing flatpak derivation. returns whether Derivative is available
    pub async fn derive_flatpak(&mut self, fv: FlatpakV) -> Result<bool> {
        match self.derivative.flatpak.get(&fv.pid) {
            Some(n) => {
                log::info!("Derivative for {} exists. Will not override", n.ns);
                Ok(true)
            }
            None => {
                let n = FlatpakBaseName::new(&fv.id, fv.pid.clone());
                self.ids.new_unique(n);
                let r = self.settings.flatpak.get(&fv.id);
                if let Some(r) = r {
                    let p = self.settings.profiles.get(&r).ok_or(DevianceError)?;
                    let res = p
                        .resolve_g(&self, self.ids.get_unique().unwrap(), &fv)
                        .await?;
                    log::info!("Derive for {}", res.ns);
                    self.derivative.flatpak.insert(fv.pid, res);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }
    pub async fn dump(&self) -> Result<()> {
        let serialized = serde_json::to_string_pretty(&self.derivative)?;
        let mut file = tokio::fs::File::create(&self.paths.derivative).await?;
        log::info!("config result dumped in netnsp.json.");
        file.write_all(serialized.as_bytes()).await?;
        Ok(())
    }

    /// Also, resume from persisted state
    pub async fn resume(&mut self, mn: &mut MultiNS, ctx: TaskCtx) -> Result<()> {
        // Some derivative do not have associated profiles
        // This is invalid, because the information is incomplete for configuration.
        self.derivative.clean_named(&self.settings.profiles);
        self.derivative
            .clean_flatpak(&self.settings.flatpak)
            .await?;

        log::debug!("Resume from saved state");

        for (_, info) in &self.derivative.named_ns {
            info.connect(mn).await?;
            info.apply_veths(&mn, &self.derivative).await?;
        }
        self.initial_nft().await?;

        // started after nft applied
        for (_, info) in &self.derivative.named_ns {
            info.run(&mn.procs).await?;
        }

        // Resume flatpaks
        for (_n, info) in &self.derivative.flatpak {
            info.connect(mn).await?;
            info.apply_veths(&mn, &self.derivative).await?;
            info.apply_nft_veth(&mut self.incre_nft);
        }
        self.incre_nft.execute()?;
        for (_n, info) in &self.derivative.flatpak {
            info.run(&mn.procs).await?;
        }

        Ok(())
    }
}

use futures::stream::TryStreamExt;
use rtnetlink::netlink_packet_route::{
    nlas::link::State, rtnl::link::LinkMessage, AddressMessage, IFF_UP,
};
use rtnetlink::{Handle, NetworkNamespace};

/// a wrapper type.
pub struct NetlinkConn {
    /// this handle may be proxied
    pub handle: Handle,
}

use crate::nft;

#[derive(Debug)]
pub struct Netns {
    pub id: NSID,
    pub netlink: NSNetlink, // veths: HashMap<String, VethPair>
}

// TODO: Test that NSID has equality only determined by inode.

impl NSID {
    pub fn from_pid(p: Pid) -> Result<Self> {
        let process = procfs::process::Process::new(p.0.try_into()?)?;
        let o: OsString = OsString::from("net");
        let nss = process.namespaces()?;
        let proc_ns = nss
            .get(&o)
            .ok_or(anyhow!("ns/net not found for given pid"))?;
        let path = proc_ns.path.clone();

        Ok(Self {
            pid: Some(p),
            name: None,
            inode: proc_ns.identifier,
            path: Some(path)
        })
    }
    /// for netnsp the invariant (that a netns name is also a profile anem) holds.
    /// therefore we will make it one type
    /// adds ns if it doesnt exist
    pub async fn from_name(p: ProfileName) -> Result<Self> {
        if !util::ns::named_ns_exist(&p)? {
            util::ns::add_netns(&p).await?;
        }
        let mut path: PathBuf = PathBuf::from(NETNS_PATH);
        path.push(&p.0);
        // ?: this is quite conservative.
        // let file = open_wo_cloexec(path.as_path())?;
        let file = tokio::fs::File::open(path.clone()).await?;
        let stat = nix::sys::stat::fstat(file.as_raw_fd())?;
        Ok(Self {
            path: Some(path),
            pid: None,
            name: Some(p),
            inode: stat.st_ino
        })
    }
    pub fn from_name_sync(p: ProfileName) -> Result<Self> {
        use std::fs::{self, File};
        if !util::ns::named_ns_exist(&p)? {
            bail!("ns doesn't exist");
        }
        let mut path: PathBuf = PathBuf::from(NETNS_PATH);
        path.push(&p.0);
        let file = File::open(path.clone())?;
        let stat = nix::sys::stat::fstat(file.as_raw_fd())?;
        Ok(Self {
            path: Some(path),
            pid: None,
            name: Some(p),
            inode: stat.st_ino
        })
    }
    pub fn proc() -> Result<Self> {
        Self::from_pid(Pid(std::process::id()))
    }
    pub async fn open(&self) -> Result<NsFile<File>> {
        match self.path {
            None => {
                unreachable!()
            }
            Some(ref p) => {
                // let f = open_wo_cloexec(&p)?;
                let f = tokio::fs::File::open(&p).await?;
                Ok(NsFile::<File>(f))
            }
        }
    }
    pub fn open_sync(&self) -> Result<NsFile<std::fs::File>> {
        match self.path {
            None => {
                unreachable!()
            }
            Some(ref p) => {
                let f = std::fs::File::open(&p)?;
                Ok(NsFile::<std::fs::File>(f))
            }
        }
    }
    pub fn open_wo_close(&self) -> Result<NsFile<std::fs::File>> {
        match self.path {
            None => {
                unreachable!()
            }
            Some(ref p) => {
                let f = open_wo_cloexec(&p)?;
                Ok(NsFile::<std::fs::File>(f))
            }
        }
    }
    pub fn exists(p: ProfileName) -> Result<bool> {
        util::ns::named_ns_exist(&p)
    }
    pub async fn del(p: ProfileName) -> Result<()> {
        NetworkNamespace::del(p.0).await?;
        Ok(())
    }
}

pub struct NsFile<F: AsRawFd>(pub F);

impl<F: AsRawFd> NsFile<F> {
    pub fn enter(&self) -> Result<()> {
        nix::sched::setns(self.0.as_raw_fd(), CloneFlags::CLONE_NEWNET)?;
        Ok(())
    }
}

// deleting a netns consumes it
impl !Clone for Netns {}
impl !Copy for Netns {}

#[derive(Derivative)]
#[derivative(Hash, PartialEq, Eq, Debug)]
/// Netlink manipulator with locally duplicated state
pub struct NSNetlink {
    pub links: BTreeMap<LinkKey, Link>,
    pub veths: BTreeMap<VPairKey, VethPair>,
    /// msg.header.index
    pub links_index: BTreeMap<u32, LinkKey>,
    /// None if in SIM
    #[derivative(Hash = "ignore")]
    #[derivative(PartialEq = "ignore")]
    #[derivative(Debug = "ignore")]
    pub conn: ConnRef,
    /// key: link index
    #[derivative(Hash = "ignore")]
    #[derivative(PartialEq = "ignore")]
    link_kind: HashMap<u32, nlas::InfoKind>,
}

#[derive(Clone)]
pub struct ConnRef {
    r: Arc<NetlinkConn>,
}

impl ConnRef {
    #[inline]
    pub fn get(&self) -> &NetlinkConn {
        &self.r
    }
    pub async fn to_netns(self, id: NSID) -> Result<Netns> {
        let mut nl: NSNetlink = NSNetlink::new(self).await?;
        nl.fill().await?;
        let ns = Netns::new(id, nl);
        Ok(ns)
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

impl VPairKey {
    pub fn link(&self, ab: bool) -> LinkKey {
        // Invariant, self.name is valid
        let basename = &self.0;
        LinkKey(if ab {
            format!("{basename}_a")
        } else {
            format!("{basename}_b")
        })
    }
}

#[derive(Debug)]
pub enum VPairP {
    A,
    B,
    Both,
}

impl NSNetlink {
    /// retrieves the list of links and info for ns
    pub async fn new(netlink: ConnRef) -> Result<NSNetlink> {
        let nsnl = NSNetlink {
            links: BTreeMap::new(),
            veths: BTreeMap::new(),
            links_index: BTreeMap::new(),
            conn: netlink,
            link_kind: HashMap::new(),
        };

        Ok(nsnl)
    }
    pub async fn fill(&mut self) -> Result<()> {
        let netlink = self.conn.get();
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
            let mut li = Link {
                name: name.clone(),
                up,
                index,
                addrs: BTreeSet::new(),
                pair: None,
                conn: self.conn.clone(),
            };
            let lk: LinkKey = name.parse()?;
            let ve = VethPair::from_link(lk.clone());
            if let Some((vk, vp)) = ve {
                let pass = if let Some(k) = self.link_kind.get(&index) {
                    matches!(k, InfoKind::Veth)
                } else {
                    true
                }; // meaning, does it count
                if pass {
                    li.pair = Some(vk.clone());
                    self.veths.merge_in_veth(vk, vp)?;
                }
            }
            let k = self.links.insert(lk.clone(), li);
            assert!(k.is_none());
            let k = self.links_index.insert(index, lk);
            assert!(k.is_none());
        }
        // the filter is not done by kernel. hence just do it here.
        let addrs = netlink.handle.address().get().execute();
        let addrs: Vec<AddressMessage> = addrs.try_collect().await?;
        for addr in addrs {
            let index_of_the_link_too = addr.header.index; // as observed.
            for msg in addr.nlas {
                let mut ipnet: Option<IpNetwork> = None;
                match msg {
                    rtnetlink::netlink_packet_route::address::Nla::Address(a) => {
                        if a.len() == 4 {
                            let con: [u8; 4] = a.try_into().unwrap();
                            let ip4: Ipv4Addr = con.into();
                            ipnet = Some(IpNetwork::new(ip4.into(), addr.header.prefix_len)?);
                        } else if a.len() == 16 {
                            let con: [u8; 16] = a.try_into().unwrap();
                            let ip6: Ipv6Addr = con.into();
                            ipnet = Some(IpNetwork::new(ip6.into(), addr.header.prefix_len)?);
                        }
                    }
                    _ => (),
                }
                if let Some(ipnet) = ipnet {
                    util::btreemap_chain_mut(
                        &mut self.links_index,
                        &mut self.links,
                        &index_of_the_link_too,
                    )
                    .unwrap()
                    .addrs
                    .insert(ipnet);
                }
            }
        }
        Ok(())
    }
}

trait VethMap {
    fn merge_in_veth(&mut self, k: VPairKey, v: VethPair) -> Result<()>;
}

impl VethMap for BTreeMap<VPairKey, VethPair> {
    fn merge_in_veth(&mut self, k: VPairKey, v: VethPair) -> Result<()> {
        let ex = self.remove(&k);
        match ex {
            None => {
                self.insert(k, v);
            }
            Some(exv) => {
                let merged = exv.merge(v)?;
                self.insert(k, merged);
            }
        };
        Ok(())
    }
}

impl NSNetlink {
    /// removes a link from netlink, and removes it from the local state
    pub async fn remove_link<'at>(&'at mut self, k: &'at LinkKey) -> Result<()> {
        // keeping invariant by data hiding.
        // we want to reflect the state of links as that vector
        let v = self.remove_link_(k).await?;
        if let Some(ref vpk) = v.pair {
            let vp: _ = self.veths.remove(&vpk).ok_or(DevianceError)?;
            match vp.pointerize() {
                Some(p) => match p {
                    VPairP::Both => {
                        // if both veth ends are present in one NS, they are both removed.
                        // as observed on MY machine.
                        self.veths.insert(vpk.to_owned(), VethPair::None);
                    }
                    _ => {
                        self.veths.insert(vpk.to_owned(), vp.remove(k));
                    }
                },
                None => (),
            }
        }
        Ok(())
    }
    pub async fn remove_link_from_veth<'at>(
        &'at mut self,
        vk: &VPairKey,
        p: &VPairP,
    ) -> Result<()> {
        log::trace!("rm {:?} from {:?}", p, vk);
        let v = self.veths.remove(vk).ok_or(DevianceError)?;
        let r = match v {
            VethPair::AB { link_a, link_b } => match p {
                VPairP::A => {
                    self.remove_link_(&link_a).await?;
                    VethPair::B(link_b)
                }
                VPairP::B => {
                    self.remove_link_(&link_b).await?;
                    VethPair::A(link_a)
                }
                VPairP::Both => {
                    self.remove_link_(&link_a).await?;
                    self.remove_link_(&link_b).await?;
                    VethPair::None
                }
            },
            VethPair::A(a) => match p {
                VPairP::A => {
                    self.remove_link_(&a).await?;
                    VethPair::None
                }
                _ => unreachable!(),
            },
            VethPair::B(b) => match p {
                VPairP::B => {
                    self.remove_link_(&b).await?;
                    VethPair::None
                }
                _ => unreachable!(),
            },
            VethPair::None => v,
        };
        self.veths.insert(vk.to_owned(), r);
        Ok(())
    }
    /// internal. remove link without syncing to veth
    async fn remove_link_<'at>(&'at mut self, k: &'at LinkKey) -> Result<Link> {
        // we want to reflect the state of links as that vector
        log::trace!("remove link {:?}", k);
        let v = self.links.remove(k);
        let netlink = self.conn.get();
        match v {
            None => Err(DevianceError.into()),
            Some(v) => {
                netlink.rm_link(v.index.clone()).await?;
                Ok(v)
            }
        }
    }
    /// move link from this ns to dst
    pub async fn move_link_to_ns(&mut self, k: &LinkKey, dst: &mut Netns, fd: RawFd) -> Result<()> {
        log::trace!("move link {:?} to {:?}", k, dst.id);
        let v = self.links.remove(k);
        match v {
            None => Err(DevianceError.into()),
            Some(v) => {
                let netlink = self.conn.get();
                if let Some(ref vpk) = v.pair {
                    let mut vp: VethPair = self.veths.remove(&vpk).ok_or(DevianceError)?;
                    vp = vp.remove(k);
                    self.veths.insert(vpk.to_owned(), vp);
                }
                netlink.ip_setns_by_fd(fd, v.index).await?;
                Link::get(&mut dst.netlink, k.clone()).await?;
                Ok(())
            }
        }
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
        let netlink = ConnRef::new(Arc::new(NetlinkConn::new_in_current_ns()));
        let netlink = NSNetlink::new(netlink).await?;
        Ok(Netns { id: entry, netlink })
    }

    pub async fn proc_current() -> Result<Netns> {
        let id = NSID::proc()?;
        let mut netlink =
            NSNetlink::new(ConnRef::new(Arc::new(NetlinkConn::new_in_current_ns()))).await?;
        netlink.fill().await?;
        Ok(Netns { id, netlink })
    }
    pub fn new(ns: NSID, netlink: NSNetlink) -> Self {
        Self { id: ns, netlink }
    }
    // 'x is shorter than 'a
    pub async fn refresh<'x>(&'x mut self) -> Result<()> {
        // will just rebuild that struct based on the handle
        log::trace!("refresh local netlink expectation for {:?}", self.id);
        let c: ConnRef = self.netlink.conn.clone();
        let mut new_nl: NSNetlink = NSNetlink::new(c).await?;
        new_nl.fill().await?;
        self.netlink = new_nl;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
/// An instance of this struct logically implies the existence of the veth pair
pub enum VethPair {
    AB {
        link_a: LinkKey,
        link_b: LinkKey,
    },
    /// Only the A part exists
    A(LinkKey),
    B(LinkKey),
    /// knowingly None.
    None,
}

impl !Copy for VethPair {}
impl !Clone for VethPair {}

pub(crate) trait SyncLinks {
    /// called once and only once when new link gets discovered
    fn on_link_add(&mut self, k: LinkKey, v: Link) -> Result<()>;
}

use std::ops::Add;

impl Add for VethPair {
    type Output = VethPair;
    fn add(self, rhs: Self) -> Self::Output {
        self.merge(rhs).unwrap()
    }
}

impl VethPair {
    pub async fn get<'a, 'b>(netlink: &'b mut NSNetlink, base_name: &VPairKey) -> Result<()> {
        let lka = base_name.link(true);
        let lkb = base_name.link(false);
        for link_name in [lka, lkb] {
            let result = Link::get(netlink, link_name).await;
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
}

impl VethPair {
    /// you need to ensure both links are not present rn, to not error
    pub async fn new<'a, 'b>(netlink: &'b mut NSNetlink, name: VPairKey) -> Result<()> {
        log::debug!("Create new veth pair, {:?}", name);
        let n = netlink.links.len();
        netlink.conn.get().add_veth_pair(&name).await?;
        Self::get(netlink, &name).await?;
        let m = netlink.links.len();
        if m - n != 2 {
            log::error!("{:?}", netlink.links);
            bail!(DevianceError);
        }
        Ok(())
    }
    /// assumes the existence of the resulting veth
    fn from_link(k: LinkKey) -> Option<(VPairKey, VethPair)> {
        let name = k.0.clone();
        let tr = name.split_at(name.len() - 2).0.to_owned();
        if name.ends_with("_a") {
            Some((VPairKey(tr), VethPair::A(k)))
        } else if name.ends_with("_b") {
            Some((VPairKey(tr), VethPair::B(k)))
        } else {
            None
        }
    }
    /// removes if there is any
    fn remove(self, v: &LinkKey) -> Self {
        match self {
            Self::AB { link_a, link_b } => {
                if v == &link_a {
                    Self::B(link_b)
                } else if v == &link_b {
                    Self::A(link_a)
                } else {
                    Self::AB { link_a, link_b }
                }
            }
            Self::A(link_a) => {
                if v == &link_a {
                    Self::None
                } else {
                    Self::A(link_a)
                }
            }
            Self::B(link_b) => {
                if v == &link_b {
                    Self::None
                } else {
                    Self::B(link_b)
                }
            }
            Self::None => Self::None,
        }
    }
    /// merge an incoming link
    fn merge(self, other: Self) -> Result<Self> {
        match other {
            Self::AB { link_a, link_b } => match self {
                VethPair::None => Ok(VethPair::AB { link_a, link_b }),
                _ => Err(DevianceError.into()),
            },
            Self::A(a) => match self {
                Self::B(b) => Ok(VethPair::AB {
                    link_a: a,
                    link_b: b,
                }),
                VethPair::None => Ok(VethPair::A(a)),
                _ => Err(DevianceError.into()),
            },
            Self::B(b) => match self {
                Self::A(a) => Ok(VethPair::AB {
                    link_a: a,
                    link_b: b,
                }),
                VethPair::None => Ok(VethPair::B(b)),
                _ => Err(DevianceError.into()),
            },
            VethPair::None => Ok(self),
        }
    }
    pub fn pointerize(&self) -> Option<VPairP> {
        match self {
            VethPair::A(_) => Some(VPairP::A),
            VethPair::B(_) => Some(VPairP::B),
            VethPair::AB { .. } => Some(VPairP::Both),
            VethPair::None => None,
        }
    }
}

use derivative::Derivative;

// invariant: Link can be created from netlink requests
// and consumed by setns calls.
// So it cannot be Clone, or Copy
#[derive(Derivative)]
#[derivative(Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Link {
    pub up: bool,
    pub name: String,
    #[derivative(Hash = "ignore")]
    #[derivative(PartialEq = "ignore")]
    pub addrs: BTreeSet<IpNetwork>,
    pub index: u32,
    /// associated veth pair if any
    pub pair: Option<VPairKey>,
    #[derivative(Hash = "ignore")]
    #[derivative(PartialEq = "ignore")]
    #[derivative(PartialOrd = "ignore")]
    #[derivative(Ord = "ignore")]
    #[derivative(Debug = "ignore")]
    conn: ConnRef,
}

impl !Copy for Link {}
impl !Clone for Link {}

impl ConnRef {
    #[inline]
    pub fn new(value: Arc<NetlinkConn>) -> Self {
        Self { r: value }
    }
}

impl Link {
    pub async fn get(netlink: &mut NSNetlink, name: LinkKey) -> Result<()> {
        log::trace!("refresh {:?}", name);
        let msg = netlink.conn.get().get_link(name.clone()).await?;
        let up = msg.header.flags & IFF_UP != 0;

        let mut l: Link = Link {
            up,
            name: name.0.to_owned(),
            addrs: BTreeSet::new(),
            index: msg.header.index,
            conn: netlink.conn.clone(),
            pair: None,
        };
        if let Some((vk, vp)) = VethPair::from_link(name.clone()) {
            netlink.veths.merge_in_veth(vk.clone(), vp)?;
            l.pair = Some(vk);
        }
        netlink.links.insert(name.clone(), l);

        Ok(())
    }
}

impl Link {
    /// We are logically assured that the link exists at this moment
    pub async fn up(&mut self, netlink: &NetlinkConn) -> Result<()> {
        if self.up {
            // XXX It should be true, iff there is no external interference
            // I think I shouldn't do check here.
            // Just let it fail and at some point this struct will be recreated, by calling `existence`
            Ok(())
        } else {
            netlink.set_link_up(self.index).await?;
            self.up = true;
            Ok(())
        }
    }
    /// ensure that an addr exists
    pub async fn add_addr(&mut self, ip: IpNetwork) -> Result<()> {
        if self.addrs.contains(&ip) {
            // we don't error here.
        } else {
            self.conn.get().add_addr_dev(ip, self.index).await?;
            // updates local perception if it suceeds
            self.addrs.insert(ip);
        }
        Ok(())
    }
    /// ensure 2 addrs
    pub async fn ensure_addrs_46(&mut self, v4: IpNetwork, v6: IpNetwork) -> Result<()> {
        self.add_addr(v4).await?;
        self.add_addr(v6).await?;
        Ok(())
    }
    // there is no individual link add method for now
}

impl NetlinkConn {
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
            .veth(base_name.link(true).into(), base_name.link(false).into())
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

use rtnetlink::proxy;

#[derive(Debug)]
/// About multiple ns-es
pub struct MultiNS {
    /// RPC.
    pub procs: SubHub,
    /// Take mut reference when operating on an NS.
    pub ns: RwLock<HashMap<NSID, RwLock<Netns>>>,
    paths: Arc<ConfPaths>,
    proxy_ctx: Arc<RwLock<proxy::ProxyCtx>>,
    ctx: TaskCtx
}

impl ConfPaths {
    pub fn sock4proxy(&self) -> PathBuf {
        self.sock.join("ns_proxy.sock")
    }
    pub fn sock4rpc(&self) -> PathBuf {
        self.sock.join("nsp_rpc.sock")
    }
    pub fn sock4ctrl(&self) -> PathBuf {
        self.sock.join("nsp.sock")
    }
}

impl MultiNS {
    pub async fn new(paths: Arc<ConfPaths>, ctx: TaskCtx) -> Result<MultiNS> {
        let ct = proxy::ProxyCtx::new(paths.sock4proxy())?;
        let mn = MultiNS {
            procs: SubHub::new(ctx.clone(), paths.clone()).await?,
            ns: Default::default(),
            paths,
            proxy_ctx: Arc::new(RwLock::new(ct)),
            ctx,
        };
        Ok(mn)
    }
    pub async fn init_current(&self) -> Result<()> {
        let ro = Netns::proc_current().await?;
        let mut m = self.ns.write().await;
        m.insert(ro.id.clone(), ro.into());
        Ok(())
    }
    /// may be called only once per NSID
    pub async fn get_nl(&self, id: NSID) -> Result<NetlinkConn> {
        use proxy::*;
        use rtnetlink::netlink_proto::new_connection_with_socket;
        use rtnetlink::netlink_sys::constants::NETLINK_ROUTE;

        let (mut stream, r) = self.procs.op(id.clone()).await?;
        match r {
            sub::OpRes::NewSub => {
                log::trace!("Handle newly created sub for {}", id);
                // start listening
                let pc = self.proxy_ctx.clone();
                let gs = tokio::spawn(async move {
                    let mut p = pc.write().await;
                    let ou = p.get_subs(1).await;
                    TaskOutput::handle_task_result(ou, "wait-on-sub".to_owned());
                });
                let (u, g) = get_non_priv_user(None, None, None, None)?;
                stream
                    .send(ToSub::Init((*self.paths).clone(), u, g, id.clone()))
                    .await?;
                gs.await?;
                // wait for gs. and the proxy will run in background.
                let pc = self.proxy_ctx.clone();
                let (sx, rx) = oneshot::channel();
                let ino = id.inode.clone();
                let tas = async move {
                    let (mut conn, handle, m) = {
                        let mut pcw = pc.write().await;
                        let mut params = ProxyCtxP {
                            shared: &mut pcw,
                            inode: ino,
                        };

                        new_connection_with_socket::<
                            _,
                            ProxySocket<{ ProxySocketType::PollRecvFrom }>,
                        >(NETLINK_ROUTE, &mut params)?
                    };

                    conn.socket_mut().init().await;
                    sx.send((handle, m))
                        .map_err(|_| anyhow!("sending handle failed"))?;
                    conn.await;
                    Ok(())
                }; // must start it now
                let (t, _r) = TaskOutput::immediately(
                    Box::pin(tas),
                    "netlink-conn-".to_owned() + &id.inode.to_string(), // this waits on the conn. it ends when the conn ends
                );
                self.ctx.dae.send(t).unwrap();
                let (h, _m) = rx.await?;
                let rth = Handle::new(h);
                let nc = NetlinkConn { handle: rth };
                log::trace!("Got netlink for {}", id.inode);

                Ok(nc)
                // then insert nc into self.netlinks. then call init_for
            }
            sub::OpRes::Existing => unreachable!(), // this method shouldn't be called twice
        }
    }
}

impl<V: VSpecifics> SubjectInfo<V> {
    /// places the veth and adds addrs. generic over V
    pub async fn apply_veths(&self, sys: &MultiNS, de: &Derivative) -> Result<()> {
        let map = sys.ns.read().await;
        let subject_ns_lock = map.get(&self.ns).ok_or(DevianceError)?;
        let mut subject_ns = subject_ns_lock.write().await;
        let (mut sub, _) = sys.procs.op(self.ns.clone()).await?;
        log::trace!("{}, iterate over vaddrs", self.ns);
        for (n, c) in self.vaddrs.iter() {
            let id = n.resolve_d(&de).await?;
            if id == self.ns {
                // Would cause a deadlock.
                bail!("VethConn can not have a connection to subject NS itself");
            }
            let t_ns_lock = map.get(&id).ok_or(DevianceError)?;
            let mut t_ns = t_ns_lock.write().await;
            let fd = sub.get_fd(id).await?;
            c.apply(&mut subject_ns, &mut t_ns, fd).await?;
        }
        Ok(())
    }
    pub fn apply_nft_veth(&self, incr: &mut IncrementalNft) {
        for (_n, v) in &self.vaddrs {
            incr.drop_packets_from(v.key.0.to_owned());
        }
    }
    pub async fn apply_nft_dns(&self) -> Result<()> {
        let pro = self.profile.as_ref().unwrap();
        if pro.dnsproxy.enable {
            let p = pro.dnsproxy.port;
            log::info!(
                "{} Apply nft rules, redirect all TCP/UDP requests to :53 to localhost:{p}",
                self.ns
            );
            let s = redirect_dns(p)?;
            s.apply().await?;
        }
        Ok(())
    }
}

impl VethConn {
    /// Adaptive application of Veth connection, accepting dirty state
    pub async fn apply<'n>(
        &self,
        subject_ns: &'n mut Netns,
        t_ns: &'n mut Netns,
        t_fd: RawFd,
    ) -> Result<()> {
        log::info!("Apply VethConn {} to {}", subject_ns.id, t_ns.id);
        if subject_ns.id == t_ns.id {
            bail!("Invalid VethConn, subject and target NS can not be the same");
        }
        let mut create: bool = false;
        let mut b_in_t = false;
        let mut a_in_s = false;
        // input state, relevant veths may exist in NSes or not. in case of weird state, it's outright removed.

        if let Some(ve) = t_ns.netlink.veths.get(&self.key) {
            if let Some(p) = ve.pointerize() {
                match p {
                    VPairP::Both => {
                        // should not happen
                        create = true;
                        t_ns.netlink.remove_link_from_veth(&self.key, &p).await?;
                    }
                    VPairP::A => {
                        // should not happen
                        create = true;
                        t_ns.netlink.remove_link_from_veth(&self.key, &p).await?;
                    }
                    VPairP::B => b_in_t = true,
                }
            }
        }
        if let Some(ve) = subject_ns.netlink.veths.get(&self.key) {
            if let Some(p) = ve.pointerize() {
                match p {
                    VPairP::Both => {
                        subject_ns
                            .netlink
                            .move_link_to_ns(&self.key.link(false), t_ns, t_fd)
                            .await?;
                        a_in_s = true;
                    }
                    VPairP::B => {
                        // should not happen
                        create = true;
                        subject_ns
                            .netlink
                            .remove_link_from_veth(&self.key, &p)
                            .await?;
                    }
                    VPairP::A => a_in_s = true,
                }
            }
        }
        // either one of the pair exists <==> a_in_s/b_in_t filled
        if !a_in_s || !b_in_t {
            create = true;
            if a_in_s {
                subject_ns.netlink.remove_link(&self.key.link(true)).await?;
            }
            if b_in_t {
                t_ns.netlink.remove_link(&self.key.link(false)).await?;
            }
        }
        if create {
            VethPair::new(&mut subject_ns.netlink, self.key.to_owned()).await?;
            subject_ns
                .netlink
                .move_link_to_ns(&self.key.link(false), t_ns, t_fd)
                .await?;
        }
        // now place addrs
        let v = subject_ns
            .netlink
            .veths
            .get(&self.key)
            .ok_or(DevianceError)?;
        if let VethPair::A(a) = v {
            let l = subject_ns.netlink.links.get_mut(a).ok_or(DevianceError)?;
            l.ensure_addrs_46(self.ip_va, self.ip6_va).await?;
            l.up(subject_ns.netlink.conn.get()).await?;
        } else {
            dbg!(&subject_ns.netlink);
            bail!(DevianceError);
        }
        let v = t_ns.netlink.veths.get(&self.key).ok_or(DevianceError)?;
        if let VethPair::B(b) = v {
            let l = t_ns.netlink.links.get_mut(b).ok_or(DevianceError)?;
            l.ensure_addrs_46(self.ip_vb, self.ip6_vb).await?;
            l.up(t_ns.netlink.conn.get()).await?;
        } else {
            dbg!(&t_ns.netlink);
            bail!(DevianceError);
        }

        Ok(())
    }
}
