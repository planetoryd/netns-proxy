use either::Either::Left;
use futures::{FutureExt, StreamExt, TryFutureExt};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use crate::{
    nft::FO_CHAIN,
    sub::{NetnspSub, NetnspSubCaller, NetnspSubImpl},
    util,
};

use anyhow::{anyhow, Ok, Result};
use netns_rs::NetNs;
use nix::{
    sched::CloneFlags,
    unistd::{setgroups, Gid, Pid, Uid},
};

use std::{collections::HashSet, net::Ipv6Addr};

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::{
    ffi::{CString, OsString},
    net::Ipv4Addr,
    os::{fd::RawFd, unix::process::CommandExt},
    path::{Path, PathBuf},
    process::exit,
};
use tokio::{
    self,
    fs::File,
    io::{AsyncBufReadExt, AsyncReadExt},
};

use crate::util::ns::*;
use crate::util::perms::*;

use crate::data::*;

impl ConfigRes {
    pub fn try_get_netinfo(&self, pid: i32) -> Result<&NetnsInfo> {
        Ok(&self
            .flatpak
            .as_ref()
            .ok_or_else(|| anyhow!("no flatpak: HashMap"))?
            .get(&pid)
            .ok_or_else(|| anyhow!("Failed to retrieve net info for process {}", pid))?
            .net)
        // map1.get(key).or_else(|| map2.get(key)).unwrap_or(&"not found");
    }
}

impl NetnspState {
    pub async fn clean_net(&self, configurer: &NetlinkConn) -> Result<()> {
        // remove veth in the root ns
        let pnames = self.get_link_names_persistent().await?;
        for pl in pnames {
            let mut links = configurer.handle.link().get().match_name(pl).execute();
            if let Result::Ok(Some(link)) = links.try_next().await {
                let i = link.header.index;
                configurer.handle.link().del(i).execute().await?;
            }
        }
        // remove persistent NSes
        let nsnames = self.profile_names();
        for ns in nsnames {
            let nso = netns_rs::NetNs::get(&ns);
            if nso.is_ok() {
                NetworkNamespace::del(ns).await?;
            }
        }
        Ok(())
    }
    // for nftables
    pub async fn get_link_names_persistent(&self) -> Result<Vec<String>> {
        let base_names: Vec<&String> = self
            .res
            .namedns
            .iter()
            .map(|x| &x.1.veth_base_name)
            .collect();

        let veth_host: Vec<String> = base_names
            .iter()
            .map(|base| veth_from_base(base, true))
            .collect();
        Ok(veth_host)
    }
    // do a full sync of firewall intention
    pub async fn apply_nft(&mut self) -> Result<()> {
        let i_names = self.get_link_names_persistent().await?;
        let inames = i_names.iter().map(|s| s.as_str()).collect::<Vec<&str>>();

        nft::apply_block_forwad(&inames)?;
        // added the tables and chains
        self.nft_refresh_once = true;
        // after that only individual rules need to be added for each flatpak
        Ok(())
    }
    // incrementally apply rules for an interface
    // may error if the a full sync hasn't been done beforehand
    pub async fn nft_for_interface(&self, name: &str) -> Result<()> {
        use rustables::*;
        log::info!("add nft rule for {}", name);
        let table = Table::new(ProtocolFamily::Inet).with_name(nft::TABLE_NAME.to_owned());
        let chain = Chain::new(&table)
            .with_hook(Hook::new(HookClass::Forward, 0))
            .with_name(FO_CHAIN)
            .with_policy(ChainPolicy::Accept);
        let rule = nft::drop_interface_rule(name, &chain)?;
        let mut batch: Batch = Batch::new();
        batch.add(&rule, MsgType::Add);
        batch.send()?;

        Ok(())
    }
    pub async fn load(paths: ConfPaths) -> Result<Self> {
        let path = Path::new(&paths.conf);
        let mut file = File::open(path).await?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).await?;

        let secret: Secret = serde_json::from_str(&contents)?;

        let path = Path::new(&paths.res);
        let mut res: ConfigRes = if path.exists() {
            let mut file = tokio::fs::File::open(path).await?;
            let mut contents = String::new();
            file.read_to_string(&mut contents).await?;
            // will reject if missing fields
            serde_json::from_str(&contents)?
        } else {
            // allow it to not exist
            ConfigRes::default()
        };
        if res.flatpak.is_none() {
            res.flatpak = Some(HashMap::new())
        }

        Ok(Self {
            res,
            conf: secret,
            paths,
            nft_refresh_once: false,
        })
    }
    pub fn profile_names(&self) -> Vec<String> {
        self.conf.clone().params.into_keys().collect()
    }
    pub async fn dump(&self) -> Result<()> {
        let serialized = serde_json::to_string_pretty(&self.res)?;
        let mut file = tokio::fs::File::create(&self.paths.res).await?;
        log::info!("config result dumped in ./netnsp.json.");
        file.write_all(serialized.as_bytes()).await?;
        Ok(())
    }
    pub fn get_avail_id(&self) -> Result<u16> {
        const MAX: u16 = 255;
        let mut ids: Vec<u16> = self
            .res
            .namedns
            .iter()
            .map(|x| x.1.id)
            .chain(
                self.res
                    .flatpak
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(|x| x.1.net.id),
            )
            .collect();
        ids.sort();
        let mut i = 0;
        while i + 1 < ids.len() {
            if ids[i + 1] - ids[i] > 1 {
                return Ok(ids[i] + 1);
            }
            i += 1;
        }
        if ids.len() > 0 {
            if ids.last().unwrap() < &MAX {
                return Ok(ids.last().unwrap() + 1);
            }
            Err(anyhow::anyhow!("no id avail"))
        } else {
            Ok(0)
        }
    }
    // generate NetnsInfo for a new isntance, ie. non-duplicating IPs
    pub async fn new_netinfo(&self, base_name: String) -> Result<NetnsInfo> {
        let id: u16 = self.get_avail_id()?;
        let id8: u8 = id.try_into()?;
        let pre4: u8 = 24;
        let pre6: u8 = 112;
        let subnet_veth: IpNetwork = IpNetwork::new(Ipv4Addr::new(10, 27, id8, 0).into(), pre4)?;
        let subnet6_veth: IpNetwork = IpNetwork::new(
            Ipv6Addr::new(0xfc0f, 0x2cdd, 0xeeff, 0, 0, 0, id, 0).into(),
            pre6,
        )?;
        let ip_vh: IpNetwork = IpNetwork::new(Ipv4Addr::new(10, 27, id8, 1).into(), pre4)?;
        let ip_vn: IpNetwork = IpNetwork::new(Ipv4Addr::new(10, 27, id8, 2).into(), pre4)?;
        let ip6_vh: IpNetwork = IpNetwork::new(
            Ipv6Addr::new(0xfc0f, 0x2cdd, 0xeeff, 0, 0, 0, id, 1).into(),
            pre6,
        )?;
        let ip6_vn: IpNetwork = IpNetwork::new(
            Ipv6Addr::new(0xfc0f, 0x2cdd, 0xeeff, 0, 0, 0, id, 2).into(),
            pre6,
        )?;

        Ok(NetnsInfo {
            base_name: base_name.clone(),
            subnet_veth: subnet_veth.to_string(),
            subnet6_veth: subnet6_veth.to_string(),
            ip_vh: ip_vh.to_string(),
            ip_vn: ip_vn.to_string(),
            ip6_vh: ip6_vh.to_string(),
            ip6_vn: ip6_vn.to_string(),
            veth_base_name: if base_name.len() < 12 {
                base_name
            } else {
                "nsp".to_owned() + &id.to_string()
            },
            id: id.into(),
            tun_ip: None,
            link_base_name: None,
        })
    }
    pub async fn orchestrate_persisns(&mut self, configurer: &NetlinkConn) -> Result<()> {
        // all the named ns have addrs generated
        let mut invalid_entries = HashSet::new();
        for (nsname, info) in &mut self.res.namedns {
            let profile = self.conf.params.get(nsname);
            if profile.is_none() {
                invalid_entries.insert(nsname.to_owned());
                continue;
            }
            let selfns = named_ns(&nsname)?;
            orchestrate_newns(info, profile.unwrap(), configurer, selfns.as_raw_fd()).await?;
        }
        self.res
            .namedns
            .retain(|k, _v| !invalid_entries.contains(k));
        Ok(())
    }
}

use futures::stream::TryStreamExt;
use netlink_packet_route::{nlas::link::State, rtnl::link::LinkMessage, AddressMessage, IFF_UP};
use rtnetlink::{Handle, NetworkNamespace};

pub struct NetlinkConn {
    pub handle: Handle,
}

use crate::nft;

// in the root ns
// creates a pair of veths, and moves one into netns
// returns addrs
// must be used without CLOEXEC
/// it does not close fd ever
pub async fn config_pre_enter_ns(
    neti: &NetnsInfo,
    configurer: &NetlinkConn,
    fd: RawFd,
) -> Result<()> {
    configurer.add_veth_pair(&neti.veth_base_name).await?;
    // we always get a fresh pair of veths after that

    configurer
        .add_addr_dev(
            neti.ip_vh.parse()?,
            &veth_from_base(&neti.veth_base_name, true).as_ref(),
        )
        .await?;
    configurer
        .add_addr_dev(
            neti.ip6_vh.parse()?,
            &veth_from_base(&neti.veth_base_name, true).as_ref(),
        )
        .await?;
    // it will be set up after nftables gets confgiured

    configurer
        .add_addr_dev(
            neti.ip_vn.parse()?,
            &veth_from_base(&neti.veth_base_name, false),
        )
        .await?;
    configurer
        .add_addr_dev(
            neti.ip6_vn.parse()?,
            &veth_from_base(&neti.veth_base_name, false),
        )
        .await?;
    configurer
        .set_up(&veth_from_base(&neti.veth_base_name, false))
        .await?;

    // briefly enter the ns
    // have to use a process, or tokio will be messed up

    let nsub = NetnspSubCaller::default();
    nsub.remove_vethb_in_ns(fd, neti.veth_base_name.clone())
        .await?;

    // move a veth into ns
    configurer
        .ip_setns_by_fd(fd, &veth_from_base(&neti.veth_base_name, false))
        .await?;

    // add a pair of veths. this ns -> some named ns

    log::trace!("ns {} configured", neti.base_name);
    Ok(())
}

/// it does not close self_ns
pub async fn orchestrate_newns(
    info: &mut NetnsInfo,
    profile: &NetnsParams,
    configurer: &NetlinkConn,
    self_ns: RawFd,
) -> Result<()> {
    // all named ns exist at this point
    if let Some(targetns) = &profile.connect {
        let lname = format!("nlink{}", info.id);
        // ip of self ns
        // let self_ip = Ipv4Addr::new(10, 28, info.id.try_into().unwrap(), 1);
        // ip of other ns
        let targetip = Ipv4Addr::new(10, 28, info.id.try_into().unwrap(), 2);
        let target_ns = named_ns(targetns)?;

        // both are pure functions on id
        info.tun_ip = Some(targetip.to_string());
        info.link_base_name = Some(lname.clone());
        let nsb = NetnspSubCaller::default();
        // cleans veth_from_base(&lname, false) from target ns
        nsb.remove_vethb_in_ns(target_ns.as_raw_fd(), lname.clone())
            .await?;
        configurer.add_veth_pair_d(&lname).await?;
        log::trace!("added ns->ns link {}", lname);
        configurer
            .ip_setns(&targetns, &veth_from_base(&lname, false).as_ref())
            .await?;
        configurer
            .ip_setns_by_fd(self_ns, &veth_from_base(&lname, true).as_ref())
            .await?;
        configurer
            .get_link(&veth_from_base(&lname, false))
            .await
            .err()
            .unwrap();
        configurer
            .get_link(&veth_from_base(&lname, true))
            .await
            .err()
            .unwrap();
        let ipn = IpNetwork::new(info.tun_ip.as_ref().unwrap().parse()?, 24)?;
        nsb.config_in_ns_up(
            target_ns.as_raw_fd(),
            info.link_base_name.clone().unwrap(),
            ipn,
        )
        .await?;
    }
    Ok(())
}

// one last step of the above fn
pub async fn config_pre_enter_ns_up(neti: &NetnsInfo, configurer: &NetlinkConn) -> Result<()> {
    configurer
        .set_up(&veth_from_base(&neti.veth_base_name, true))
        .await?;

    Ok(())
}

pub async fn config_network(netlink: &NetlinkConn, state: &mut NetnspState) -> Result<()> {
    let ns_names: Vec<String> = state.profile_names();
    for ns in &ns_names {
        let netinfo_o;
        let netinfo;
        match state.res.namedns.get(ns) {
            None => {
                netinfo_o = state.new_netinfo(ns.clone()).await?;
                state.res.namedns.insert(ns.to_owned(), netinfo_o.clone());
                netinfo = &netinfo_o
            }
            Some(n) => netinfo = n,
        }

        let mut rootns = Netns::root_ns(netlink).await?;
        let rootns_handle = rootns.op_netlink()?;
        let mut newns = Netns::new(either::Either::Right(ns.clone()), netlink).await?;
        let newns_handle = newns.op_netlink()?;
        let vpk = VethPair::new(netlink, netinfo.veth_base_name.clone(), rootns_handle).await?;
        // TODO: remove veth in target ns
        match rootns_handle.veths.get(&vpk).unwrap() {
            VethPair::AB { link_a, link_b } => {
                rootns_handle
                    .move_link_to_ns(&link_b.clone(), &mut newns, netlink)
                    .await?;
            }
            _ => anyhow::bail!(DevianceError),
        }
    }
    state.res.root_inode = get_pid1_netns_inode().await?;
    state.dump().await?;
    state.apply_nft().await?;
    for ns in &ns_names {
        let info = state.res.namedns.get(ns).unwrap();
        config_pre_enter_ns_up(info, netlink).await?;
    }
    state.orchestrate_persisns(netlink).await?;
    Ok(())
}

pub struct Netns {
    file: File,
    id: either::Either<Pid, String>,
    netlink: NSNetlink, // veths: HashMap<String, VethPair>
}

// deleting a netns consumes it
impl !Copy for Netns {}
impl !Clone for Netns {}

#[derive(Serialize, Deserialize)]
/// netlink info
pub struct NSNetlink {
    /// other links
    links: HashMap<LinkKey, Link>,
    /// identified veth pairs
    veths: HashMap<VPairKey, VethPair>,
    links_index: HashMap<u32, LinkKey>,
}

#[derive(Serialize, Deserialize, Hash, PartialEq, Eq, Clone, Debug)]
pub struct LinkKey(String);

#[derive(Serialize, Deserialize, Hash, PartialEq, Eq, Clone)]
struct VPairKey(String);

use thiserror::Error;

#[derive(Error, Debug)]
#[error("Removal when it doesn't exist, or addition when it already exists etc.")]
pub struct DevianceError;

pub enum VPairI {
    A,
    B,
    Both,
}

impl SyncVethP for NSNetlink {
    fn on_vethp_add(&mut self, k: &VPairKey, v: VethPair) -> Result<()> {
        self.veths.insert(*k, v);
        Ok(())
    }
    fn on_link_add(&mut self, k: &LinkKey, v: Link) -> Result<()> {
        self.links.insert(*k, v);
        Ok(())
    }
}

impl NSNetlink {
    /// retrieves the list of links and info for ns
    pub async fn init(netlink: &NetlinkConn) -> Result<Self> {
        let mut links = netlink.handle.link().get().execute();
        let mut ml = HashMap::new();
        let mut mv = HashMap::new();
        let mut mlindex = HashMap::new();
        while let Some(link) = links.try_next().await? {
            let mut name = None;
            let mut up = None;
            let index = link.header.index;
            for n in link.nlas {
                match n {
                    netlink_packet_route::nlas::link::Nla::IfName(n) => name = Some(n),
                    netlink_packet_route::nlas::link::Nla::OperState(s) => match s {
                        State::Up => up = Some(true),
                        _ => (),
                    },
                    _ => (),
                }
            }
            let name = name.ok_or(DevianceError)?;
            let mut li = Link {
                name: name.clone(),
                up: up.ok_or(DevianceError)?,
                index,
                addrs: vec![],
                pair: None,
            };
            let lk = LinkKey(name);
            let ve = VethPair::from_link(lk.clone());
            if let Some((vk, vp)) = ve {
                li.pair = Some(vk.clone());
                mv.insert(vk, vp);
            }
            ml.insert(lk.clone(), li);
            mlindex.insert(index, lk);
        }
        // the filter is not done by kernel. hence just do it here.
        let addrs = netlink.handle.address().get().execute();
        let addrs: Vec<AddressMessage> = addrs.try_collect().await?;
        for addr in addrs {
            let index_of_the_link_too = addr.header.index; // as observed.
            for msg in addr.nlas {
                let mut ipnet: Option<IpNetwork> = None;
                match msg {
                    netlink_packet_route::address::Nla::Address(a) => {
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
                    util::hashmap_chain_mut(&mlindex, &ml, &index_of_the_link_too)
                        .unwrap()
                        .addrs
                        .push(ipnet);
                }
            }
        }
        Ok(Self {
            links: ml,
            veths: mv,
            links_index: mlindex,
        })
    }
    /// also syncs to veth
    pub async fn remove_link(&mut self, k: &LinkKey, netlink: &NetlinkConn) -> Result<()> {
        // keeping invariant by data hiding.
        // we want to reflect the state of links as that vector
        let v = self.links.remove(k);
        match v {
            None => Err(DevianceError.into()),
            Some(v) => {
                netlink.rm_link(v.index.clone()).await?;
                if let Some(ref vpk) = v.pair {
                    let vp: &mut VethPair = self.veths.get_mut(&vpk).ok_or(DevianceError)?;
                    vp.remove(k.clone());
                }
                Ok(())
            }
        }
    }
    async fn move_link_to_ns(
        &mut self,
        k: &LinkKey,
        target: &mut Netns,
        netlink: &NetlinkConn,
    ) -> Result<()> {
        let v = self.links.remove(k);
        match v {
            None => Err(DevianceError.into()),
            Some(mut v) => {
                if let Some(ref vpk) = v.pair {
                    // remove it from local veth
                    let vp: &mut VethPair = self.veths.get_mut(&vpk).ok_or(DevianceError)?;
                    vp.remove(k.clone());
                }
                netlink
                    .ip_setns_by_fd(target.file.as_raw_fd(), v.index)
                    .await?;
                v.up = false;
                v.addrs = vec![];
                v.pair = None;
                target.netlink.links.insert(k.clone(), v);
                target.netlink.sync_link_to_veth(k);

                Ok(())
            }
        }
    }
    fn sync_link_to_veth(&mut self, k: &LinkKey) -> Result<()> {
        let link = self.links.get_mut(k).ok_or(DevianceError)?;
        let vk = VethPair::from_link(*k);
        match vk {
            Some(vk) => {
                link.pair = Some(vk.0);
                self.insert_veth(&vk.0, vk.1);
            }
            None => {}
        };
        Ok(())
    }
    fn insert_veth(&mut self, k: &VPairKey, v: VethPair) -> Result<()> {
        let ex = self.veths.get(k);
        match ex {
            None => {
                self.veths.insert(*k, v);
            }
            Some(exv) => {
                let merged = exv.merge(v)?;
                self.veths.insert(*k, merged);
            }
        };
        Ok(())
    }
}

// invariant: Netns struct exists ==> Netns exists in root ns
// so we can partially check the code before compiling
// we get an Netns obj to perform ops on it
// and we get a VethPair obj inside, and add addrs to it
impl Netns {
    /// get a netns and spawn a netnsp-sub process.
    /// if named ns doesn't exist, add it. If it does, get it.
    pub async fn new(entry: either::Either<Pid, String>, netlink: &NetlinkConn) -> Result<Self> {
        // we have two ways to entry
        // after the entry, we should not touch the raw things outside this object
        let o = match entry {
            either::Either::Right(ref name) => {
                if named_ns_exist(&name)? {
                    Netns {
                        file: util::ns::named_ns(&name)?,
                        id: entry,
                        netlink: NSNetlink::init(netlink).await?,
                    }
                } else {
                    add_netns(&name).await?;
                    Netns {
                        file: util::ns::named_ns(&name)?,
                        id: entry,
                        netlink: NSNetlink::init(netlink).await?,
                    }
                }
            }
            Left(p) => Netns {
                file: util::ns::get_ns_by_pid(p.as_raw())?,
                id: entry,
                netlink: NSNetlink::init(netlink).await?,
            },
        };
        Ok(o)
    }
    /// shorthand for new() of pid 1
    pub async fn root_ns(netlink: &NetlinkConn) -> Result<Self> {
        Self::new(either::Either::Left(Pid::from_raw(1)), netlink).await
    }
    pub fn op_netlink(&mut self) -> Result<&mut NSNetlink> {
        let curr = get_self_netns_inode()?;
        let stat = nix::sys::stat::fstat(self.file.as_raw_fd())?;
        anyhow::ensure!(stat.st_ino == curr);
        Ok(&mut self.netlink)
    }
}

#[derive(Serialize, Deserialize)]
/// An instance of this struct logically implies the existence of the veth pair
pub enum VethPair {
    AB {
        link_a: LinkKey,
        link_b: LinkKey,
    },
    /// Only the A part exists
    A(LinkKey),
    B(LinkKey),
    None,
}

impl !Copy for VethPair {}
impl !Clone for VethPair {}

/// upper layer structs may keep state about links
pub(crate) trait SyncVethP {
    fn on_vethp_add(&mut self, k: &VPairKey, v: VethPair) -> Result<()>;
    /// called once and only once when new link gets discovered
    fn on_link_add(&mut self, k: &LinkKey, v: Link) -> Result<()>;
}

impl VethPair {
    async fn get<K: SyncVethP>(
        netlink: &NetlinkConn,
        base_name: &str,
        keeper: &mut K,
    ) -> Result<Self> {
        let link_a = Link::get(netlink, &Self::veth_name_from_base(base_name, true)).await;
        let link_b = Link::get(netlink, &Self::veth_name_from_base(base_name, false)).await;

        let r = if let Result::Ok(link_a) = link_a {
            keeper.on_link_add(&link_a.0, link_a.1)?;
            if let Result::Ok(link_b) = link_b {
                keeper.on_link_add(&link_b.0, link_b.1)?;
                VethPair::AB {
                    link_a: link_a.0,
                    link_b: link_b.0,
                }
            } else {
                VethPair::A(link_a.0)
            }
        } else if let Result::Ok(link_b) = link_b {
            keeper.on_link_add(&link_b.0, link_b.1)?;
            VethPair::B(link_b.0)
        } else {
            VethPair::None
        };

        Ok(r)
    }
    /// true for a
    pub fn veth_name_from_base(basename: &str, ab: bool) -> String {
        let basename = basename.to_owned();
        if basename.len() > 12 {
            unreachable!()
        }
        if ab {
            format!("{basename}_a")
        } else {
            format!("{basename}_b")
        }
    }
    fn from_link(k: LinkKey) -> Option<(VPairKey, VethPair)> {
        let name = k.0;
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
    fn remove(&mut self, v: LinkKey) -> Self {
        match self {
            Self::AB { link_a, link_b } => {
                if v == *link_a {
                    Self::B(*link_b)
                } else if v == *link_b {
                    Self::A(*link_a)
                } else {
                    Self::AB {
                        link_a: *link_a,
                        link_b: *link_b,
                    }
                }
            }
            Self::A(link_a) => {
                if v == *link_a {
                    Self::None
                } else {
                    Self::A(*link_a)
                }
            }
            Self::B(link_b) => {
                if v == *link_b {
                    Self::None
                } else {
                    Self::B(*link_b)
                }
            }
            Self::None => Self::None,
        }
    }
    /// merge an incoming link
    fn merge(self, other: Self) -> Result<Self> {
        match other {
            Self::AB { link_a, link_b } => match self {
                VethPair::None => Ok(other),
                _ => Err(DevianceError.into()),
            },
            Self::A(a) => match self {
                Self::B(b) => Ok(VethPair::AB {
                    link_a: a,
                    link_b: b,
                }),
                VethPair::None => Ok(other),
                _ => Err(DevianceError.into()),
            },
            Self::B(b) => match self {
                Self::A(a) => Ok(VethPair::AB {
                    link_a: a,
                    link_b: b,
                }),
                VethPair::None => Ok(other),
                _ => Err(DevianceError.into()),
            },
            VethPair::None => Ok(self),
        }
    }
    pub async fn new<K: SyncVethP>(
        netlink: &NetlinkConn,
        name: String,
        keeper: &mut K,
    ) -> Result<VPairKey> {
        netlink
            .add_veth_pair(&name, Self::veth_name_from_base)
            .await?;
        // should just get it from netlink, 'cause there is a index field
        let p = Self::get(netlink, &name, keeper).await?;
        let k = VPairKey(name);
        // like event propagation
        keeper.on_vethp_add(&k, p)?;

        Ok(k)
    }
}

// invariant: Link can be created from netlink requests
// and consumed by setns calls.
// So it cannot be Clone, or Copy
#[derive(Serialize, Deserialize, Hash, PartialEq, Eq)]
struct Link {
    up: bool,
    name: String,
    addrs: Vec<IpNetwork>,
    index: u32,
    /// associated veth pair if any
    pair: Option<VPairKey>,
}

impl !Copy for Link {}
impl !Clone for Link {}

impl Link {
    pub(crate) async fn get(netlink: &NetlinkConn, name: &str) -> Result<(LinkKey, Self)> {
        let msg = netlink.get_link(name).await?;
        let up = msg.header.flags & IFF_UP != 0;
        let k = LinkKey(name.to_string());
        Ok((
            k,
            Link {
                up,
                name: name.to_string(),
                addrs: vec![],
                pair: None,
                index: msg.header.index,
            },
        ))
    }
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
    pub async fn add_addr() {}
    // there is no individual link add method for now
}

impl NetlinkConn {
    pub fn new(x: Link) -> Self {
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
    pub async fn get_link(&self, name: &str) -> Result<LinkMessage> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_owned())
            .execute();
        if let Some(link) = links.try_next().await? {
            Ok(link)
        } else {
            Err(anyhow!("link message None"))
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
    pub async fn add_veth_pair(&self, base_name: &str, f: fn(&str, bool) -> String) -> Result<()> {
        self.handle
            .link()
            .add()
            .veth(f(base_name, true), f(base_name, false))
            .execute()
            .await
            .map_err(|e| anyhow!("adding {base_name} veth pair fails. {e}"))
    }
    pub async fn add_addr_dev(&self, addr: IpNetwork, dev: u32) -> Result<()> {
        let mut get_addr = self
            .handle
            .address()
            .get()
            .set_link_index_filter(dev)
            .set_prefix_length_filter(addr.prefix())
            .set_address_filter(addr.ip())
            .execute();
        if let Some(_addrmsg) = get_addr.try_next().await? {
            Ok(())
        } else {
            // the desired IP has not been added
            self.handle
                .address()
                .add(dev, addr.ip(), addr.prefix())
                .execute()
                .await
                .map_err(anyhow::Error::from)
        }
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

// prepare a TUN for tun2socks
pub fn tun_ops(tun: tidy_tuntap::Tun) -> Result<()> {
    let fd = tun.as_raw_fd();

    // as tested, the line below is needless.
    // unsafe { tunsetowner(fd, 1000)? };
    unsafe { tunsetpersist(fd, 1)? }; // works if uncommented

    Ok(())
}

pub async fn watch_log(
    mut reader: tokio::io::Lines<tokio::io::BufReader<impl tokio::io::AsyncRead + Unpin>>,
    tx: Option<tokio::sync::oneshot::Sender<bool>>,
    pre: String,
) -> Result<()> {
    if let Some(line) = reader.next_line().await? {
        if tx.is_some() {
            tx.unwrap().send(true).unwrap();
        }
        log::info!("{pre} {}", line);
        while let Some(line) = reader.next_line().await? {
            log::info!("{pre} {}", line);
        }
    }
    Ok(())
}

pub fn watch_both(
    chil: &mut tokio::process::Child,
    pre: String,
    tx: Option<tokio::sync::oneshot::Sender<bool>>,
) -> Result<()> {
    let stdout = chil.stdout.take().unwrap();
    let stderr = chil.stderr.take().unwrap();
    let reader = tokio::io::BufReader::new(stdout).lines();
    let reader2 = tokio::io::BufReader::new(stderr).lines();
    tokio::spawn(watch_log(reader, tx, pre.clone()));
    tokio::spawn(watch_log(reader2, None, pre));

    Ok(())
}
