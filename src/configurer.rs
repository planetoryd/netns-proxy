#![feature(ip)]
#![feature(async_closure)]
#![feature(exit_status_error)]
#![feature(setgroups)]


use futures::{FutureExt, TryFutureExt};
use ipnetwork::IpNetwork;
use tokio::io::AsyncWriteExt;

use crate::watcher::ActiveProfiles;
use crate::{nft::FO_CHAIN};
use anyhow::{anyhow, Ok, Result};
use netns_rs::{NetNs};
use nix::{
    sched::CloneFlags,
    unistd::{setgroups, Gid, Uid},
};
use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;

use std::{
    ffi::{CString, OsString},
    net::{Ipv4Addr},
    os::{fd::RawFd, unix::process::CommandExt},
    path::{Path, PathBuf},
    process::{exit},
};
use std::{collections::HashMap};
use std::{os::fd::AsRawFd};
use tokio::{
    self,
    fs::File,
    io::{AsyncBufReadExt, AsyncReadExt},
};

pub const NETNS_PATH: &str = "/run/netns/";

// generated info and state store
#[derive(Serialize, Deserialize, Default)]
pub struct ConfigRes {
    // resultant/generated info for each persistent/named netns
    pub netns_info: HashMap<String, NetnsInfo>,
    // Flatpak instance pids to profile names. Transient.
    pub flatpak: Option<ActiveProfiles>,
    pub root_inode: u64,
    // Counter, for any number x > counter such that x is never used
    // which ensures non-collision within the scope of one ConfigRes
    // currently not in use. I don't bother deleting it
    pub counter: u16,
}

// It may contain secret proxy parameters, so let's just consider them a secret as a whole
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Secret {
    // netns_name to params
    // aka, Profiles
    pub params: HashMap<String, NetnsParams>,
    // Flatpak app IDs to profile names
    pub flatpak: HashMap<String, String>,
}

pub struct NetnspState {
    pub res: ConfigRes,
    pub conf: Secret,
    pub paths: ConfPaths,
    nft_refresh_once: bool,
}

pub struct ConfPaths {
    conf: String,
    res: String,
}

// Each instance has a unique NetnsInfo
// identified by pid OR persistent name
pub type InstanceID = either::Either<i32, String>;

impl Default for ConfPaths {
    fn default() -> Self {
        Self {
            conf: "./secret.json".to_owned(),
            res: "./netnsp.json".to_owned(),
        }
    }
}

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
    // for nftables
    pub async fn get_link_names_persistent(&self) -> Result<Vec<String>> {
        let base_names: Vec<&String> = self
            .res
            .netns_info
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
            .netns_info
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
        })
    }
}

// aka, Profiles
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct NetnsParams {
    // the program to be run along
    // it is run as non-root, but not sandboxed too.
    pub cmd: Option<NetnsParamCmd>,
    // the port which the socks5 proxy is at
    // defaults to 9909
    pub hport: Option<u32>,
    // whether you want to chain proxies
    // set to true and Tun2socks will direct traffic to socks5://localhost:1080
    // set to false and traffic will be directed to socks5:://veth_host:hport
    #[serde(default)]
    pub chain: bool,
    // if you have an ipv6 only proxy
    // this would force all DNS to go ipv6
    #[serde(default)]
    pub ipv6: bool,
    pub dns_argv: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct NetnsParamCmd {
    pub program: String,
    pub argv: Vec<String>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct NetnsInfo {
    pub base_name: String, // has no length limit
    pub subnet_veth: String,
    pub subnet6_veth: String,
    pub ip_vh: String,
    pub ip6_vh: String,
    pub ip_vn: String,
    pub ip6_vn: String,
    pub veth_base_name: String, // veth names have length limit
    pub id: u16,                // unique
}

fn set_initgroups(user: &nix::unistd::User, gid: u32) {
    let gid = Gid::from_raw(gid);
    let s = user.name.clone();
    let c_str = CString::new(s).unwrap();
    match nix::unistd::initgroups(&c_str, gid) {
        std::result::Result::Ok(_) => log::debug!("Setting initgroups..."),
        Err(e) => {
            log::error!("Failed to set init groups: {:#?}", e);
            exit(1);
        }
    }
}

pub fn drop_privs(name: &str) -> Result<()> {
    log::trace!("drop privs, to {name}");
    let log_user = users::get_user_by_name(name).unwrap();
    let gi = Gid::from_raw(log_user.primary_group_id());
    let ui = Uid::from_raw(log_user.uid());
    log::trace!("GID to {gi}");
    nix::unistd::setresgid(gi, gi, gi)?;
    log::trace!("change groups");
    setgroups(&[gi])?;
    log::trace!("UID to {ui}");
    nix::unistd::setresuid(ui, ui, ui)?;

    log::info!("dropped privs");

    Ok(())
}

pub fn drop_privs1(gi: Gid, ui: Uid) -> Result<()> {
    log::trace!("groups, {:?}", nix::unistd::getgroups()?);
    log::trace!("GID to {gi}");
    nix::unistd::setresgid(gi, gi, gi)?;
    let user = nix::unistd::User::from_uid(ui).unwrap().unwrap();
    set_initgroups(&user, gi.as_raw());
    log::trace!("UID to {ui}");
    nix::unistd::setresuid(ui, ui, ui)?;

    log::info!("dropped privs to resuid={ui} resgid={gi}");

    Ok(())
}

// fd will not have CLOEXEC
pub fn nsfd(ns_name: &str) -> Result<RawFd> {
    use nix::fcntl::{open, OFlag};
    use nix::sys::stat::Mode;
    let mut p = PathBuf::from(NETNS_PATH);
    p.push(ns_name);
    open(&p, OFlag::O_RDONLY, Mode::empty()).map_err(anyhow::Error::from)
}

// fd will not have CLOEXEC
pub fn nsfd_by_path(p: &Path) -> Result<RawFd> {
    use nix::fcntl::{open, OFlag};
    use nix::sys::stat::Mode;
    open(p, OFlag::O_RDONLY, Mode::empty()).map_err(anyhow::Error::from)
}

pub fn ns_exists(ns_name: &str) -> Result<bool> {
    let mut p = PathBuf::from(NETNS_PATH);
    p.push(ns_name);
    let r = p.try_exists().map_err(anyhow::Error::from)?;
    if r {
        anyhow::ensure!(p.is_file());
    }
    Ok(r)
    // throws error if abnormality beyond exists-or-not appears
}

use futures::stream::TryStreamExt;
use netlink_packet_route::{rtnl::link::LinkMessage, IFF_UP};
use rtnetlink::Handle;

pub struct Configurer {
    handle: Handle,
}

use crate::nft;

// in the root ns
// creates a pair of veths, and moves one into netns
// returns addrs
// must be used without CLOEXEC
pub async fn config_pre_enter_ns(
    neti: &NetnsInfo,
    configurer: &Configurer,
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
    // configurer
    //     .set_up(&veth_from_base(&neti.veth_base_name, true))
    //     .await?;

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

    let mut path = std::env::current_exe()?;
    path.pop();
    path.push("netnsp-sub");

    let mut cmd: tokio::process::Child = tokio::process::Command::new(path.clone())
        .arg(fd.to_string())
        .arg(&neti.veth_base_name)
        .uid(0)
        .spawn()
        .unwrap();
    cmd.wait().await?;

    // move a veth into ns
    configurer
        .ip_setns_by_fd(fd, &veth_from_base(&neti.veth_base_name, false))
        .await?;

    log::trace!("ns {} configured", neti.base_name);
    nix::unistd::close(fd)?;
    Ok(())
}

// one last step of the above fn
pub async fn config_pre_enter_ns_up(neti: &NetnsInfo, configurer: &Configurer) -> Result<()> {
    configurer
        .set_up(&veth_from_base(&neti.veth_base_name, true))
        .await?;

    Ok(())
}

pub async fn config_in_ns(fd: RawFd, veth_base_name: String) -> Result<()> {
    enter_ns_by_fd(fd)?;
    let configurer = Configurer::new();
    let rh = configurer
        .get_link(&veth_from_base(&veth_base_name, false))
        .await;
    if rh.is_err() {
        // do nothing, and later netnsp-main will move a veth in
    } else {
        configurer
            .handle
            .link()
            .del(rh.unwrap().header.index) // the one in root ns
            .execute()
            .await
            .map_err(|e| anyhow!("removing {veth_base_name} veth in guest ns fails. {e}"))?;
    }
    Ok(())
}

pub async fn config_network(configurer: &Configurer, state: &mut NetnspState) -> Result<()> {
    let ns_names: Vec<String> = state.profile_names();
    for ns in &ns_names {
        let netinfo_o;
        let netinfo;
        match state.res.netns_info.get(ns) {
            None => {
                netinfo_o = state.new_netinfo(ns.clone()).await?;
                state
                    .res
                    .netns_info
                    .insert(ns.to_owned(), netinfo_o.clone());
                netinfo = &netinfo_o
            }
            Some(n) => netinfo = n,
        }

        Configurer::add_netns(&ns).await?;
        let fd = nsfd(&ns)?;
        config_pre_enter_ns(&netinfo, configurer, fd.as_raw_fd()).await?;
    }
    state.res.root_inode = get_pid1_netns_inode().await?;
    state.dump().await?;
    state.apply_nft().await?;
    for ns in &ns_names {
        let info = state.res.netns_info.get(ns).unwrap();
        config_pre_enter_ns_up(info, configurer).await?;
    }
    Ok(())
}

pub async fn get_pid1_netns_inode() -> Result<u64> {
    use procfs::process::Process;
    let pid1_process = Process::new(1)?;
    let nslist = pid1_process.namespaces()?;
    let pid1_net_ns = nslist
        .get(&OsString::from("net"))
        .ok_or_else(|| anyhow::anyhow!("PID 1 net namespace not found"))?;

    Ok(pid1_net_ns.identifier)
}

pub fn get_self_netns_inode() -> Result<u64> {
    use procfs::process::Process;
    let selfproc = Process::myself()?;
    let nslist = selfproc.namespaces()?;
    let selfns = nslist.get(&OsString::from("net"));
    match selfns {
        None => anyhow::bail!("self net ns file missing"),
        Some(ns) => Ok(ns.identifier),
    }
}

pub fn get_self_netns() -> Result<netns_rs::NetNs> {
    use procfs::process::Process;
    let selfproc = Process::myself()?;
    let nslist = selfproc.namespaces()?;
    let selfns = nslist.get(&OsString::from("net"));
    match selfns {
        None => anyhow::bail!("self net ns file missing"),
        Some(ns) => {
            use netns_rs::get_from_path;
            let netns_ = get_from_path(&ns.path)?;
            Ok(netns_)
        }
    }
}

// None for non-persistent ns
pub async fn self_netns_identify() -> Result<Option<(String, NetNs)>> {
    use netns_rs::get_from_path;

    let selfns = get_self_netns()?;
    let path = Path::new(NETNS_PATH);
    for entry in path.read_dir()? {
        if let core::result::Result::Ok(entry) = entry {
            let ns = get_from_path(entry.path())?;
            if ns == selfns {
                // identified to be x netns
                // ==> there is a file under netns path, readable and matches proc netns
                return Ok(Some((
                    ns.path()
                        .file_name()
                        .ok_or_else(|| anyhow::anyhow!("OsStr"))?
                        .to_string_lossy()
                        .into_owned(),
                    ns,
                )));
            }
        }
        // some iter may fail and get ignored but that should be fine
    }
    Ok(None) // means, "no matches under NETNS_PATH"
}

use netns_rs::Env;

pub struct NsEnv;

impl Env for NsEnv {
    fn persist_dir(&self) -> PathBuf {
        NETNS_PATH.into()
    }
}

pub fn veth_from_base(basename: &str, host: bool) -> String {
    let basename = basename.to_owned();
    if basename.len() > 12 {
        unreachable!()
    }
    if host {
        format!("{basename}_vh")
    } else {
        format!("{basename}_vn")
    }
}

impl Configurer {
    pub fn new() -> Self {
        use rtnetlink::new_connection;
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);

        Self { handle }
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
    pub async fn set_up(&self, name: &str) -> Result<()> {
        log::trace!("get link {} up", name);
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_owned())
            .execute();
        if let Some(link) = links.try_next().await? {
            let is_up = link.header.flags & IFF_UP != 0;
            if is_up {
                Ok(())
            } else {
                self.handle
                    .link()
                    .set(link.header.index)
                    .up()
                    .execute()
                    .await
                    .map_err(anyhow::Error::from)
            }
        } else {
            Err(anyhow!("link message None"))
        }
    }
    pub async fn add_veth_pair(&self, base_name: &str) -> Result<bool> {
        // netlink would error if name is too long
        let rh = self.get_link(&veth_from_base(base_name, true)).await;

        if rh.is_err() {
            // do nothing
        } else {
            // remove them
            self.handle
                .link()
                .del(rh.unwrap().header.index) // the one in root ns
                .execute()
                .await
                .map_err(|e| anyhow!("removing {base_name} veth in root ns fails. {e}"))?;
            // also the one in ns
            // but it will be done by other fn later
        };
        let r1 = self
            .handle
            .link()
            .add()
            .veth(
                veth_from_base(base_name, true),
                veth_from_base(base_name, false),
            )
            .execute()
            .await
            .map_err(|e| anyhow!("adding {base_name} veth pair fails. {e}"));
        return match r1 {
            Err(e) => {
                let rh = self.get_link(&veth_from_base(base_name, false)).await;
                if rh.is_ok() {
                    log::warn!(
                        "Are you running from a sub-netns. {} exists. Or, you killed netnsproxy process half-way",
                        &veth_from_base(base_name, false)
                    );
                }
                Err(e)
            }
            _ => Ok(false), // veths dont exist, adding suceeded
        };
    }
    pub async fn add_addr_dev(&self, addr: IpNetwork, dev: &str) -> Result<()> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(dev.to_string())
            .execute();
        if let Some(link) = links.try_next().await? {
            let mut get_addr = self
                .handle
                .address()
                .get()
                .set_link_index_filter(link.header.index)
                .set_prefix_length_filter(addr.prefix())
                .set_address_filter(addr.ip())
                .execute();
            if let Some(_addrmsg) = get_addr.try_next().await? {
                Ok(())
            } else {
                // the desired IP has not been added
                self.handle
                    .address()
                    .add(link.header.index, addr.ip(), addr.prefix())
                    .execute()
                    .await
                    .map_err(anyhow::Error::from)
            }
        } else {
            Err(anyhow!("link message None"))
        }
    }

    pub async fn ip_setns_by_fd(&self, fd: RawFd, dev: &str) -> Result<()> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(dev.to_owned())
            .execute();
        let linkmsg = links.try_next().await;
        match linkmsg {
            core::result::Result::Ok(Some(link)) => self
                .handle
                .link()
                .set(link.header.index)
                .setns_by_fd(fd)
                .execute()
                .await
                .map_err(anyhow::Error::from),
            _ => {
                // should be present in the netns
                // omit checks here. netns-sub should check them
                Ok(())
            }
        }
    }

    pub async fn ip_setns(&self, ns_name: &str, dev: &str) -> Result<()> {
        let fd = nsfd(ns_name)?;
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(dev.to_owned())
            .execute();
        let linkmsg = links.try_next().await;
        match linkmsg {
            core::result::Result::Ok(Some(link)) => self
                .handle
                .link()
                .set(link.header.index)
                .setns_by_fd(fd.as_raw_fd())
                .execute()
                .await
                .map_err(anyhow::Error::from),
            _ => {
                // should be present in the netns
                // omit checks here. netns-sub should check them
                Ok(())
            }
        }
    }

    pub async fn add_netns(ns_name: &str) -> Result<()> {
        use rtnetlink::NetworkNamespace;
        if ns_exists(ns_name)? {
            Ok(())
        } else {
            NetworkNamespace::add(ns_name.to_string())
                .await
                .map_err(anyhow::Error::from)
        }
    }

    // one of dst and v4 must be Some
    pub async fn ip_add_route(
        &self,
        dev: &str,
        dst: Option<IpNetwork>,
        v4: Option<bool>,
    ) -> Result<()> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(dev.to_owned())
            .execute();
        if let Some(link) = links.try_next().await? {
            let index = link.header.index;
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
        } else {
            Err(anyhow!("link message None"))
        }
    }

    pub async fn add_addrs_guest(&self, base_name: &str, info: &NetnsInfo) -> Result<()> {
        log::trace!("add addrs in guest ns");
        self.add_addr_dev(
            info.ip_vn.clone().parse()?,
            veth_from_base(&base_name, false).as_ref(),
        )
        .await
        .ok();
        self.add_addr_dev(
            info.ip6_vn.clone().parse()?,
            veth_from_base(&base_name, false).as_ref(),
        )
        .await
        .ok();

        Ok(())
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
        log::debug!("{pre} {}", line);
        while let Some(line) = reader.next_line().await? {
            log::trace!("{pre} {}", line);
        }
    }
    Ok(())
}

pub async fn watch_both(
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

pub async fn enter_ns_by_name(ns_name: &str) -> Result<()> {
    let fd = nsfd(ns_name)?;
    nix::sched::setns(fd, CloneFlags::CLONE_NEWNET)?;
    nix::unistd::close(fd)?;
    let got_ns = self_netns_identify().await?.ok_or_else(|| {
        anyhow::anyhow!("failed to identify netns. no matches under the given netns directory")
    })?;

    anyhow::ensure!(got_ns.0 == ns_name);
    log::info!("current ns {} (named and persistent)", got_ns.0);

    Ok(())
}

pub fn enter_ns_by_fd(ns_fd: RawFd) -> Result<()> {
    nix::sched::setns(ns_fd, CloneFlags::CLONE_NEWNET)?;
    let stat = nix::sys::stat::fstat(ns_fd)?;
    let selfi = get_self_netns_inode()?;
    anyhow::ensure!(stat.st_ino == selfi);
    Ok(())
}

// ensure that the ns does not match self ns
pub fn ensure_ns_not_root(ns_fd: RawFd) -> Result<()> {
    let stat = nix::sys::stat::fstat(ns_fd)?;
    let selfi = get_self_netns_inode()?;
    anyhow::ensure!(stat.st_ino != selfi);
    Ok(())
}

pub fn enter_ns_by_pid(pi: i32) -> Result<()> {
    let process = procfs::process::Process::new(pi)?;
    let o: OsString = OsString::from("net");
    let nss = process.namespaces()?;
    let proc_ns = nss
        .get(&o)
        .ok_or(anyhow!("ns/net not found for given pid"))?;
    let r = std::fs::File::open(&proc_ns.path)?;
    nix::sched::setns(r.as_raw_fd(), CloneFlags::CLONE_NEWNET)?;
    let self_inode = get_self_netns_inode()?;
    anyhow::ensure!(proc_ns.identifier == self_inode);
    log::info!("current ns is from pid {}", pi);
    Ok(())
}
