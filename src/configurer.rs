#![feature(ip)]
#![feature(async_closure)]
#![feature(exit_status_error)]
#![feature(setgroups)]
use flexi_logger::FileSpec;

use futures::{FutureExt, TryFutureExt};
use ipnetwork::IpNetwork;
use tokio::io::AsyncWriteExt;

use crate::watcher::ActiveProfiles;
use crate::{gen_ip, watcher};
use anyhow::{anyhow, Context, Ok, Result};
use netns_rs::{DefaultEnv, NetNs};
use nix::{
    libc::{kill, SIGTERM},
    sched::CloneFlags,
    unistd::{getppid, setgroups, Gid, Uid},
};
use serde::{Deserialize, Serialize};
use std::{
    borrow::{Borrow, Cow},
    ffi::{CStr, CString, OsString},
    net::{Ipv4Addr, SocketAddrV6},
    os::{fd::RawFd, unix::process::CommandExt},
    path::{Path, PathBuf},
    process::{exit, Stdio},
};
use std::{collections::HashMap, time::Duration};
use std::{env, os::fd::AsRawFd};
use sysinfo::{self, PidExt, ProcessExt, System, SystemExt};
use tokio::{
    self,
    fs::File,
    io::{AsyncBufReadExt, AsyncReadExt},
    process::Command,
};
pub const NETNS_PATH: &str = "/run/netns/";

#[derive(Serialize, Deserialize, Default)]
pub struct ConfigRes {
    // resultant/generated info for each persistent/named netns
    pub netns_info: HashMap<String, NetnsInfo>,
    // Flatpak instance pids to profile names. Transient.
    pub flatpak: Option<ActiveProfiles>,
    pub root_inode: u64,
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

impl Default for ConfPaths {
    fn default() -> Self {
        Self {
            conf: "./secret.json".to_owned(),
            res: "./netnsp.json".to_owned(),
        }
    }
}

impl NetnspState {
    // for nftables
    pub async fn get_all_link_names(&self) -> Result<Vec<String>> {
        let base_names: Vec<&String> = self
            .res
            .netns_info
            .keys()
            .chain(self.conf.flatpak.keys())
            .collect();
        let veth_host: Vec<String> = base_names
            .iter()
            .map(|base| veth_from_base(base, true))
            .collect();
        Ok(veth_host)
    }
    // do a full sync of firewall intention
    pub async fn apply_nft(&self) -> Result<()> {
        let i_names = self.get_all_link_names().await?;
        let inames = i_names.iter().map(|s| s.as_str()).collect::<Vec<&str>>();

        nft::apply_block_forwad(&inames)?;
        Ok(())
    }
    // incrementally apply rules for an interface
    // may error if the a full sync hasn't been done beforehand
    pub async fn nft_for_interface(&self, name: &str) -> Result<()> {
        use rustables::*;
        let table = Table::new(ProtocolFamily::Inet).with_name(nft::TABLE_NAME.to_owned());
        let chain = Chain::new(&table)
            .with_hook(Hook::new(HookClass::Forward, 0))
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
    pub subnet_veth: String,
    pub subnet6_veth: String,
    pub ip_vh: String,
    pub ip6_vh: String,
    pub ip_vn: String,
    pub ip6_vn: String,
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

pub fn nsfd(ns_name: &str) -> Result<std::fs::File> {
    let mut p = PathBuf::from(NETNS_PATH);
    p.push(ns_name);
    let r = std::fs::File::open(p)?;
    Ok(r)
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

// Trys to add an netns. If it exists, remove it.
// Get the NS up.
pub async fn config_ns(
    ns_name: &str,
    f: fn(&str, bool) -> String,
    config_res: &mut ConfigRes,
    configurer: &Configurer,
) -> Result<()> {
    Configurer::add_netns(ns_name).await?;
    let vpair_skipped = configurer.add_veth_pair(ns_name).await?;

    // Get a subnet in 10.0 for the veth pair
    let subnet_veth =
        gen_ip("10.0.0.0/8".parse().unwrap(), ns_name.to_string(), None, 16).to_string();
    let subnet6_veth =
        gen_ip("fc00::/16".parse().unwrap(), ns_name.to_string(), None, 125).to_string();

    let ip_vh = gen_ip(
        "10.0.0.0/8".parse().unwrap(),
        ns_name.to_string(),
        Some("vh".to_string()),
        16,
    )
    .ip();
    let ip_vn = gen_ip(
        "10.0.0.0/8".parse().unwrap(),
        ns_name.to_string(),
        Some("vn".to_string()),
        16,
    )
    .ip();

    let ip6_vh = gen_ip(
        "fc00::/16".parse().unwrap(),
        ns_name.to_string(),
        Some("ip6vh".to_string()),
        125,
    )
    .ip();
    let ip6_vn = gen_ip(
        "fc00::/16".parse().unwrap(),
        ns_name.to_string(),
        Some("ip6vn".to_string()),
        125,
    )
    .ip();

    let info = NetnsInfo {
        subnet_veth: subnet_veth.clone(),
        subnet6_veth: subnet6_veth.clone(),
        ip_vh: ip_vh.to_string(),
        ip6_vh: ip6_vh.to_string(),
        ip_vn: ip_vn.to_string(),
        ip6_vn: ip6_vn.to_string(),
    };

    configurer
        .add_addr_dev(
            (info.ip_vh.clone() + "/16").parse()?,
            f(&ns_name, true).as_ref(),
        )
        .await?;
    configurer
        .add_addr_dev(
            (info.ip6_vh.clone() + "/125").parse()?,
            f(&ns_name, true).as_ref(),
        )
        .await?;
    configurer.set_up(&f(&ns_name, true)).await?;

    if !vpair_skipped {
        configurer
            .add_addr_dev(
                (info.ip_vn.clone() + "/16").parse()?,
                f(&ns_name, false).as_ref(),
            )
            .await?;
        configurer
            .add_addr_dev(
                (info.ip6_vn.clone() + "/125").parse()?,
                f(&ns_name, false).as_ref(),
            )
            .await?;
        configurer.set_up(&f(&ns_name, true)).await?;
    } else {
        // ensure it does not exist
        let linkmsg_veth_ns = configurer.get_link(&f(&ns_name, false)).await;
        anyhow::ensure!(linkmsg_veth_ns.is_err())
    }

    log::info!("veth subnet {subnet_veth}, {subnet6_veth}, host {ip_vh}, {ip6_vh}, guest {ip_vn}, {ip6_vn}");

    assert!(!ip_vh.is_global());
    assert!(!ip6_vh.is_global());
    configurer.ip_setns(ns_name, &f(ns_name, false)).await?;
    config_res.netns_info.insert(ns_name.to_owned(), info);

    log::trace!("ns {ns_name} configured");
    Ok(())
}

pub async fn config_pre_enter_ns(
    base_name: &str,
    veth_name: fn(&str, bool) -> String,
    configurer: &Configurer,
    fd: RawFd,
) -> Result<NetnsInfo> {
    let vpair_skipped = configurer.add_veth_pair(base_name).await?;

    // Get a subnet in 10.0 for the veth pair
    let subnet_veth = gen_ip(
        "10.0.0.0/8".parse().unwrap(),
        base_name.to_string(),
        None,
        16,
    )
    .to_string();
    let subnet6_veth = gen_ip(
        "fc00::/16".parse().unwrap(),
        base_name.to_string(),
        None,
        125,
    )
    .to_string();

    let ip_vh = gen_ip(
        "10.0.0.0/8".parse().unwrap(),
        base_name.to_string(),
        Some("vh".to_string()),
        16,
    )
    .ip();
    let ip_vn = gen_ip(
        "10.0.0.0/8".parse().unwrap(),
        base_name.to_string(),
        Some("vn".to_string()),
        16,
    )
    .ip();

    let ip6_vh = gen_ip(
        "fc00::/16".parse().unwrap(),
        base_name.to_string(),
        Some("ip6vh".to_string()),
        125,
    )
    .ip();
    let ip6_vn = gen_ip(
        "fc00::/16".parse().unwrap(),
        base_name.to_string(),
        Some("ip6vn".to_string()),
        125,
    )
    .ip();

    let info = NetnsInfo {
        subnet_veth: subnet_veth.clone(),
        subnet6_veth: subnet6_veth.clone(),
        ip_vh: ip_vh.to_string(),
        ip6_vh: ip6_vh.to_string(),
        ip_vn: ip_vn.to_string(),
        ip6_vn: ip6_vn.to_string(),
    };

    configurer
        .add_addr_dev(
            (info.ip_vh.clone() + "/16").parse()?,
            veth_name(&base_name, true).as_ref(),
        )
        .await?;
    configurer
        .add_addr_dev(
            (info.ip6_vh.clone() + "/125").parse()?,
            veth_name(&base_name, true).as_ref(),
        )
        .await?;
    configurer.set_up(&veth_name(&base_name, true)).await?;

    if !vpair_skipped {
        configurer
            .add_addr_dev(
                (info.ip_vn.clone() + "/16").parse()?,
                veth_name(&base_name, false).as_ref(),
            )
            .await?;
        configurer
            .add_addr_dev(
                (info.ip6_vn.clone() + "/125").parse()?,
                veth_name(&base_name, false).as_ref(),
            )
            .await?;
        configurer.set_up(&veth_name(&base_name, true)).await?;
    } else {
        // ensure it does not exist
        let linkmsg_veth_ns = configurer.get_link(&veth_name(&base_name, false)).await;
        anyhow::ensure!(linkmsg_veth_ns.is_err())
    }

    log::info!("veth subnet {subnet_veth}, {subnet6_veth}, host {ip_vh}, {ip6_vh}, guest {ip_vn}, {ip6_vn}");

    assert!(!ip_vh.is_global());
    assert!(!ip6_vh.is_global());
    // move a veth into ns
    configurer
        .ip_setns_by_fd(fd, &veth_name(base_name, false))
        .await?;

    log::trace!("ns {} configured", base_name);
    Ok(info)
}

pub async fn config_network(
    ns_names: Vec<String>,
    configrer: &Configurer,
    state: &mut NetnspState,
) -> Result<()> {
    for ns in &ns_names {
        config_ns(&ns, veth_from_base, &mut state.res, &configrer).await?;
    }

    state.res.root_inode = get_pid1_netns_inode().await?;
    state.apply_nft().await?;
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

pub async fn get_self_netns() -> Result<netns_rs::NetNs> {
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

    let selfns = get_self_netns().await?;
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
    pub async fn add_veth_pair(&self, ns_name: &str) -> Result<bool> {
        let rh = self.get_link(&veth_from_base(ns_name, true)).await;

        if rh.is_err() {
            let r1 = self
                .handle
                .link()
                .add()
                .veth(
                    veth_from_base(ns_name, true),
                    veth_from_base(ns_name, false),
                )
                .execute()
                .await
                .map_err(|e| anyhow!("adding {ns_name} veth pair fails. {e}"));
            return match r1 {
                Err(e) => {
                    let rh = self.get_link(&veth_from_base(ns_name, false)).await;
                    if rh.is_ok() {
                        log::warn!(
                            "Are you running from a sub-netns. {} exists",
                            &veth_from_base(ns_name, false)
                        );
                    }
                    Err(e)
                }
                _ => Ok(false), // veths dont exist, adding suceeded
            };
        } else {
            Ok(true) // they already exist, and it skipped adding
        }
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

    pub async fn add_addrs_guest(&self, ns_name: &str, info: &NetnsInfo) -> Result<()> {
        self.add_addr_dev(
            (info.ip_vn.clone() + "/16").parse()?,
            veth_from_base(&ns_name, false).as_ref(),
        )
        .await
        .ok();
        self.add_addr_dev(
            (info.ip6_vn.clone() + "/125").parse()?,
            veth_from_base(&ns_name, false).as_ref(),
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
    nix::sched::setns(nsfd(ns_name)?.as_raw_fd(), CloneFlags::CLONE_NEWNET)?;
    let got_ns = self_netns_identify().await?.ok_or_else(|| {
        anyhow::anyhow!("failed to identify netns. no matches under the given netns directory")
    })?;

    anyhow::ensure!(got_ns.0 == ns_name);
    log::info!("current ns {} (named and persistent)", got_ns.0);

    Ok(())
}

pub async fn enter_ns_by_fd(ns_fd: RawFd) -> Result<()> {
    nix::sched::setns(ns_fd, CloneFlags::CLONE_NEWNET)?;

    Ok(())
}

pub fn enter_ns_by_pid(pi: i32) -> Result<RawFd> {
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

    Ok(r.as_raw_fd())
}

pub fn get_non_priv_user(uid: Option<String>, gid: Option<String>) -> Result<(u32, u32)> {
    let r_ui: u32;
    let r_gi: u32;
    if let core::result::Result::Ok(log_name) = env::var("SUDO_USER") {
        // run from sudo
        let log_user = users::get_user_by_name(&log_name).unwrap();
        r_ui = log_user.uid();
        r_gi = log_user.primary_group_id();
    } else if uid.is_some() && gid.is_some() {
        // supplied
        r_gi = gid.unwrap().parse()?;
        r_ui = uid.unwrap().parse()?;
    } else {
        // as child process of some non-root
        let parent_pid = nix::unistd::getppid();
        let parent_process = match procfs::process::Process::new(parent_pid.into()) {
            core::result::Result::Ok(process) => process,
            Err(_) => panic!("cannot access parent process"),
        };
        r_ui = parent_process.status()?.euid;
        r_gi = parent_process.status()?.egid;
    }

    Ok((r_ui, r_gi))
}
