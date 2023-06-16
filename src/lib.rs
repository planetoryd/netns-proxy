#![feature(ip)]
#![feature(async_closure)]
#![feature(exit_status_error)]
#![feature(setgroups)]
use flexi_logger::FileSpec;

use futures::{FutureExt, TryFutureExt};
use ipnetwork::IpNetwork;

use anyhow::{anyhow, Context, Ok, Result};
use netns_rs::{DefaultEnv, NetNs};
use nix::{
    libc::{kill, SIGTERM},
    sched::CloneFlags,
    unistd::{getppid, setgroups, Gid, Uid},
};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Borrow,
    error::Error,
    ffi::{CStr, OsString, CString},
    net::IpAddr,
    net::{Ipv4Addr, SocketAddrV6},
    ops::Deref,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{exit, Stdio},
};
use std::{collections::HashMap, time::Duration};
use std::{env, os::fd::AsRawFd, process};
use sysinfo::{self, get_current_pid, Pid, PidExt, ProcessExt, System, SystemExt};
use tokio::{
    self,
    fs::File,
    io::{AsyncBufReadExt, AsyncReadExt},
    process::Command,
};
pub mod ip_gen;

use ip_gen::gen_ip;

pub const NETNS_PATH: &str = "/run/netns/";
// Standard procedure
// Creates various netns, base-vpn, socks, i2p, lokinet, un-firewalled
// Kill other running processes, suspected
// Fork, setns, drop privs, start daemons

static mut curr_netns: &str = "";
pub static mut logger: Option<flexi_logger::LoggerHandle> = None;

#[derive(Serialize, Deserialize, Default)]
pub struct ConfigRes {
    pub netns_info: HashMap<String, NetnsInfo>,
    pub root_inode: u64,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Secret {
    pub proxies: HashMap<String, Vec<String>>, // socks proxies per netns
}

#[derive(Serialize, Deserialize, Default)]
pub struct NetnsInfo {
    pub subnet_veth: String,
    pub subnet6_veth: String,
    pub ip_vh: String,
    pub ip6_vh: String,
    pub ip_vn: String,
    pub ip6_vn: String,
}

use futures::stream::TryStreamExt;
use netlink_packet_route::{rtnl::link::LinkMessage, IFF_UP};
use rtnetlink::Handle;

pub struct Configurer {
    handle: Handle,
}

pub fn kill_suspected() {
    let s = System::new_all();
    for (pid, process) in s.processes() {
        // kill by saved pids
        // or by matching commandlines
        let c = process.cmd();
        if c.into_iter().any(|x| x.contains("tun2socks"))
            || c.into_iter().any(|x| x.contains("gost"))
            || c.into_iter().any(|x| x.contains("dnsproxy"))
        {
            println!("killed {pid} {}", c[0]);
            unsafe {
                kill(pid.as_u32() as i32, SIGTERM);
            }
        }
    }
}

pub fn veth_from_ns(nsname: &str, host: bool) -> String {
    if host {
        format!("{nsname}_vh")
    } else {
        format!("{nsname}_vn")
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
        let rh = self.get_link(&veth_from_ns(ns_name, true)).await;

        if rh.is_err() {
            let r1 = self
                .handle
                .link()
                .add()
                .veth(veth_from_ns(ns_name, true), veth_from_ns(ns_name, false))
                .execute()
                .await
                .map_err(|e| anyhow!("adding {ns_name} veth pair fails. {e}"));
            return match r1 {
                Err(e) => {
                    let rh = self.get_link(&veth_from_ns(ns_name, false)).await;
                    if rh.is_ok() {
                        log::warn!(
                            "Are you running from a sub-netns. {} exists",
                            &veth_from_ns(ns_name, false)
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
                    if v4.is_some() && v4.unwrap() {
                        req.v4().execute().await.map_err(anyhow::Error::from)
                    } else {
                        req.v6().execute().await.map_err(anyhow::Error::from)
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
            veth_from_ns(&ns_name, false).as_ref(),
        )
        .await
        .ok();
        self.add_addr_dev(
            (info.ip6_vn.clone() + "/125").parse()?,
            veth_from_ns(&ns_name, false).as_ref(),
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

pub async fn inner_daemon(
    ns_path: String,
    ns_name: &str,
    uid: Option<String>,
    gid: Option<String>,
) -> Result<()> {
    let tun_target_port = 9909;
    use tidy_tuntap::{flags, Tun};
    unsafe {
        log::trace!("set logger");
        // logger = Some(
        //     flexi_logger::Logger::try_with_env_or_str("error,netns_proxy=debug")
        //         .unwrap()
        //         .log_to_file(FileSpec::default())
        //         .duplicate_to_stdout(flexi_logger::Duplicate::All)
        //         .start()
        //         .unwrap(),
        // );
        logger = Some(
            flexi_logger::Logger::try_with_env_or_str("error,netns_proxy=debug")
                .unwrap()
                .log_to_stdout()
                .start()
                .unwrap(),
        );
    }

    let path = "./netnsp.json";
    let mut file = File::open(path).await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;

    let config: ConfigRes = serde_json::from_str(&contents)?;

    let path = "./secret.json";
    let mut file = File::open(path).await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;

    let secret: Secret = serde_json::from_str(&contents)?;

    log::info!("netns-proxy of {ns_path}, daemon started");
    nix::sched::setns(nsfd(ns_name)?.as_raw_fd(), CloneFlags::CLONE_NEWNET)?;

    let got_ns = self_netns_identify()
        .await?
        .ok_or_else(|| anyhow::anyhow!("failed to identify netns"))?;

    let tun_name = "s_tun";
    log::info!("current ns {}", got_ns.0);

    if got_ns.0 != ns_name {
        log::error!("entering netns failed, {} != {}", got_ns.0, ns_name);
        exit(1);
    }

    // as for now, the code above works, the new process is in the netns, checked on 4/24
    // get lo up and check netns
    log::debug!("get interface lo");
    let ns_config = config.netns_info.get(ns_name).unwrap();
    let configurer = Configurer::new();

    configurer.set_up("lo").await?;
    configurer.add_addrs_guest(ns_name, ns_config).await?;

    let tun = Tun::new(tun_name, false).unwrap(); // prepare a TUN for tun2socks, as root.
                                                  // the TUN::new here creates a non-persistent TUN
                                                  // empirically, TUN::new does not error when there is existing TUN with the same name, and says the dev to be up

    let flags = tun.flags().unwrap();
    log::info!("got TUN {}, flags {:?}", tun_name, flags);

    if !flags.intersects(flags::Flags::IFF_UP) {
        log::info!("bring TUN up, {}", tun_name);
        tun.bring_up()?;
        let flags = tun.flags().unwrap();
        anyhow::ensure!(flags.intersects(flags::Flags::IFF_UP));
    }

    tun_ops(tun)?; // drop File

    let base_prxy_v4 =
        "socks5://".to_owned() + &ns_config.ip_vh + ":" + &tun_target_port.to_string();
    // let prxy_ipv6: SocketAddrV6 =
    //     SocketAddrV6::new(ns_config.ip6_vh.parse()?, tun_target_port, 0, 0);
    // let prxy_ipv6 = "socks5://".to_owned() + &prxy_ipv6.to_string();
    // log::debug!("proxy ipv6 {}", prxy_ipv6);

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
        // let pid = nix::unistd::getpid();

        let parent_pid = nix::unistd::getppid();
        let parent_process = match procfs::process::Process::new(parent_pid.into()) {
            core::result::Result::Ok(process) => process,
            Err(_) => panic!("cannot access parent process"),
        };
        r_ui = parent_process.status()?.euid;
        r_gi = parent_process.status()?.egid;
    }

    let gi = Gid::from_raw(r_gi);
    let ui = Uid::from_raw(r_ui);

    assert!(!ui.is_root());
    log::debug!("{gi}, {ui}");

    async fn watch_log(
        mut reader: tokio::io::Lines<tokio::io::BufReader<impl tokio::io::AsyncRead + Unpin>>,
        tx: tokio::sync::oneshot::Sender<bool>,
        pre: &str,
    ) -> Result<()> {
        if let Some(line) = reader.next_line().await? {
            tx.send(true).unwrap();
            log::debug!("{pre} {}", line);
            while let Some(line) = reader.next_line().await? {
                log::trace!("{pre} {}", line);
            }
        }

        Ok(())
    }

    match ns_name {
        "base_p" => {
            let mut tun2 = std::process::Command::new("tun2socks");
            tun2.uid(ui.into()).gid(gi.into()).groups(&[gi.into()]);
            tun2.args(&["-device", tun_name, "-proxy", &base_prxy_v4]);
            let mut tun2_async: Command = tun2.into();
            tun2_async.stdout(Stdio::piped());
            let mut tun2h = tun2_async.spawn()?;
            let stdout = tun2h.stdout.take().unwrap();
            let reader = tokio::io::BufReader::new(stdout).lines();
            let (tx, rx) = tokio::sync::oneshot::channel();
            tokio::spawn(watch_log(reader, tx, "tun2socks"));
            rx.await?;
            configurer.set_up(tun_name).await?;
            configurer.set_up(&veth_from_ns(ns_name, false)).await?;
            configurer
                .ip_add_route(tun_name, None, Some(true))
                .await
                .ok();

            let mut dns = std::process::Command::new("dnsproxy");
            dns.uid(ui.into()).gid(gi.into()).groups(&[gi.into()]);
            dns.args(&[
                "-l",
                "127.0.0.1",
                "-l",
                "127.0.0.53", // systemd-resolved
                "-l",
                "::1",
                "-p",
                "53",
                "-u",
                "tcp://1.1.1.1:53",
                "--cache",
            ]);
            let mut dns_async: Command = dns.into();
            // dns_async.kill_on_drop(true);
            let mut dnsh = dns_async.spawn()?;

            tokio::try_join!(
                tun2h.wait().map_err(|e| e.into()),
                dnsh.wait().map_err(|e| e.into())
            )?;
        }
        "i2p" => {
            // netns that can only access i2p
        }
        "clean_ip1" => {
            let proxy1 = &secret
                .proxies
                .get(ns_name)
                .ok_or(anyhow!("not configured"))?[0];
            assert!(!proxy1.is_empty());
            log::debug!("clean proxy, {proxy1}");

            let mut tun2 = std::process::Command::new("tun2socks");
            tun2.uid(ui.into()).gid(gi.into()).groups(&[gi.into()]);
            tun2.args(&["-device", tun_name, "-proxy", "127.0.0.1:1080"]);
            let mut tun2_async: Command = tun2.into();
            tun2_async.stdout(Stdio::piped());
            let mut tun2h = tun2_async.spawn()?;
            let stdout = tun2h.stdout.take().unwrap();
            let reader = tokio::io::BufReader::new(stdout).lines();
            let (tx, rx) = tokio::sync::oneshot::channel();
            tokio::spawn(watch_log(reader, tx, "clean_ip1_tun"));
            rx.await?;
            configurer.set_up(tun_name).await?;
            configurer.set_up(&veth_from_ns(ns_name, false)).await?;
            configurer
                .ip_add_route(tun_name, None, Some(true))
                .await
                .ok();
            configurer
                .ip_add_route(tun_name, Some("::/0".parse()?), None)
                .await
                .ok();
            // outputs to stdout. no logs kept

            let mut dns = std::process::Command::new("dnsproxy");
            dns.uid(ui.into()).gid(gi.into()).groups(&[gi.into()]);
            dns.args(&[
                "-l",
                "127.0.0.1",
                "-l",
                "127.0.0.53", // systemd-resolved
                "-l",
                "::1",
                "-p",
                "53",
                "-u",
                "tcp://1.1.1.1:53",
                "--cache",
            ]);
            let mut dns_async: Command = dns.into();
            dns_async.kill_on_drop(true);
            let mut dnsh = dns_async.spawn()?;

            let mut gost = std::process::Command::new("gost");
            gost.uid(ui.into()).gid(gi.into()).groups(&[gi.into()]);
            gost.args(&[
                "-L=socks5://localhost:1080",
                ("-F=".to_owned() + &base_prxy_v4).as_ref(),
                &("-F=".to_owned() + proxy1),
            ]);
            let mut gost_async: Command = gost.into();
            let mut gosth = gost_async.spawn()?;

            tokio::try_join!(
                tun2h.wait().map_err(|e| e.into()),
                dnsh.wait().map_err(|e| e.into()),
                gosth.wait().map_err(|e| e.into())
            )?;
        }
        "clean_ipv6" => {
            let proxy6 = &secret
                .proxies
                .get(ns_name)
                .ok_or(anyhow!("not configured"))?[0];
            assert!(!proxy6.is_empty());
            log::debug!("IPv6 proxy, {proxy6}");

            let mut gost = std::process::Command::new("gost");
            gost.uid(ui.into()).gid(gi.into()).groups(&[gi.into()]);
            gost.args(&[
                "-L=socks5://localhost:1080",
                ("-F=".to_owned() + &base_prxy_v4).as_ref(),
                &("-F=".to_owned() + proxy6),
            ]);
            let mut gost_async: Command = gost.into();
            let mut gosth = gost_async.spawn()?;

            let mut tun2 = std::process::Command::new("tun2socks");
            tun2.uid(ui.into()).gid(gi.into()).groups(&[gi.into()]);
            tun2.args(&["-device", tun_name, "-proxy", "127.0.0.1:1080"]);
            let mut tun2_async: Command = tun2.into();
            tun2_async.stdout(Stdio::piped());
            let mut tun2h = tun2_async.spawn()?;
            let stdout = tun2h.stdout.take().unwrap();
            let reader = tokio::io::BufReader::new(stdout).lines();
            let (tx, rx) = tokio::sync::oneshot::channel();
            tokio::spawn(watch_log(reader, tx, "clean_ipv6_tun,"));
            rx.await?;
            configurer.set_up(tun_name).await?;
            configurer.set_up(&veth_from_ns(ns_name, false)).await?;
            configurer
                .ip_add_route(tun_name, None, Some(true))
                .await
                .ok();
            configurer
                .ip_add_route(tun_name, Some("::/0".parse()?), None)
                .await
                .ok();

            // outputs to stdout. no logs kept
            let mut dns = std::process::Command::new("dnsproxy");
            dns.uid(ui.into()).gid(gi.into()).groups(&[gi.into()]);
            dns.args(&[
                "-l",
                "127.0.0.1",
                "-l",
                "127.0.0.53", // systemd-resolved
                "-l",
                "::1",
                "-p",
                "53",
                "-u",
                "tcp://[2620:119:35::35]:53",
                "--cache",
            ]);
            let mut dns_async: Command = dns.into();
            dns_async.kill_on_drop(true);
            let mut dnsh = dns_async.spawn()?;

            tokio::try_join!(
                tun2h.wait().map_err(|e| e.into()),
                dnsh.wait().map_err(|e| e.into()),
                gosth.wait().map_err(|e| e.into())
            )?;
        }
        _ => {
            log::warn!("no matches found, exiting");
        }
    };

    Ok(())
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

pub async fn drop_privs(name: &str) -> Result<()> {
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

pub async fn drop_privs1(gi: Gid, ui: Uid) -> Result<()> {
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

// Trys to add an netns. If it exists, remove it.
// Get the NS up.
pub async fn config_ns(
    ns_name: &str,
    f: fn(&str, bool) -> String,
    config_res: &mut ConfigRes,
    configurer: &Configurer,
) -> Result<()> {
    // rtnetlink sucks. just use the command line
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
    // brilliant me, File::open(p)?.as_raw_fd() got the file closed before use, fixed it

    log::trace!("ns {ns_name} configured");
    Ok(())
}

pub async fn config_network() -> Result<ConfigRes> {
    let mut res = ConfigRes::default();

    let configrer = Configurer::new();
    for ns in TASKS {
        config_ns(&ns, veth_from_ns, &mut res, &configrer).await?;
    }

    res.root_inode = get_pid1_netns_inode().await?;

    Ok(res)
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

pub async fn get_self_netns_inode() -> Result<u64> {
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
    Ok(None)
}

use netns_rs::Env;
struct NsEnv;

impl Env for NsEnv {
    fn persist_dir(&self) -> PathBuf {
        NETNS_PATH.into()
    }
}

pub static TASKS: [&str; 5] = ["base_p", "i2p", "clean_ip1", "clean_ipv6", "lokins"];
