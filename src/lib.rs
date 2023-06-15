#![feature(ip)]
#![feature(async_closure)]
#![feature(exit_status_error)]
#![feature(setgroups)]
use flexi_logger::FileSpec;

use futures::{FutureExt, TryFutureExt};
use ipnetwork::IpNetwork;

use anyhow::{anyhow, Context, Ok, Result};
use nix::{
    libc::{kill, SIGTERM},
    sched::CloneFlags,
    unistd::{getppid, setgroups, Gid, Uid},
};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Borrow,
    error::Error,
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

pub async fn set_up(name: &str) -> Result<()> {
    let res = Command::new("ip")
        .args(["link", "set", name, "up"])
        .output()
        .await?
        .status;
    if res.success() {
        Ok(())
    } else {
        Err(anyhow!("setting {name} up fails"))
    }
}

pub async fn add_veth_pair(ns_name: &str) -> Result<()> {
    let res = Command::new("ip")
        .args([
            "link",
            "add",
            veth_from_ns(ns_name, true).as_ref(),
            "type",
            "veth",
            "peer",
            "name",
            veth_from_ns(ns_name, false).as_ref(),
        ])
        .output()
        .await?
        .status;
    if res.success() {
        Ok(())
    } else {
        Err(anyhow!("adding {ns_name} veth pair fails"))
    }
}

pub async fn add_addr_dev(addr: &str, dev: &str) -> Result<()> {
    let res = Command::new("ip")
        .args(["addr", "add", addr, "dev", dev])
        .output()
        .await?
        .status;
    if res.success() {
        Ok(())
    } else {
        let r = anyhow!("adding {addr} to {dev} fails");
        log::warn!("{r}");
        Err(r)
    }
}

pub async fn ip_setns(ns_name: &str, dev: &str) -> Result<()> {
    let res = Command::new("ip")
        .args(["link", "set", dev, "netns", ns_name])
        .output()
        .await?
        .status;
    if res.success() {
        Ok(())
    } else {
        let r = anyhow!("moving {dev} to {ns_name} fails");
        log::warn!("{r}");
        Err(r)
    }
}

pub async fn inner_daemon(
    ns_path: String,
    ns_name: &str,
    uid: Option<String>,
    gid: Option<String>,
) -> Result<()> {
    let tun_target_port = 9909;

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

    let got_ns_ = String::from_utf8(
        Command::new("ip")
            .args(["netns", "identify"])
            .arg(nix::unistd::getpid().to_string())
            .uid(0)
            .output()
            .await?
            .stdout,
    )?;
    let got_ns = got_ns_.trim();
    let tun = "s_tun";
    log::info!("current ns {}", got_ns);

    if got_ns != ns_name {
        log::error!("entering netns failed, {} != {}", got_ns, ns_name);
        exit(1);
    }

    // as for now, the code above works, the new process is in the netns, checked on 4/24
    // get lo up and check netns
    log::debug!("get interface lo");
    let ns_config = config.netns_info.get(ns_name).unwrap();

    set_up("lo").await?;
    add_addrs_guest(ns_name, ns_config).await?;

    let mut ip_args = "tuntap add mode tun dev".split(' ').collect::<Vec<&str>>();
    ip_args.push(tun);
    let ss = Command::new("ip").args(ip_args).output().await?.status;
    match ss.code() {
        Some(e) => {
            log::warn!("tun add fail {}", e)
        }
        _ => {}
    }

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
            tun2.args(&["-device", tun, "-proxy", &base_prxy_v4]);
            let mut tun2_async: Command = tun2.into();
            tun2_async.stdout(Stdio::piped());
            let mut tun2h = tun2_async.spawn()?;
            let stdout = tun2h.stdout.take().unwrap();
            let reader = tokio::io::BufReader::new(stdout).lines();
            let (tx, rx) = tokio::sync::oneshot::channel();
            tokio::spawn(watch_log(reader, tx, "tun2socks"));
            rx.await?;
            set_up(tun).await?;
            set_up(&veth_from_ns(ns_name, false)).await?;
            ip_add_route(tun, None).await.ok();

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
            tun2.args(&["-device", tun, "-proxy", "127.0.0.1:1080"]);
            let mut tun2_async: Command = tun2.into();
            tun2_async.stdout(Stdio::piped());
            let mut tun2h = tun2_async.spawn()?;
            let stdout = tun2h.stdout.take().unwrap();
            let reader = tokio::io::BufReader::new(stdout).lines();
            let (tx, rx) = tokio::sync::oneshot::channel();
            tokio::spawn(watch_log(reader, tx, "clean_ip1_tun"));
            rx.await?;
            set_up(tun).await?;
            set_up(&veth_from_ns(ns_name, false)).await?;
            ip_add_route(tun, None).await.ok();
            ip_add_route6(tun, Some("::/0")).await.ok();
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
            tun2.args(&["-device", tun, "-proxy", "127.0.0.1:1080"]);
            let mut tun2_async: Command = tun2.into();
            tun2_async.stdout(Stdio::piped());
            let mut tun2h = tun2_async.spawn()?;
            let stdout = tun2h.stdout.take().unwrap();
            let reader = tokio::io::BufReader::new(stdout).lines();
            let (tx, rx) = tokio::sync::oneshot::channel();
            tokio::spawn(watch_log(reader, tx, "clean_ipv6_tun,"));
            rx.await?;
            set_up(tun).await?;
            set_up(&veth_from_ns(ns_name, false)).await?;
            ip_add_route(tun, None).await.ok();
            ip_add_route6(tun, Some("::/0")).await.ok();

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

pub async fn ip_add_route(dev: &str, mut dst: Option<&str>) -> Result<()> {
    if dst.is_none() {
        dst = Some("default");
    }
    let res = Command::new("ip")
        .args(["route", "add", dst.unwrap(), "dev", dev])
        .output()
        .await?
        .status;
    if res.success() {
        Ok(())
    } else {
        let r = anyhow!("adding route to {dev} fails");
        log::warn!("{r}");
        Err(r)
    }
}

pub async fn ip_add_route6(dev: &str, mut dst: Option<&str>) -> Result<()> {
    if dst.is_none() {
        dst = Some("default");
    }
    let res = Command::new("ip")
        .args(["-6", "route", "add", dst.unwrap(), "dev", dev])
        .output()
        .await?
        .status;
    if res.success() {
        Ok(())
    } else {
        let r = anyhow!("adding route to {dev} fails");
        log::warn!("{r}");
        Err(r)
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
    // log::trace!("change groups");
    // setgroups(&[gi])?;
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

pub async fn add_netns(ns_name: &str) -> Result<()> {
    let res = Command::new("ip")
        .args(["netns", "add", ns_name])
        .output()
        .await?
        .status;
    if res.success() {
        Ok(())
    } else {
        let r = anyhow!("adding {ns_name} fails");
        log::warn!("{r}");
        Err(r)
    }
}

pub async fn add_addrs_guest(ns_name: &str, info: &NetnsInfo) -> Result<()> {
    add_addr_dev(
        (info.ip_vn.clone() + "/16").as_ref(),
        veth_from_ns(&ns_name, false).as_ref(),
    )
    .await
    .ok();
    add_addr_dev(
        (info.ip6_vn.clone() + "/125").as_ref(),
        veth_from_ns(&ns_name, false).as_ref(),
    )
    .await
    .ok();

    Ok(())
}

// Trys to add an netns. If it exists, remove it.
// Get the NS up.
pub async fn config_ns(
    ns_name: &str,
    f: fn(&str, bool) -> String,
    config_res: &mut ConfigRes,
) -> Result<()> {
    // rtnetlink sucks. just use the command line
    let _ = add_netns(ns_name).await;
    let _ = add_veth_pair(ns_name).await;

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

    add_addr_dev(
        (info.ip_vh.clone() + "/16").as_ref(),
        f(&ns_name, true).as_ref(),
    )
    .await
    .ok();
    add_addr_dev(
        (info.ip6_vh.clone() + "/125").as_ref(),
        f(&ns_name, true).as_ref(),
    )
    .await
    .ok();
    let _ = set_up(&f(&ns_name, true)).await;

    add_addr_dev(
        (info.ip_vn.clone() + "/16").as_ref(),
        f(&ns_name, false).as_ref(),
    )
    .await
    .ok();
    add_addr_dev(
        (info.ip6_vn.clone() + "/125").as_ref(),
        f(&ns_name, false).as_ref(),
    )
    .await
    .ok();
    let _ = set_up(&f(&ns_name, true)).await;

    log::info!("veth subnet {subnet_veth}, {subnet6_veth}, host {ip_vh}, {ip6_vh}, guest {ip_vn}, {ip6_vn}");

    assert!(!ip_vh.is_global());
    assert!(!ip6_vh.is_global());
    ip_setns(ns_name, &f(ns_name, false)).await.ok();
    config_res.netns_info.insert(ns_name.to_owned(), info);
    // brilliant me, File::open(p)?.as_raw_fd() got the file closed before use, fixed it

    log::trace!("ns {ns_name} configured");
    Ok(())
}

pub async fn config_network() -> Result<ConfigRes> {
    let mut res = ConfigRes::default();

    // robust
    // 1. initial config state: add all configs
    // 2. half-configured state: some lines fail and the rest of config is resumed
    // 3. already configured: all lines fail
    // 4. other weird state, just reboot
    for ns in TASKS {
        config_ns(&ns, veth_from_ns, &mut res).await?;
    }

    res.root_inode = get_pid1_netns_inode().await?;

    Ok(res)
}

pub async fn get_pid1_netns_inode() -> Result<u64> {
    let netns_link = tokio::fs::read_link(Path::new("/proc/1/ns/net")).await?;
    let inode_str = netns_link
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .trim_start_matches("net:[");
    inode_str
        .trim_end_matches(']')
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("Failed to parse inode number as u64"))
}

pub async fn get_self_netns_inode() -> Result<u64> {
    let netns_link = tokio::fs::read_link(Path::new("/proc/self/ns/net")).await?;

    let inode_str = netns_link
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Failed to get file name from symlink target"))?
        .to_str()
        .unwrap()
        .trim_start_matches("net:[");

    inode_str
        .trim_end_matches(']')
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("Failed to parse inode number as u64"))
}

pub static TASKS: [&str; 5] = ["base_p", "i2p", "clean_ip1", "clean_ipv6", "lokins"];
