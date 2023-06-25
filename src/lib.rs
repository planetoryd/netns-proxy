#![feature(ip)]
#![feature(async_closure)]
#![feature(exit_status_error)]
#![feature(setgroups)]
#![feature(get_mut_unchecked)]
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
pub mod configurer;
mod nft;
pub mod util;
pub mod watcher;

use configurer::*;


// Standard procedure
// Creates various netns, base-vpn, socks, i2p, lokinet, un-firewalled
// Kill other running processes, suspected
// Fork, setns, drop privs, start daemons
pub static mut logger: Option<flexi_logger::LoggerHandle> = None;

pub fn substitute_argv<'a>(n_info: &'a NetnsInfo, argv: &mut Vec<String>) {
    let mut sub_map: HashMap<String, &String> = HashMap::new();
    sub_map.insert(format!("${}", "subnet_veth"), &n_info.subnet_veth);
    sub_map.insert(format!("${}", "subnet6_veth"), &n_info.subnet6_veth);
    sub_map.insert(format!("${}", "ip_vh"), &n_info.ip_vh);
    sub_map.insert(format!("${}", "ip6_vh"), &n_info.ip6_vh);
    sub_map.insert(format!("${}", "ip_vn"), &n_info.ip_vn);
    sub_map.insert(format!("${}", "ip6_vn"), &n_info.ip6_vn);

    for s in argv.iter_mut() {
        let mut s_ = s.to_owned();
        for (key, value) in &sub_map {
            s_ = s_.replace(key, value);
        }
        *s = s_;
    }
}

#[test]
fn test_substitute_argv() {
    let n_info = NetnsInfo {
        base_name: "x".to_owned(),
        subnet_veth: "eth0".to_string(),
        subnet6_veth: "eth1".to_string(),
        ip_vh: "192.168.0.1".to_string(),
        ip6_vh: "2001:db8::1".to_string(),
        ip_vn: "192.168.0.2".to_string(),
        ip6_vn: "2001:db8::2".to_string(),
        veth_base_name: "ss".to_owned(),
        id: 2
    };

    let mut argv = vec![
        "ping".to_string(),
        "-c".to_string(),
        "1".to_string(),
        "$ip_vnxx".to_string(),
    ];

    substitute_argv(&n_info, &mut argv);

    assert_eq!(
        argv,
        vec![
            "ping".to_string(),
            "-c".to_string(),
            "1".to_string(),
            "192.168.0.2xx".to_string(),
        ]
    );
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

// first four args must be Some()
pub async fn inner_daemon(
    profile: Option<String>,
    uid: Option<String>,
    gid: Option<String>,
    fd: Option<String>,
    pid: Option<String>, // for non-persistent netns
) -> Result<()> {
    let mut tun_target_port = 9909;
    use tidy_tuntap::{flags, Tun};
    // enters the netns
    // add addrs to the veth
    // makes a tun
    // runs daemons

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

    let profile = profile.unwrap();
    let fd = fd.unwrap().parse()?;

    let mut state = NetnspState::load(Default::default()).await?;

    let config: ConfigRes = state.res;
    let secret: Secret = state.conf;

    log::info!("netns-proxy of profile {profile}, sub-process started");

    // get into a process' netns
    enter_ns_by_fd(fd)?;

    let tun_name = "s_tun";

    let netconf = if pid.is_none() {
        log::trace!("pid not supplied for netnsp-sub");
        config.netns_info.get(&profile).unwrap()
    } else {
        // assumption: PIDs in the config do not collide
        // which stands if we run it from the same PID namespace all along
        config.try_get_netinfo(pid.as_ref().unwrap().parse()?)?
    };

    let configurer = Configurer::new();

    configurer.set_up("lo").await?;
    configurer.add_addrs_guest(&netconf.veth_base_name, netconf).await?;

    let tun = Tun::new(tun_name, false)?; // prepare a TUN for tun2socks, as root.
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

    let r_ui: u32;
    let r_gi: u32;
    use util::get_non_priv_user;
    (r_ui, r_gi) = get_non_priv_user(uid, gid)?;

    // the uid and gid for non-privileged processes
    let gi = Gid::from_raw(r_gi);
    let ui = Uid::from_raw(r_ui);

    assert!(!ui.is_root());
    assert!(gi.as_raw() != 0);
    log::debug!("unprileged processes will be run with, gid {gi}, uid {ui}");

    let params = &secret.params[&profile];
    if let Some(tp) = params.hport {
        tun_target_port = tp;
    }
    let mut proc_set = tokio::task::JoinSet::new();
    let ip_vh: IpNetwork = netconf.ip_vh.parse()?;
    let ip_vh_ip = ip_vh.ip().to_string() ;
    let mut base_prxy_v4 =
        "socks5://".to_owned() + &ip_vh_ip + ":" + &tun_target_port.to_string();
    if params.hport.is_some() {
        base_prxy_v4 = format!("socks5://{}:{}", &ip_vh_ip, params.hport.unwrap());
    }
    if params.chain {
        // so, this takes precedence
        base_prxy_v4 = format!("socks5://127.0.0.1:1080")
    }

    // Tun2socks
    let mut tun2 = std::process::Command::new("tun2socks");
    tun2.uid(ui.into()).gid(gi.into()).groups(&[gi.into()]);
    tun2.args(&["-device", tun_name, "-proxy", &base_prxy_v4]);
    let mut tun2_async: Command = tun2.into();
    tun2_async.stdout(Stdio::piped());
    let mut tun2h = tun2_async.spawn()?;
    let stdout = tun2h.stdout.take().unwrap();
    let reader = tokio::io::BufReader::new(stdout).lines();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let pre = format!("{}/tun2socks", netconf.base_name);
    tokio::spawn(watch_log(reader, Some(tx), pre));
    rx.await?;
    configurer.set_up(tun_name).await?;
    let vn = &veth_from_base(&netconf.veth_base_name, false);
    configurer.set_up(&vn).await?;
    configurer
        .ip_add_route(tun_name, None, Some(true))
        .await
        .ok();
    configurer
        .ip_add_route(tun_name, None, Some(false))
        .await
        .ok();
    proc_set.spawn((async move || {
        tun2h
            .wait()
            .map_err(|e| anyhow::Error::from(e))
            .map_ok(|o| (o, "tun2socks".to_owned()))
            .await
    })());

    // Dnsproxy
    let mut dns = std::process::Command::new("dnsproxy");
    dns.uid(ui.into()).gid(gi.into()).groups(&[gi.into()]);

    if let Some(dv) = &params.dns_argv {
        dns.args(dv);
    } else {
        // dnsproxy is behind the proxy
        // DNSSEC or such is unnecessary.
        if params.ipv6 {
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
        } else {
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
        }
    }
    let mut dns_async: Command = dns.into();
    dns_async.stdout(Stdio::piped());
    dns_async.stderr(Stdio::piped());
    let mut dnsh = dns_async.spawn()?;
    let pre = format!("{}/dnsproxy", &netconf.base_name);
    watch_both(&mut dnsh, pre, None).await?;
    proc_set.spawn((async move || {
        dnsh.wait()
            .map_err(|e| anyhow::Error::from(e))
            .map_ok(|o| (o, "dnsproxy".to_owned()))
            .await
    })());

    // User-supplied process
    if let Some(cmd) = &params.cmd {
        let mut uproc = std::process::Command::new(&cmd.program);
        let mut cmd_c: NetnsParamCmd = cmd.to_owned();
        substitute_argv(&netconf, &mut cmd_c.argv);

        uproc.uid(ui.into()).gid(gi.into()).groups(&[gi.into()]);
        uproc.args(&cmd_c.argv);
        let mut uproc_async: Command = uproc.into();
        uproc_async.stdout(Stdio::piped());
        uproc_async.stderr(Stdio::piped());
        let mut uproch = uproc_async.spawn()?;
        let pre = format!("{}/cmd", &netconf.base_name);
        watch_both(&mut uproch, pre, None).await?;

        proc_set.spawn((async move || {
            uproch
                .wait()
                .map_err(|e| anyhow::Error::from(e))
                .map_ok(|o| (o, format!("{}, argv {:?}", cmd_c.program, cmd_c.argv)))
                .await
        })());
    }

    while let Some(r) = proc_set.join_next().await {
        let r = r??;
        log::warn!("\"{}\" exited with {}, for {}", r.1, r.0, &netconf.base_name)
    }

    Ok(())
}
