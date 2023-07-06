#![feature(ip)]
#![feature(async_closure)]
#![feature(async_fn_in_trait)]
#![feature(exit_status_error)]
#![feature(setgroups)]
#![feature(get_mut_unchecked)]
use anyhow::{bail, Result};
use futures::{AsyncRead, Future, SinkExt, StreamExt, TryFutureExt};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use tarpc::server::{BaseChannel, Channel};
use tarpc::tokio_util::codec::{self, LengthDelimitedCodec};
use tokio::io::BufStream;

use crate::*;

use anyhow::Ok;

use nix::unistd::{unlink, Gid, Pid, Uid};

use std::sync::Arc;
use std::{net::Ipv4Addr, os::fd::RawFd, path::PathBuf};
use std::{os::unix::process::CommandExt, process::Stdio};

use sysinfo::{self, ProcessExt, SystemExt};
use tokio::{
    self,
    io::{AsyncBufReadExt, AsyncReadExt},
    process::Command,
};

use crate::util::ns::*;
use data::*;
use util::substitute_argv;

use anyhow::anyhow;
use tarpc::tokio_serde::formats::{Bincode, SymmetricalBincode};
use tarpc::{context, serde_transport};
use dashmap::DashMap;

// more invariant, the better
// traits are invariant
// in any case, we are asking the machine to prove properties of code, like typing.
pub trait NetnspSub {
    async fn config_in_ns_up(&self, fd: RawFd, link_base_name: String, ip: IpNetwork)
        -> Result<()>;
    async fn remove_vethb_in_ns(&self, fd: RawFd, veth_base_name: String) -> Result<()>;
    async fn inner_daemon(
        &self,
        profile: String,
        uid: Uid,
        gid: Gid,
        fd: RawFd,
        pid: Option<Pid>, // for non-persistent netns
    ) -> Result<()>;
    async fn with_ipc(&self, sname: String) -> Result<()>;
}

use tarpc::{client, server};

#[tarpc::service]
pub trait NsubService {
    async fn id() -> RawFd;
    async fn remove_link(k: LinkKey) -> bool;
    async fn p() ;
}

#[derive(Clone)]
struct NsubRPC;

#[tarpc::server]
impl NsubService for NsubRPC {
    async fn id(self, _: tarpc::context::Context) -> RawFd {
        2.into()
    }
    async fn remove_link(self, _: tarpc::context::Context, k: LinkKey) -> bool {
        true
    }
}

pub struct NetnspSubImpl;

pub struct NetnspSubCaller {
    sock_path: PathBuf,
    subs: Arc<DashMap<RawFd, NsubServiceClient>>
}

impl NetnspSubCaller {
    /// only need one per program
    async fn init() -> Result<Self> {
        // TODO: security
        let sock_path: PathBuf = "./netnsp.sock".into();
        if sock_path.exists() {
            unlink(sock_path.as_path())?;
        }
        let subs = Arc::new(DashMap::new());
        let mut sock = serde_transport::unix::listen(sock_path.as_path(), Bincode::default).await?;
        let sub_m = subs.clone();
        tokio::spawn(async move {
            while let Some(s) = sock.next().await {
                let s: _ = s?;
                let c = NsubServiceClient::new(Default::default(), s).spawn();
                // the peer_addr is unnamed, so it must self identify.
                let fd = c.id(context::current()).await?;
                sub_m.insert(fd.into(), c);
            }
            Ok(())
        });
        Ok(Self {
            sock_path,
            subs,
        })
    }
    /// start a new sub
    /// new sub for each ns
    async fn new_sub(&mut self, fd: RawFd) -> Result<()> {
        let mut cmd = Command::new(std::env::current_exe()?)
            .arg(self.sock_path.as_path())
            .arg(fd.to_string())
            .uid(0) // run it as root
            .spawn()
            .unwrap();

        let task = cmd.wait();
        task.await?;

        Ok(())
    }
}


impl NetnspSub for NetnspSubImpl {
    /// veth_b is removed from ns
    async fn remove_vethb_in_ns(&self, fd: RawFd, veth_base_name: String) -> Result<()> {
        enter_ns_by_fd(fd)?;
        let configurer = NetlinkConn::new();
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
    async fn config_in_ns_up(
        &self,
        fd: RawFd,
        link_base_name: String,
        ip: IpNetwork,
    ) -> Result<()> {
        log::trace!("set ns->ns link up in target ns and add ip");
        enter_ns_by_fd(fd)?;
        let configurer = NetlinkConn::new();
        let rh = configurer
            .get_link(&veth_from_base(&link_base_name, false))
            .await;
        let rh = rh?;
        let ipn: IpNetwork = ip;
        let add = configurer
            .handle
            .address()
            .add(rh.header.index, ipn.ip(), ipn.prefix())
            .execute()
            .await;
        if add.is_err() {
            // should be ok
            log::info!("add addr to target ns, {:?}", add.unwrap_err())
        }
        configurer
            .handle
            .link()
            .set(rh.header.index)
            .up()
            .execute()
            .await?;
        Ok(())
    }
    async fn inner_daemon(
        &self,
        profile: String,
        uid: Uid,
        gid: Gid,
        fd: RawFd,
        pid: Option<Pid>, // for non-persistent netns
    ) -> Result<()> {
        use tidy_tuntap::{flags, Tun};
        // enters the netns
        // add addrs to the veth
        // makes a tun
        // runs daemons

        let state = NetnspState::load(Default::default()).await?;

        let config: ConfigRes = state.res;
        let secret: Secret = state.conf;

        log::info!("netns-proxy of profile {profile}, sub-process started");

        // get into a process' netns
        enter_ns_by_fd(fd)?;

        let tun_name = "s_tun";

        let netconf = if pid.is_none() {
            log::trace!("pid not supplied for netnsp-sub");
            config.namedns.get(&profile).unwrap()
        } else {
            // assumption: PIDs in the config do not collide
            // which stands if we run it from the same PID namespace all along
            config.try_get_netinfo(pid.as_ref().unwrap().as_raw())?
        };

        let configurer = NetlinkConn::new();

        configurer.set_up("lo").await?;
        configurer
            .add_addrs_guest(&netconf.veth_base_name, netconf)
            .await?;

        // config ns to ns links
        if let Some(lname) = &netconf.link_base_name {
            // ip of self ns
            let self_ip = Ipv4Addr::new(10, 28, netconf.id.try_into().unwrap(), 1);
            // ip of other ns
            // let host_ip = Ipv4Addr::new(10, 28, netconf.id.try_into().unwrap(), 2);
            let devname = veth_from_base(&lname, true);
            let devget = configurer.get_link(&devname).await;
            if devget.is_err() {
                anyhow::bail!("interface {} missing", devname);
            }
            configurer
                .add_addr_dev(IpNetwork::new(self_ip.into(), 24)?, &devname.as_ref())
                .await?;
            configurer.set_up(&devname.as_ref()).await?;
        }

        let params: &NetnsParams = &secret.params[&profile];
        let mut proc_set = tokio::task::JoinSet::new();
        let ip_vh: IpNetwork = netconf.ip_vh.parse()?;
        let ip_vh_ip = ip_vh.ip().to_string();
        let r_ui: u32;
        let r_gi: u32;
        use util::perms::get_non_priv_user;
        (r_ui, r_gi) = get_non_priv_user(None, None, Some(uid), Some(gid))?;

        // the uid and gid for non-privileged processes
        let gi = Gid::from_raw(r_gi);
        let ui = Uid::from_raw(r_ui);

        if params.tun2socks.unwrap_or(true) {
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

            assert!(!ui.is_root());
            assert!(gi.as_raw() != 0);
            log::debug!("unprileged processes will be run with, gid {gi}, uid {ui}");

            let tun_target_port = params.tunport.unwrap_or(9909);
            let base_prxy_v4;
            if params.chain {
                base_prxy_v4 = format!(
                    "socks5://{}:{}",
                    netconf.tun_ip.as_ref().unwrap_or(&"127.0.0.1".to_string()),
                    tun_target_port
                )
            } else {
                base_prxy_v4 = format!("socks5://{}:{}", &ip_vh_ip, tun_target_port);
            }

            // Tun2socks
            let mut tun2 = std::process::Command::new("tun2socks");
            tun2.uid(ui.into()).gid(gi.into()).groups(&[gi.into()]);
            tun2.args(&[
                "-device",
                tun_name,
                "-proxy",
                &base_prxy_v4,
                "-loglevel",
                "warning", // TODO: tun2 log level
            ]);
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
        }

        if params.dnsproxy.unwrap_or(true) {
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
            watch_both(&mut dnsh, pre, None)?;
            proc_set.spawn((async move || {
                dnsh.wait()
                    .map_err(|e| anyhow::Error::from(e))
                    .map_ok(|o| (o, "dnsproxy".to_owned()))
                    .await
            })());
        }

        if let Some(cmd) = &params.su_cmd {
            let mut uproc = std::process::Command::new(&cmd.program);
            let mut cmd_c: NetnsParamCmd = cmd.to_owned();
            substitute_argv(&netconf, &mut cmd_c.argv);

            uproc.uid(0).gid(0);
            uproc.args(&cmd_c.argv);
            let mut uproc_async: Command = uproc.into();
            uproc_async.stdout(Stdio::piped());
            uproc_async.stderr(Stdio::piped());
            let mut uproch = uproc_async.spawn()?;
            let pre = format!("{}/su_cmd", &netconf.base_name);
            watch_both(&mut uproch, pre, None)?;

            proc_set.spawn((async move || {
                uproch
                    .wait()
                    .map_err(|e| anyhow::Error::from(e))
                    .map_ok(|o| (o, format!("{}, argv {:?}", cmd_c.program, cmd_c.argv)))
                    .await
            })());
        }

        // User-supplied process
        if let Some(cmd) = &params.cmd {
            let mut uproc = std::process::Command::new(&cmd.program);
            let mut cmd_c: NetnsParamCmd = cmd.to_owned();
            substitute_argv(&netconf, &mut cmd_c.argv);

            uproc.uid(ui.into()).gid(gi.into()).groups(&[gi.into()]);
            if let Some(uname) = &cmd.user {
                let u = users::get_user_by_name(uname).unwrap();
                uproc.uid(u.uid());
            }

            uproc.args(&cmd_c.argv);
            let mut uproc_async: Command = uproc.into();
            uproc_async.stdout(Stdio::piped());
            uproc_async.stderr(Stdio::piped());
            let mut uproch = uproc_async.spawn()?;
            let pre = format!("{}/cmd", &netconf.base_name);
            watch_both(&mut uproch, pre, None)?;

            proc_set.spawn((async move || {
                uproch
                    .wait()
                    .map_err(|e| anyhow::Error::from(e))
                    .map_ok(|o| (o, format!("{}, argv {:?}", cmd_c.program, cmd_c.argv)))
                    .await
            })());
        }

        if let Some(ep) = params.expose_port {
            // let pre = netconf.base_name.clone();
            // proc_set.spawn(async move {
            //     log::info!("{} / tcp proxy listening on {}, redirecting to 127.1:{}", pre, ep + 1, ep);
            //     tcproxy::start_proxy(ep)
            //         .await
            //         .map(|_| (ExitStatus::from_raw(0), "tcp proxy".to_owned()))
            // });

            // the code above does not work, for unknown reasons
            // and I don't want to spend more hours on this blend of async, system, stochastic programming

            // I think my firewall made it not work.

            let mut path = std::env::current_exe()?;
            path.pop();
            path.push("tproxy");

            let mut cmd: tokio::process::Child = tokio::process::Command::new(path.clone())
                .arg(ep.to_string())
                .uid(ui.into())
                .gid(gi.into())
                .spawn()
                .unwrap();
            cmd.wait().await?;
        }

        while let Some(r) = proc_set.join_next().await {
            let r = r??;
            log::warn!(
                "\"{}\" exited with {}, for {}",
                r.1,
                r.0,
                &netconf.base_name
            )
        }
        Ok(())
    }
}
