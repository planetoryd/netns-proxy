use std::collections::BTreeMap;
use std::env;
use std::fmt::Debug;
use std::fs::File;
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Ok;
use anyhow::Result;
use futures::Future;
use futures::StreamExt;
use futures::{FutureExt, TryFutureExt};

use nix::sys::signal::kill;
use nix::sys::signal::Signal;
use nix::sys::signal::Signal::SIGTERM;
use nix::unistd::{Gid, Pid, Uid};
use pidfd::{PidFd, PidFuture};
use procfs::process::Process;

use netlink_ops::netns::Pid as DPid;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use tokio::io::BufStream;
use tokio::{
    signal::unix::SignalKind,
    sync::{
        mpsc::{self, unbounded_channel, UnboundedReceiver, UnboundedSender},
        oneshot::{self, Receiver},
        Mutex,
    },
    task::{AbortHandle, JoinError, JoinHandle, JoinSet},
};

use nix::unistd::setgroups;

use std::collections::HashMap;

use std::{ffi::CString, os::unix::process::CommandExt, path::Path, process::exit};
use tokio::{
    self,
    io::{AsyncBufReadExt, AsyncReadExt},
};

use std::cmp::Eq;
use std::hash::Hash;

/// get v in mb with key from ma
pub fn hashmap_chain<'a, A, B, C>(
    ma: &'a HashMap<A, B>,
    mb: &'a HashMap<B, C>,
    k_in_ma: &'a A,
) -> Option<&'a C>
where
    A: Eq + Hash,
    B: Eq + Hash,
    C: Eq + Hash,
{
    ma.get(k_in_ma).and_then(|r| mb.get(r))
}

/// get v in mb with key from ma
pub fn hashmap_chain_mut<'a, A, B, C>(
    ma: &'a mut HashMap<A, B>,
    mb: &'a mut HashMap<B, C>,
    k_in_ma: &'a A,
) -> Option<&'a mut C>
where
    A: Eq + Hash,
    B: Eq + Hash,
    C: Eq + Hash,
{
    ma.get_mut(k_in_ma).and_then(|r| mb.get_mut(r))
}

pub fn btreemap_chain_mut<'a, A, B, C>(
    ma: &'a mut BTreeMap<A, B>,
    mb: &'a mut BTreeMap<B, C>,
    k_in_ma: &'a A,
) -> Option<&'a mut C>
where
    A: Ord,
    B: Ord,
    C: Ord,
{
    ma.get_mut(k_in_ma).and_then(|r| mb.get_mut(r))
}

pub async fn watch_log<S: futures::Stream<Item = std::io::Result<String>> + Send>(
    mut reader: Pin<Box<S>>,
    tx: Option<tokio::sync::oneshot::Sender<bool>>,
    prefix: String,
) -> Result<()> {
    if let Some(line) = reader.next().await {
        let line = line?;
        log::debug!("{} {}", prefix, line);
        if let Some(t) = tx {
            t.send(true).unwrap();
        }
    }
    while let Some(line) = reader.next().await {
        let line = line?;
        log::debug!("{} {}", prefix, line);
    }
    Ok(())
}

pub fn watch_both(
    chil: &mut tokio::process::Child,
    pre: String,
    tx: Option<tokio::sync::oneshot::Sender<bool>>,
) -> Result<()> {
    use tokio::io::BufReader;
    use tokio_stream::wrappers::LinesStream;
    let stdout = chil.stdout.take().unwrap();
    let stderr = chil.stderr.take().unwrap();

    let reader = LinesStream::new(BufReader::new(stdout).lines());
    let reader_err = LinesStream::new(BufReader::new(stderr).lines());
    let s = futures::stream_select!(reader, reader_err);
    tokio::spawn(watch_log(Box::pin(s), tx, pre.clone()));

    Ok(())
}

pub mod perms {
    use super::*;
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

    pub fn drop_privs_id(gi: Gid, ui: Uid) -> Result<()> {
        log::trace!("groups, {:?}", nix::unistd::getgroups()?);
        log::trace!("GID to {gi}");
        nix::unistd::setresgid(gi, gi, gi)?;
        let user = nix::unistd::User::from_uid(ui).unwrap().unwrap();
        set_initgroups(&user, gi.as_raw());
        log::trace!("UID to {ui}");
        nix::unistd::setresuid(ui, ui, ui)?;
        log::info!("Dropped privileges to resuid={ui} resgid={gi}");
        Ok(())
    }

    pub fn get_non_priv_user(
        uid: Option<String>,
        gid: Option<String>,
        uid2: Option<Uid>,
        gid2: Option<Gid>,
    ) -> Result<(u32, u32)> {
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
        } else if uid2.is_some() && gid2.is_some() {
            r_gi = gid2.unwrap().as_raw();
            r_ui = uid2.unwrap().as_raw();
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

        if r_ui == 0 || r_gi == 0 {
            // when straceing
            Ok((1000, 1000))
        } else {
            Ok((r_ui, r_gi))
        }
    }
}

pub fn kill_children(pid: i32) -> Result<()> {
    let su = Process::new(pid)?;
    let chi: Vec<u32> = su
        .tasks()?
        .filter_map(|t| t.ok().and_then(|x| x.children().ok()))
        .flatten()
        .collect();

    for c in chi {
        kill(Pid::from_raw(c.try_into()?), Signal::SIGTERM).map_err(anyhow::Error::from)?;
    }

    Ok(())
}

#[cfg(not(test))]
use log::info;
use sysinfo::PidExt;
use sysinfo::ProcessExt;
use sysinfo::SystemExt;

#[cfg(test)]
use std::println as info;

use sysinfo::System;

pub fn kill_suspected() -> Result<()> {
    let s = System::new_all();
    for (pid, process) in s.processes() {
        // kill by saved pids
        // or by matching commandlines
        let c = process.cmd();
        if c.into_iter().any(|x| x.contains("tun2socks"))
            || c.into_iter().any(|x| x.contains("dnsproxy"))
        {
            println!("killed {pid} {}", c[0]);
            kill(nix::unistd::Pid::from_raw(pid.as_u32() as i32), SIGTERM)?;
        }
    }
    Ok(())
}

pub mod ns {
    pub const NETNS_PATH: &str = "/run/netns/";
    use futures::TryFutureExt;

    use anyhow::{anyhow, Ok, Result};
    use netns_rs::NetNs;
    use nix::sched::CloneFlags;

    use std::os::fd::AsRawFd;
    use std::{
        ffi::OsString,
        os::fd::RawFd,
        path::{Path, PathBuf},
    };
    use tokio::{self, fs::File};

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

    pub async fn get_pid1_netns_inode() -> Result<u64> {
        use procfs::process::Process;
        let pid1_process = Process::new(1)?;
        let nslist = pid1_process.namespaces()?;
        let pid1_net_ns = nslist
            .get(&OsString::from("net"))
            .ok_or_else(|| anyhow::anyhow!("PID 1 net namespace not found"))?;

        Ok(pid1_net_ns.identifier)
    }

    // alternatively it can be done without deps, in a few lines.
    // TODO: would it be overoptimization to optimize this ? procfs is wasting syscalls.
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
}

pub fn wait_pid(x: DPid) -> Option<PidFuture> {
    if let Result::Ok(f) = unsafe { PidFd::open(x.0 as i32, 0) } {
        unsafe {
            let _ = f.send_raw_signal(libc::SIGINT, std::ptr::null(), 0);
        };
        Some(f.into_future())
    } else {
        None
    }
}

/// Remotely aborts a future
pub struct AbortOnDrop(pub AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort()
    }
}

impl From<AbortHandle> for AbortOnDrop {
    fn from(value: AbortHandle) -> Self {
        Self(value)
    }
}

#[derive(Debug)]
pub struct AbortOnDropTokio<T>(pub JoinHandle<T>);

impl<T> Future for AbortOnDropTokio<T> {
    type Output = std::result::Result<T, JoinError>;
    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        unsafe { self.map_unchecked_mut(|s| &mut s.0) }.poll(cx)
    }
}

impl<T> Drop for AbortOnDropTokio<T> {
    fn drop(&mut self) {
        self.0.abort()
    }
}

impl<T> From<JoinHandle<T>> for AbortOnDropTokio<T> {
    fn from(value: JoinHandle<T>) -> Self {
        Self(value)
    }
}

impl<T> AbortOnDropTokio<T> {
    pub fn handle(&self) -> AbortHandle {
        self.0.abort_handle()
    }
}

#[tokio::test]
async fn test_aod() {
    let h = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        println!("3");
    });

    let h2 = tokio::spawn(async move { h.await });
    h2.abort(); // Aboring h2, dropping h, doesn't abort h.

    println!("--");

    let h: AbortOnDropTokio<()> = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        println!("3");
    })
    .into();

    let h2 = tokio::spawn(async move { h.await });
    h2.abort(); // This also aborts h

    tokio::time::sleep(Duration::from_secs(5)).await;

    // should output -- 3
}

pub fn to_vec_internal<T: serde::Serialize>(x: &T) -> Result<Vec<u8>> {
    let v = ron::to_string(x)?.into_bytes();
    Ok(v)
}

pub fn from_vec_internal<'a, T: for<'b> serde::Deserialize<'b>>(b: &'a [u8]) -> Result<T> {
    let k = ron::from_str(&String::from_utf8_lossy(b))?;
    Ok(k)
}

#[derive(Error, Debug)]
#[error("sender or receiver failure")]
pub struct ChannelFailure;