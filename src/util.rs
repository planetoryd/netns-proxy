use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::ExitStatus;

use anyhow::Ok;
use anyhow::Result;
use futures::Future;
use futures::{FutureExt, TryFutureExt};
use ipnetwork::IpNetwork;
use nix::sys::signal::kill;
use nix::sys::signal::Signal;
use nix::sys::signal::Signal::SIGTERM;
use nix::unistd::Gid;
use nix::unistd::Pid;
use nix::unistd::Uid;
use procfs::process::Process;
use serde::Deserialize;
use serde::Serialize;
use tarpc::client::RpcError;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Receiver;
use tokio::task::JoinSet;

use crate::data::FlatpakID;
use crate::data::*;
use crate::{
    nft::FO_CHAIN,
    sub::{NetnspSubCaller, NetnspSubImpl},
};
use anyhow::anyhow;
use netns_rs::NetNs;
use nix::{sched::CloneFlags, unistd::setgroups};

use std::{collections::HashSet, net::Ipv6Addr};

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::{
    ffi::{CString, OsString},
    net::Ipv4Addr,
    os::{fd::RawFd, unix::process::CommandExt},
    path::Path,
    process::exit,
};
use tokio::{
    self,
    io::{AsyncBufReadExt, AsyncReadExt},
};

use std::cmp::Eq;
use std::hash::Hash;

pub fn convert_strings_to_strs(strings: &Vec<String>) -> Vec<&str> {
    strings.iter().map(|s| s.as_str()).collect()
}

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

pub async fn watch_log(
    mut reader: tokio::io::Lines<tokio::io::BufReader<impl tokio::io::AsyncRead + Unpin>>,
    tx: Option<tokio::sync::oneshot::Sender<bool>>,
    prefix: String,
) -> Result<()> {
    if let Some(line) = reader.next_line().await? {
        log::info!("{} {}", prefix, line);
        if let Some(t) = tx {
            t.send(true);
        }
    }
    while let Some(line) = reader.next_line().await? {
        log::info!("{} {}", prefix, line);
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
    let reader_err = tokio::io::BufReader::new(stderr).lines();
    tokio::spawn(watch_log(reader, tx, pre.clone()));
    tokio::spawn(watch_log(reader_err, None, pre));

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

        log::info!("dropped privs to resuid={ui} resgid={gi}");

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

#[test]
fn t_pidfd() -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let f = unsafe { pidfd::PidFd::open(853481, 0)?.into_future() };
            println!("opened");
            f.await?;
            println!("finished");
            Ok(())
        })
}

#[test]
fn get_all_child_pids() -> Result<()> {
    use procfs::process::Process;

    let su = Process::new(942129)?;
    let mt = su.task_main_thread()?;
    dbg!(mt.children()?);
    let chi: Vec<u32> = su
        .tasks()?
        .filter_map(|t| t.ok().and_then(|x| x.children().ok()))
        .flatten()
        .collect();

    dbg!(chi);
    Ok(())
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

pub fn flatpak_perms_checkup(list: Vec<FlatpakID>) -> Result<()> {
    let basedirs = xdg::BaseDirectories::with_prefix("flatpak")?;
    info!("trying to adapt flatpak app permissions");
    for appid in list {
        let mut sub = PathBuf::from("overrides");
        sub.push(appid.0);
        let p = basedirs.get_data_file(&sub);
        if p.exists() {
            let mut conf = ini::Ini::load_from_file(p.as_path())?;
            let k = conf.get_from(Some("Context"), "shared");
            if k.is_some() {
                if k.unwrap().contains("!network") {
                    info!("{} found. it has correct config", p.to_string_lossy());
                } else {
                    let o = k.unwrap().to_owned();
                    let v = o + ";!network";
                    conf.set_to(Some("Context"), "shared".to_owned(), v);
                    conf.write_to_file(p.as_path())?;
                    info!("{} written", p.to_string_lossy());
                }
            } else {
                conf.set_to(Some("Context"), "shared".to_owned(), "!network".to_owned());
                conf.write_to_file(p.as_path())?;
                info!("{} written", p.to_string_lossy());
            }
        } else {
            // create a new file for it
            let mut conf = ini::Ini::new();
            conf.set_to(Some("Context"), "shared".to_owned(), "!network".to_owned());
            info!("{} written. new file", p.to_string_lossy());
            conf.write_to_file(p.as_path())?;
        }
    }
    Ok(())
}

#[test]
fn test_flatpakperm() -> Result<()> {
    flatpak_perms_checkup(
        [
            "org.mozilla.firefox".parse()?,
            "im.fluffychat.Fluffychat".parse()?,
        ]
        .to_vec(),
    )
    .unwrap();
    Ok(())
}

use crate::data::SubjectInfo;

use sysinfo::System;

pub fn kill_suspected() -> Result<()> {
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
            kill(nix::unistd::Pid::from_raw(pid.as_u32() as i32), SIGTERM)?;
        }
    }
    Ok(())
}

pub fn open_wo_cloexec(path: &Path) -> Result<tokio::fs::File> {
    use nix::fcntl::{open, OFlag};
    use nix::sys::stat::Mode;
    let fd = open(path, OFlag::O_RDONLY, Mode::empty())?;
    let syncf = unsafe { File::from_raw_fd(fd) };

    Ok(syncf.into())
}

pub mod ns {
    pub const NETNS_PATH: &str = "/run/netns/";
    use futures::{FutureExt, TryFutureExt};
    use ipnetwork::IpNetwork;
    use tokio::io::AsyncWriteExt;

    use crate::{
        data::ProfileName,
        nft::FO_CHAIN,
        sub::{NetnspSubCaller, NetnspSubImpl},
    };

    use anyhow::{anyhow, Ok, Result};
    use netns_rs::NetNs;
    use nix::{
        sched::CloneFlags,
        unistd::{setgroups, Gid, Uid},
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

    pub trait ValidNamedNS: AsRef<Path> {}
    impl ValidNamedNS for ProfileName {}

    impl AsRef<Path> for ProfileName {
        fn as_ref(&self) -> &Path {
            Path::new(&self.0)
        }
    }

    pub fn named_ns<N: ValidNamedNS>(ns_name: &N) -> Result<File> {
        let mut p = PathBuf::from(NETNS_PATH);
        p.push(&ns_name);
        open_wo_cloexec(p.as_path())
    }

    pub fn named_ns_exist<N: ValidNamedNS>(ns_name: &N) -> Result<bool> {
        let mut p = PathBuf::from(NETNS_PATH);
        p.push(ns_name);
        let r = p.try_exists().map_err(anyhow::Error::from)?;
        if r {
            // file exists but not a file. should error
            anyhow::ensure!(p.is_file());
        }
        Ok(r)
    }

    pub async fn enter_ns_by_name<N: ValidNamedNS>(ns_name: &N) -> Result<()> {
        let fd = named_ns(ns_name)?;
        nix::sched::setns(fd.as_raw_fd(), CloneFlags::CLONE_NEWNET)?;
        let got_ns = self_netns_identify().await?.ok_or_else(|| {
            anyhow::anyhow!("failed to identify netns. no matches under the given netns directory")
        })?;
        let g_ns = Path::new(&got_ns.0);
        anyhow::ensure!(g_ns == ns_name.as_ref());
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

    /// file opened w/o cloexec
    pub fn get_ns_by_pid(pi: i32) -> Result<File> {
        let process = procfs::process::Process::new(pi)?;
        let o: OsString = OsString::from("net");
        let nss = process.namespaces()?;
        let proc_ns = nss
            .get(&o)
            .ok_or(anyhow!("ns/net not found for given pid"))?;
        let r = open_wo_cloexec(&proc_ns.path)?;
        Ok(r)
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
    /// unchecked
    pub async fn add_netns<N: ValidNamedNS>(ns_name: &N) -> Result<()> {
        use rtnetlink::NetworkNamespace;
        NetworkNamespace::add(ns_name.as_ref().to_string_lossy().into_owned())
            .await
            .map_err(anyhow::Error::from)
    }
    use netns_rs::Env;

    use super::open_wo_cloexec;

    pub struct NsEnv;

    impl Env for NsEnv {
        fn persist_dir(&self) -> PathBuf {
            NETNS_PATH.into()
        }
    }
}

pub mod error {
    use serde::{Deserialize, Serialize};
    use thiserror::Error;

    #[derive(Error, Debug)]
    #[error("Deviance from a configuration plan")]
    pub struct DevianceError;

    #[derive(Error, Debug)]
    #[error("Something is missing, and it can be handled")]
    pub struct MissingError;

    use serde_error::Error as SError;

    pub fn se_ok() -> Result<(), SError> {
        Result::Ok(())
    }
}

/// A place to keep all daemons
pub struct Daemons {
    pub sender: DaemonSender,
    recver: UnboundedReceiver<Pin<Box<dyn Future<Output = TaskOutput> + Send>>>,
    daemons: JoinSet<TaskOutput>,
}

pub type DaemonSender = UnboundedSender<Pin<Box<dyn Future<Output = TaskOutput> + Send>>>;

pub struct TaskOutput {
    pub name: String,
    pub result: Result<()>,
    /// notified in case the task stops
    pub sig: Option<oneshot::Sender<()>>,
}

use serde_error::Error as SErr;

impl TaskOutput {
    pub fn new(
        f: Pin<Box<dyn Future<Output = Result<()>> + Send>>,
        name: String,
    ) -> (
        Pin<Box<dyn Future<Output = TaskOutput> + Send>>,
        Receiver<()>,
    ) {
        let (sx, rx) = oneshot::channel();
        (
            Box::pin(async move {
                let r = f.await;
                TaskOutput {
                    name,
                    result: r,
                    sig: Some(sx),
                }
            }),
            rx,
        )
    }
    pub fn subprocess(
        f: Pin<Box<dyn Future<Output = Result<ExitStatus, std::io::Error>> + Send>>,
        name: String,
    ) -> (
        Pin<Box<dyn Future<Output = TaskOutput> + Send>>,
        Receiver<()>,
    ) {
        let (sx, rx) = oneshot::channel();
        (
            Box::pin(async move {
                let r = f.await;
                let r = match r {
                    Result::Ok(e) => {
                        log::info!("{} process exited with {}", name, e);
                        Ok(())
                    }
                    Err(e) => Err(e.into()),
                };
                TaskOutput {
                    name,
                    result: r,
                    sig: Some(sx),
                }
            }),
            rx,
        )
    }
    pub fn rpc(
        f: Pin<Box<dyn Future<Output = Result<Result<(), SErr>, RpcError>> + Send>>,
        name: String,
    ) -> (
        Pin<Box<dyn Future<Output = TaskOutput> + Send>>,
        Receiver<()>,
    ) {
        let (sx, rx) = oneshot::channel();
        (
            Box::pin(async move {
                let r = f.await;
                let r = match r {
                    Result::Ok(x) => x.map_err(|x| anyhow::Error::from(x)),
                    Err(x) => Result::<(), _>::Err(x.into()),
                };
                TaskOutput {
                    name,
                    result: r,
                    sig: Some(sx),
                }
            }),
            rx,
        )
    }
    pub fn wrapped<E: std::error::Error + Send + Sync + 'static>(
        f: Pin<Box<dyn Future<Output = Result<Result<()>, E>> + Send>>,
        name: String,
    ) -> (
        Pin<Box<dyn Future<Output = TaskOutput> + Send>>,
        Receiver<()>,
    ) {
        let (sx, rx) = oneshot::channel();
        (
            Box::pin(async move {
                let r = f.await;
                let r = match r {
                    Result::Ok(x) => x,
                    Err(x) => Err::<(), anyhow::Error>(x.into()),
                };
                TaskOutput {
                    name,
                    result: r,
                    sig: Some(sx),
                }
            }),
            rx,
        )
    }
}

impl Daemons {
    pub fn new() -> Self {
        let (s, r) = mpsc::unbounded_channel();
        Daemons {
            sender: s,
            recver: r,
            daemons: JoinSet::new(),
        }
    }
    pub async fn run(&mut self) -> Result<()> {
        loop {
            tokio::select! {
                maybe_task = self.recver.recv() => {
                    log::trace!("received new daemon");
                    if let Some(task) = maybe_task {
                        self.daemons.spawn(task);
                    }
                },
                maybe_res = self.daemons.join_next() => {
                    if let Some(res) = maybe_res {
                        let res = res?;
                        log::error!("Daemon {} stopped. {:?}", res.name, res.result);
                        if let Some(x) = res.sig {
                            x.send(()).unwrap();
                        }

                        // TODO: can I get traceback by logging ?
                    }
                }
            }
        }
    }
}
