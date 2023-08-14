use std::collections::BTreeMap;
use std::env;
use std::fmt::Debug;
use std::fs::File;
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::Ok;
use anyhow::Result;
use futures::Future;
use futures::StreamExt;
use futures::{FutureExt, TryFutureExt};

use nix::sys::signal::kill;
use nix::sys::signal::Signal;
use nix::sys::signal::Signal::SIGTERM;
use nix::unistd::Gid;
use nix::unistd::Pid;
use nix::unistd::Uid;
use pidfd::PidFd;
use procfs::process::Process;

use tokio::io::BufStream;
use tokio::signal::unix::SignalKind;
use tokio::sync::mpsc;
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Receiver;
use tokio::task::AbortHandle;
use tokio::task::JoinError;
use tokio::task::JoinHandle;
use tokio::task::JoinSet;

use crate::data::FlatpakID;
use crate::netlink::NsFile;
use crate::sub::SocketEOF;

use nix::unistd::setgroups;

use std::collections::HashMap;

use std::{ffi::CString, os::unix::process::CommandExt, path::Path, process::exit};
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

/// adapt the flatpak settings of given list
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
            conf.write_to_file(p.as_path())?;
            info!("{} written. New file", p.to_string_lossy());
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

pub fn open_wo_cloexec(path: &Path) -> Result<File> {
    use nix::fcntl::{open, OFlag};
    use nix::sys::stat::Mode;
    let fd = open(path, OFlag::O_RDONLY, Mode::empty())?;
    let syncf = unsafe { File::from_raw_fd(fd) };

    Ok(syncf)
}

pub mod ns {
    pub const NETNS_PATH: &str = "/run/netns/";
    use futures::TryFutureExt;

    use crate::data::ProfileName;

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
        let f = open_wo_cloexec(p.as_path())?.into();
        Ok(f)
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
        let r = open_wo_cloexec(&proc_ns.path)?.into();
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
    use anyhow::Result;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use thiserror::Error;

    #[derive(Error, Debug)]
    #[error("Deviance from a configuration plan, or the configuration is faulty")]
    pub struct DevianceError;

    #[derive(Error, Debug)]
    #[error("Something is missing, and it can be handled")]
    pub struct MissingError;
}

/// A way to wait on all tasks before quitting
pub struct Awaitor {
    pub sender: DaemonSender,
    recver: UnboundedReceiver<Pin<Box<dyn Future<Output = TaskOutput> + Send>>>,
    daemons: JoinSet<TaskOutput>,
}

pub struct PidAwaiter {
    pub sx: UnboundedSender<crate::data::Pid>,
    pub rx: UnboundedReceiver<crate::data::Pid>,
}

impl PidAwaiter {
    pub fn new() -> Self {
        let (sx, rx) = unbounded_channel();
        Self { sx, rx }
    }
    pub async fn kill_n_wait(mut self) {
        let mut h = vec![];
        while let Result::Ok(x) = self.rx.try_recv() {
            // all pids should be in buffer
            if let Result::Ok(f) = unsafe { PidFd::open(x.0 as i32, 0) } {
                unsafe {
                    let _ = f.send_raw_signal(libc::SIGINT, std::ptr::null(), 0);
                };
                h.push(f.into_future());
            } else {
                // skip. dead proc.
            }
        }
        log::debug!("Wait {} processes to finish", h.len());
        futures::future::join_all(h).await;
        log::debug!("All processes stopped");
    }
}

pub type DaemonSender = UnboundedSender<Pin<Box<dyn Future<Output = TaskOutput> + Send>>>;

/// Senders.
#[derive(Debug, Clone)]
pub struct TaskCtx {
    pub dae: DaemonSender,
    pub pid: UnboundedSender<crate::data::Pid>,
}

pub struct TaskOutput {
    pub name: String,
    pub result: Result<()>,
    /// notified in case the task stops
    pub sig: Option<oneshot::Sender<()>>,
}

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
                Self::handle_task_result(r, name.clone());
                TaskOutput {
                    name,
                    result: Ok(()),
                    sig: Some(sx),
                }
            }),
            rx,
        )
    }
    pub fn wrapped<E2: std::error::Error + Send + Sync + 'static, T: 'static + Debug>(
        f: Pin<Box<dyn Future<Output = Result<Result<T>, E2>> + Send>>,
        name: String,
    ) -> (
        Pin<Box<dyn Future<Output = TaskOutput> + Send>>,
        Receiver<()>,
    ) {
        let (sx, rx) = oneshot::channel();
        (
            Box::pin(async move {
                let r = f.await;
                let n2 = name.clone();
                let r = match r {
                    Result::Ok(x) => {
                        Self::handle_task_result(x, n2);
                        Ok(())
                    }
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
    pub fn immediately<T: Send + 'static + Debug>(
        f: Pin<Box<dyn Future<Output = Result<T>> + Send>>,
        name: String,
    ) -> (
        Pin<Box<dyn Future<Output = TaskOutput> + Send>>,
        Receiver<()>,
    ) {
        let n2 = name.clone();
        let h: AbortOnDrop<_> = tokio::spawn(async move {
            let x = f.await;
            Self::handle_task_result(x, name);
            Ok(())
        })
        .into();

        Self::wrapped(Box::pin(h), n2)
    }
    pub fn immediately_std<
        T: Send + 'static + Debug,
        E: std::error::Error + Send + Sync + 'static,
    >(
        f: Pin<Box<dyn Future<Output = Result<T, E>> + Send>>,
        name: String,
    ) -> (
        Pin<Box<dyn Future<Output = TaskOutput> + Send>>,
        Receiver<()>,
    ) {
        let n2 = name.clone();
        let h: AbortOnDrop<_> = tokio::spawn(async move {
            let x = f.await;
            Self::handle_task_result(x, name);
            Ok(())
        })
        .into();
        Self::wrapped(Box::pin(h), n2)
    }
    pub fn handle_task_result<T: Debug, E: Debug>(x: Result<T, E>, name: String) {
        // a task can error before Awaiter start awaiting, which produces an error
        // that has to be handled early. Otherwise nothing will be logged, which looks like deadlock.
        if let Err(e) = x {
            log::error!("Task {} errored, {:?}", name, e);
        } else {
            log::debug!("Task {} has result {:?}", name, x.unwrap());
        }
    }
}

impl Awaitor {
    pub fn new() -> Self {
        let (s, r) = mpsc::unbounded_channel();
        Awaitor {
            sender: s,
            recver: r,
            daemons: JoinSet::new(),
        }
    }
    pub async fn wait(&mut self) -> Result<()> {
        loop {
            tokio::select! {
                maybe_task = self.recver.recv() => {
                    if let Some(task) = maybe_task {
                        self.daemons.spawn(task);
                    }
                },
                maybe_res = self.daemons.join_next() => {
                    if let Some(res) = maybe_res {
                        let res = res?;
                        log::error!("daemon {} stopped. {:?}", res.name, res.result);
                        if let Some(x) = res.sig {
                            let _ = x.send(());
                        }
                        // TODO: can I get traceback by logging ?
                    }
                }
            }
        }
    }
}

use crate::sub::handle;
use std::sync::atomic::Ordering;
use tokio::net::UnixStream;
use tokio_util::codec::Framed;
use tokio_util::codec::LengthDelimitedCodec;

pub async fn handle_sig(pw: PidAwaiter) -> Result<()> {
    tokio::signal::unix::signal(SignalKind::interrupt())?
        .recv()
        .await;
    SIG_EXIT.store(true, Ordering::Relaxed);
    log::debug!("Sub received SIGINT. Now kill wait processes to die");
    pw.kill_n_wait().await;
    Ok(())
}

static SIG_EXIT: AtomicBool = AtomicBool::new(false);

pub fn branch_out() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 4 {
        let path: Result<PathBuf, _> = args[2].parse();
        let fd: Result<i32, _> = args[3].parse();
        if path.is_ok() && fd.is_ok() && args[1] == "sub" {
            let fd = fd?;
            let fd: File = unsafe { File::from_raw_fd(fd) };
            let ns = NsFile(fd);
            ns.enter()?;
            return tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let sock_path = path.unwrap();
                    let conn = UnixStream::connect(sock_path.as_path()).await?;
                    let f: Framed<UnixStream, LengthDelimitedCodec> =
                        Framed::new(conn, LengthDelimitedCodec::new());

                    let x = handle(f).await;
                    if let Err(e) = x {
                        if let Some(x) = e.downcast_ref::<SocketEOF>() {
                            if SIG_EXIT.load(Ordering::Relaxed) {
                                // ignore
                            } else {
                                log::error!("exit as sub \n Err: {:?}", e);
                            }
                        } else {
                            log::error!("exit as sub \n Err: {:?}", e);
                        }
                        exit(1);
                    }
                    return Ok(());

                    Ok(())
                });
        }
    }

    Ok(())
}

pub struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Future for AbortOnDrop<T> {
    type Output = std::result::Result<T, JoinError>;
    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        unsafe { self.map_unchecked_mut(|s| &mut s.0) }.poll(cx)
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort()
    }
}

impl<T> From<JoinHandle<T>> for AbortOnDrop<T> {
    fn from(value: JoinHandle<T>) -> Self {
        Self(value)
    }
}

impl<T> AbortOnDrop<T> {
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

    let h: AbortOnDrop<()> = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        println!("3");
    })
    .into();

    let h2 = tokio::spawn(async move { h.await });
    h2.abort(); // This also aborts h

    tokio::time::sleep(Duration::from_secs(5)).await;

    // should output -- 3
}
