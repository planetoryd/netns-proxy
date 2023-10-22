use std::{
    collections::HashMap,
    convert::Infallible,
    fmt::Display,
    fs::create_dir_all,
    io::Write,
    marker::{self, ConstParamTy},
    net::IpAddr,
    os::fd::{AsRawFd, RawFd},
    path::{Path, PathBuf},
    pin::Pin,
    process::exit,
    result::Result as SResult,
};

use amplify::{From, Wrapper};
use anyhow::{anyhow, bail, Ok, Result};
use async_recursion::async_recursion;
use bimap::BiMap;
use bytes::Bytes;
use derivative::Derivative;
use futures::{
    channel::mpsc::{self, Receiver as MRecver, UnboundedReceiver, UnboundedSender},
    future::{abortable, join_all},
    stream::{AbortHandle, Abortable, Aborted, FuturesUnordered},
    Future, Sink, SinkExt, Stream, StreamExt, TryFutureExt,
};
use netlink_ops::netns::{Fcntl, Pid, NSID};
use nix::{sched::CloneFlags, sys::signal::Signal::SIGTERM};
use pidfd::PidFuture;
use rumpsteak::{
    channel::{impl_recv, impl_send, Bidirectional, Recving, Sending},
    choices, session, try_session, Branch, ChoiceB, End, FullDual, IntoSession, Message, Receive,
    ReceiveError, Role, Roles, Route, Select, Send,
};
use rumpsteak::{Choices, PartialDual};
use serde::{Deserialize, Serialize};
use static_assertions::{assert_impl_all, assert_not_impl_all};
use thiserror::Error;
use tokio::{
    net::{UnixListener, UnixStream},
    task::JoinHandle,
};
use tokio_send_fd::SendFd;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use fixed_map::{Key as FKey, Map as FMap};

use std::marker::Send as MSend;

use crate::{
    id_alloc::{self, IDAlloc},
    listener::Listener,
    util::{from_vec_internal, to_vec_internal, wait_pid, AbortOnDropTokio}, config::{Validated, ServerConf, TUN2Proxy},
};

use crate::util::ChannelFailure;

#[derive(Debug, Default)]
/// Use this instead of [tokio::spawn]
pub struct ServerTasks {
    pub sids: IDAlloc,
    pub subject: HashMap<SubjectKey, SubjectData>,
    pub subject_names: BiMap<SubjectKey, SubjectName>,
}

#[derive(Debug, Default)]
pub struct SubjectData {
    /// Relevant Futures which serve as event handlers
    pub map: FMap<STaskType, (AbortHandle, Pid)>,
    pub users: u32,
}

impl SubjectData {
    pub fn kill(&mut self) -> Result<()> {
        for item in (&self.map).into_iter() {
            let (ty, (h, p)): (STaskType, &(AbortHandle, Pid)) = item;
            nix::sys::signal::kill(p.to_nix()?, SIGTERM)?;
            h.abort(); // should I abort here.
        }
        self.map.clear();
        Ok(())
    }
    pub fn watch(
        &mut self,
        k: STaskType,
        pid: Pid,
        spawn: impl FnOnce(PidFuture) -> AbortHandle,
    ) -> Result<()> {
        let fut = wait_pid(pid).ok_or_else(|| anyhow!("process doesn't exist"))?;
        let h = spawn(fut.into());
        let k: Option<_> = self.map.insert(k, (h, pid));
        if k.is_some() {
            // repeated addition should have been checked earlier.
            bail!(InvariantBreach);
        }
        Ok(())
    }
    /// Run tuntap process for the subject and register it
    /// We maintain an invariant here, any [TUN2Proxy] is validated, and then written into the /run directory, and read by the subprocess.
    pub fn run_tuntap(
        &mut self,
        dev: DevFd,
        conf: TUN2Proxy,
        ns: NSFd,
        confstate: &Validated<ServerConf>,
        id: &SubjectKey,
        spawn: impl FnOnce(PidFuture) -> AbortHandle,
    ) -> Result<()> {
        dev.fd.unset_cloexec()?;
        ns.fd.unset_cloexec()?;
        let mut command = std::process::Command::new(std::env::current_exe()?);
        let path = confstate.tuntap_conf_path(id.0);
        let by = to_vec_internal(&conf)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .read(true)
            .open(&path)?;
        file.write_all(&by)?;
        file.unset_cloexec()?;
        command
            .arg("tuntap")
            .arg(dev.fd.to_string())
            .arg(file.as_raw_fd().to_string())
            .arg(ns.fd.to_string());
        let child = command.spawn()?;
        let pid = Pid(child.id());
        self.watch(STaskType::Tun2proxy, pid, spawn)?;

        Ok(())
    }
}

assert_impl_all!(PidFuture: marker::Send, Sync);

// All subprocesses should be monitored with pidfd.
// Drop the Pidfd Future to kill the process. or the usual way.

#[derive(Clone, Copy, Debug, FKey, Serialize, Deserialize)]
pub enum STaskType {
    Tun2proxy,
    UserProgram,
}

pub type SKeyInner = u32;

#[derive(Wrapper, Debug, From, Hash, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
pub struct SubjectKey(pub SKeyInner);

/// Human readable name
#[derive(Wrapper, Debug, From, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct SubjectName(pub String);

impl Display for SubjectName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}]", self.0)
    }
}

#[choices]
#[derive(Serialize, Deserialize, Clone)]
pub enum Msg {
    CtrlMsg(),
    Identify(),
    SetUser(),
}

/// A subject can depend on a user. When the user shuts down the subject is GCed.
#[derive(Serialize, Deserialize, Clone)]
pub enum SetUser {
    Unset,
    Pid(Pid),
}

/// Client type
#[choices]
#[derive(Serialize, Deserialize, Clone)]
pub enum Identify {
    Control,
    Sub,
}

#[choices]
#[derive(Serialize, Deserialize, Clone)]
pub enum Kill {
    Subject(SubjectKey),
    Daemon,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FD(pub RawFd);

FDType!(DevFd, fd);
FDType!(NSFd, fd);

pub macro FDType( $t:ident, $inner:ident ) {
    #[derive(Clone)]
    pub struct $t {
        pub $inner: RawFd,
    }
    impl Message<$t> for FD {
        fn downcast(self) -> SResult<$t, Self> {
            Result::Ok($t { $inner: self.0 })
        }
        fn upcast(label: $t) -> Self {
            Self(label.$inner)
        }
    }
    impl Message<$t> for $t {
        fn downcast(self) -> SResult<$t, Self> {
            Result::Ok(self)
        }
        fn upcast(label: $t) -> Self {
            label
        }
    }
}

#[choices]
#[derive(Serialize, Deserialize, Clone)]
pub enum CtrlMsg {
    SubjectMsg(),
    /// Allow setting config through protocol
    ProgramConfig(ServerConf),
}

#[choices]
#[derive(Serialize, Deserialize, Clone)]
pub enum SubjectMsg {
    Initiate(pub SubjectName, pub InitialParams),
    GC(),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GC(pub SubjectName);

#[derive(Serialize, Deserialize, Clone)]
pub struct InitialParams {
    pub tun2proxy: TUN2Proxy,
    pub user: SetUser,
}
// Wrapped because of foreign trait impls
pub struct FramedUS(pub Framed<UnixStream, LengthDelimitedCodec>);

/// Client endpoint that connects the server
#[derive(Role)]
pub struct Client(
    #[route(Server, Msg)] FramedUS,
    #[route(Server, FD)] FDStream,
);

impl Client {
    pub async fn connect(sock: impl AsRef<Path>) -> Result<Client> {
        let (pa, pb) = UnixStream::pair()?;
        let conn = UnixStream::connect(sock).await?;
        conn.send_stream(pa).await?;
        let f: Framed<UnixStream, LengthDelimitedCodec> =
            Framed::new(conn, LengthDelimitedCodec::new());
        let f = FramedUS(f);

        Ok(Client(f, FDStream(pb)))
    }
}

/// The main endpoint of daemon.
#[derive(Role)]
pub struct Server(
    #[route(Client, Msg)] pub FramedUS,
    #[route(Client, FD)] pub FDStream,
);

#[derive(Wrapper, From)]
pub struct FDStream(pub UnixStream);

#[session]
pub type SubIdentify = Send<Server, (FramedUS, Identify), End>;

#[session]
pub struct Ctrl(Select<Server, (FramedUS, CtrlMsg)>);

/// Protocol to execute after the initial parameters have been sent
impl<'k> ChoiceB<'k> for Initiate {
    #[session('k Client)]
    type SelectorSession = Send<Server, (FDStream, DevFd), Send<Server, (FDStream, NSFd), End>>;
    #[session('k Server)]
    type BrancherSession = <Self::SelectorSession as PartialDual<'k, Client, Server>>::Dual<
        <Ctrl<'k, Client> as FullDual<'k, Client, Server>>::Dual,
    >;
}

impl<'k> ChoiceB<'k> for GC {
    #[session('k Client)]
    type SelectorSession = End;
    #[session('k Server)]
    type BrancherSession = <Self::SelectorSession as PartialDual<'k, Client, Server>>::Dual<
        <Ctrl<'k, Client> as FullDual<'k, Client, Server>>::Dual,
    >;
}

impl<'k> ChoiceB<'k> for Control {
    #[session('k Client)]
    type SelectorSession = End;
    #[session('k Server)]
    type BrancherSession = End;
}

impl<'k> ChoiceB<'k> for Sub {
    #[session('k Client)]
    type SelectorSession = End;
    #[session('k Server)]
    type BrancherSession = End;
}

impl<'k> ChoiceB<'k> for ServerConf {
    #[session('k Client)]
    type SelectorSession = End;
    #[session('k Server)]
    type BrancherSession = <Self::SelectorSession as PartialDual<'k, Client, Server>>::Dual<
        <Ctrl<'k, Client> as FullDual<'k, Client, Server>>::Dual,
    >;
}

impl Sending<FD> for FDStream {
    type Fut<'x> = impl Future<Output = Result<(), std::io::Error>>;
    type Error = std::io::Error;
    fn send(&mut self, item: FD) -> Self::Fut<'_> {
        async move { self.0.send_fd(item.0).await }
    }
}

impl Recving<FD> for FDStream {
    type Fut<'x> = impl Future<Output = Result<Option<FD>, Self::Error>>;
    type Error = std::io::Error;
    fn recv(&mut self) -> Self::Fut<'_> {
        async move { self.0.recv_fd().await.map(|k| Some(FD(k))) }
    }
}

pub fn exit_if_eof<T>(r: &Result<T>) {
    if let Err(e) = r {
        log::error!("exit as sub: SocketEOF");
        exit(1);
    }
}

// Theoreticlly I should send futures over the channel as I shouldn't run blocking code.
pub type BoxFunc =
    Box<dyn for<'a, 'b> FnOnce(&mut Listener, FutSetW<'a, 'b>) -> Result<()> + marker::Send>;
pub type FutOut = Option<BoxFunc>;

pub type AbortaFut<'f> = Pin<Box<dyn Future<Output = Result<FutOut>> + marker::Send + Sync + 'f>>;

#[derive(Clone, Copy)]
/// To break type recursion
pub struct FutSetW<'a, 'b>(pub &'a FutSet<'b>);

pub type FutSet<'f> = FuturesUnordered<Abortable<AbortaFut<'f>>>;

assert_impl_all!(FutSet: marker::Send, Sync);

pub type IntClient = UnboundedSender<BoxFunc>;

pub fn abortable_spawn<'a, 'f>(
    fut: Pin<Box<dyn Future<Output = Result<FutOut>> + marker::Send + Sync + 'f>>,
    set: FutSetW<'a, 'f>,
) -> AbortHandle {
    let (ab, h) = abortable(fut);
    set.0.push(ab);
    h
}

pub macro boxfn {
    ( $a:ident, $b:ident, $c:block ) => {
        Box::new(move |$a: &mut Listener, $b: FutSetW| {
            $c
            Ok(())
        }) as BoxFunc
    },
    ( $s:ident, $a:ident, $b:ident, $c:block ) => {
        $s.unbounded_send(Box::new(move |$a: &mut Listener, $b: FutSetW| {
            $c
            Ok(())
        }) as BoxFunc).map_err(|_|ChannelFailure)?;
    }
}

#[derive(Debug, Error)]
#[error("your input caused the crash")]
pub struct InputError;

#[derive(Debug, Error)]
#[error("this shouldn't happen. maybe some assumed invariants are broken.")]
pub struct InvariantBreach;

/// Add the Fut to the set, and places the abort handle
pub macro add_abortable_some($f:expr, $v:expr, $s:expr) {
    if !$v.as_ref().map(|x| x.is_aborted()).unwrap_or(false) {
        let (f, h) = abortable($f);
        $s.push(f);
        $v = Some(h);
    }
}

pub macro ignored_abortable($f:expr, $s:expr) {
    let (f, _h) = abortable($f);
    $s.push(f);
}

pub async fn wrap_fut(f: impl Future<Output = Result<()>> + marker::Send + Sync) -> Result<FutOut> {
    f.await?;
    Ok(None)
}

impl<I: for<'a> Deserialize<'a>> Recving<I> for FramedUS {
    type Fut<'x> = impl Future<Output = Result<Option<I>, Self::Error>> where Self: 'x;
    type Error = anyhow::Error;
    fn recv(&mut self) -> Self::Fut<'_> {
        async move {
            let by = StreamExt::next(&mut self.0).await;
            if let Some(by) = by {
                let by = by?;
                Result::Ok(from_vec_internal(&by)?)
            } else {
                Result::Ok(None)
            }
        }
    }
}

impl<I: Serialize> Sending<I> for FramedUS {
    type Fut<'x> = impl Future<Output = Result<(), Self::Error>> where Self: 'x;
    type Error = anyhow::Error;
    fn send(&mut self, item: I) -> Self::Fut<'_> {
        async move {
            let vec = to_vec_internal(&item)?;
            self.0.send(vec.into()).await?;
            Ok(())
        }
    }
}

impl Listener {
    /// GC a subject, kill all related processes and futures
    pub fn gc_subject(&mut self, sname: &SubjectName) -> Result<()> {
        let skey = self
            .tasks
            .subject_names
            .get_by_right(sname)
            .ok_or(InputError)?;
        self.tasks
            .subject
            .get_mut(skey)
            .ok_or(InvariantBreach)?
            .kill()?;
        self.tasks.subject.remove(skey);

        Ok(())
    }
    /// Allocate a key
    pub fn initiate_subject(&mut self, sname: SubjectName) -> Result<SubjectKey> {
        let id = self.tasks.sids.alloc_or()?;
        let skey = SubjectKey(id);
        self.tasks.subject_names.insert(skey, sname);
        self.tasks.subject.insert(skey, Default::default());

        Ok(skey)
    }
}

// macro crashes rust-analyzer
// choiceb! {
//     SubjectMsg, 'k,
//     Client => Select<Server, SubjectMsgBranch>,
//     Server => <Self::SelectorSession as Dual<'k, Client, Server>>::Dual
// }
