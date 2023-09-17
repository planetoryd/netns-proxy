use crate::netlink::nl_ctx;
use crate::nft::Mergeable;
use crate::schedule::{NMap, NSMap, NSWaitfree};
use crate::{tun2proxy, util};
use anyhow::{bail, Result};
use bytes::{Buf, Bytes, BytesMut};
use dashmap::mapref::one::{Ref, RefMut};
use derivative::Derivative;
use futures::stream::{SplitSink, SplitStream};
use futures::{Future, SinkExt, StreamExt, TryFutureExt};
use nix::sys::memfd;
use rtnetlink::netlink_proto::new_connection_with_socket;
use rtnetlink::netlink_sys::{AsyncSocket, TokioSocket};
use rtnetlink::Handle;
use serde::{Deserialize, Serialize};

use simple_stream::frame::SimpleFrameBuilder;
use smoltcp::phy::{Medium, TunTapInterface};
use tidy_tuntap::flags;
use tokio::fs::remove_file;

use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::SignalKind;
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::{mpsc, oneshot, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tokio_send_fd::SendFd;
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

use crate::data::{self, *};

use crate::util::error::DevianceError;
use crate::util::perms::get_non_priv_user;

use anyhow::Ok;

use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::future::pending;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::exit;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::Arc;

use sysinfo::{self, ProcessExt, SystemExt};
use tokio::{self, io::AsyncReadExt, process::Command};

use crate::netlink::*;
use crate::util::{AbortOnDrop, ProcessManager, TaskCtx, TaskOutput};
use anyhow::anyhow;
use dashmap::DashMap;
use tokio_util::codec::Framed;
// I briefly tried to proxy the netink socket. It feels like too much trouble.
// And the kernel could do it without needless proxying

use crate::state::*;
use crate::util::*;

pub struct NsubState {
    pub ns: Netns,
    pub ctx: TaskCtx,
    pub non_priv_uid: u32,
    pub non_priv_gid: u32,
}

use std::sync::atomic::Ordering;
pub static SIG_EXIT: AtomicBool = AtomicBool::new(false);

pub async fn handle_signal(pw: Arc<ProcessManager>) -> Result<()> {
    tokio::signal::unix::signal(SignalKind::interrupt())?
        .recv()
        .await;
    SIG_EXIT.store(true, Ordering::SeqCst);
    log::debug!("Sub received SIGINT.");
    pw.kill_await(None, KillMask::all()).await;
    exit(0);
}

#[derive(Default)]
pub struct NLFilter<N: NMap<V = TokioSocket>> {
    subs: SubHub<NSWaitfree<Sub, NSID>>,
    map: Arc<N>,
}

impl<N: NMap<V = TokioSocket>> NLFilter<N> {
    pub async fn init_sock(&self, k: &NSIDKey) -> Result<TokioSocket> {
        let (_g, sub, _): (_, _, _) = self.subs.get(k).await?;
        let fd = sub
            .get_fd(FDReq::Netlink(
                rtnetlink::netlink_sys::constants::NETLINK_NETFILTER,
            ))
            .await?;
        let ts = unsafe { TokioSocket::from_raw_fd(fd.fd) };

        Ok(ts)
    }
}

impl<N: NMap<V = TokioSocket>> NSMap for NLFilter<N> {
    type Inner = N;
    type V = N::V;
    async fn get<'r, Fut: Future<Output = Result<Self::V>>>(
        &'r self,
        k: &<Self::Inner as NMap>::K,
    ) -> Result<(
        <Self::Inner as NMap>::ReadGuard<'r>,
        fn(&'r <Self::Inner as NMap>::ReadGuard<'r>) -> &'r Self::V,
        bool,
    )> {
        self.map
            .get(k, async move |x| self.init_sock(x).await)
            .await
    }
    async fn get_mut<'w, Fut: Future<Output = Result<Self::V>>>(
        &'w self,
        k: &<Self::Inner as NMap>::K,
    ) -> Result<(
        <Self::Inner as NMap>::WriteGuard<'w>,
        fn(&'w mut <Self::Inner as NMap>::WriteGuard<'w>) -> &'w mut Self::V,
        bool,
    )>
    where
        Self::V: 'w,
    {
        self.map
            .get_mut(k, async move |x| self.init_sock(x).await)
            .await
    }
}

#[derive(Debug)]
pub struct Sub {
    pub sink: SplitSink<Framed<UnixStream, LengthDelimitedCodec>, Bytes>,
    pub fd_queue: mpsc::UnboundedSender<oneshot::Sender<FdPre>>,
    pub fd_counter: AtomicU32,
}

impl Sub {
    pub async fn send(&mut self, x: ToSub) -> Result<()> {
        self.sink.send(util::to_vec_internal(&x)?.into()).await?;
        Ok(())
    }
    /// This fn has to be atomic therefore &mut
    pub async fn get_fd(&mut self, req: FDReq) -> Result<FdPre> {
        let (sx, rx) = oneshot::channel();
        // atmoic begins
        self.fd_queue.send(sx).unwrap();
        self.send(ToSub::FetchFd(req)).await?;
        // atomic ends
        Ok(rx.await?)
    }
    pub fn new_fd_token(&mut self) -> FdToken {
        FdToken(
            self.fd_counter
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
        )
    }
}

#[derive(Debug, Derivative)]
#[derivative(Clone(bound = ""))]
pub struct SubHub<N: NMap<V = Sub, K = NSID> + Default> {
    pub map: Arc<N>,
    sock_path: PathBuf,
    queue: mpsc::UnboundedSender<(NSID, oneshot::Sender<Sub>)>,
    ctx: TaskCtx,
}

impl<N: NMap<V = Sub, K = NSID> + Default> SubHub<N> {
    /// only need one per program
    pub async fn new(ctx: TaskCtx, paths: Arc<ConfPaths>) -> Result<Self> {
        let sock_rpc = paths.sock4rpc();
        if sock_rpc.exists() {
            remove_file(sock_rpc.as_path()).await?;
        }
        let subs = Arc::new(N::default());
        let sock = UnixListener::bind(sock_rpc.as_path())?;
        let sub_m = subs.clone();
        let (queue, mut rx) = mpsc::unbounded_channel::<(NSID, oneshot::Sender<Sub>)>();
        let sockr = sock_rpc.clone();
        let task = async move {
            let mut to_abort = Vec::new();
            loop {
                let (stream, _anon) = sock.accept().await?;
                log::trace!("new connection on {:?}", sockr.as_path());
                let fd_stream = stream.recv_stream().await?;
                let f: Framed<UnixStream, LengthDelimitedCodec> =
                    Framed::new(stream, LengthDelimitedCodec::new());
                let (sink, mut stream) = f.split();
                let (fd_q, mut fd_rx) = mpsc::unbounded_channel();

                let f = Sub {
                    sink,
                    fd_queue: fd_q,
                    fd_counter: AtomicU32::new(0),
                };

                let h: AbortOnDrop<_> = tokio::spawn(async move {
                    while let Some(byt) = stream.next().await {
                        let pack: ToMain = util::from_vec_internal(&byt?)?;
                        match pack {
                            ToMain::FD(res) => {
                                let fd = fd_stream.recv_fd().await?;

                                if let Some(sx) = fd_rx.recv().await {
                                    sx.send(FdPre { fd, kind: res })
                                        .map_err(|_| anyhow!("sending TUN fd failed"))?;
                                } else {
                                    break;
                                }
                            }
                            _ => unimplemented!(),
                        }
                    }
                    Ok(())
                })
                .into();
                to_abort.push(h);
                // the peer_addr is unnamed, so it must self identify.
                log::trace!("wait for rpc-sub assignment");
                if let Some((id, sx)) = rx.recv().await {
                    log::trace!("rpc-sub assigned {}", id);
                    sx.send(f).map_err(|_| anyhow!("sending failed"))?;
                } else {
                    // channel closed. should not happen
                    anyhow::bail!("queue channel closed");
                }
            }
            Ok(())
        }; // must start it now
        let (t, _r) = TaskOutput::immediately(task, "rpc-listener".to_owned());
        ctx.reg(ProcessGroup::Top, TaskKind::Task(t));
        // ends when the listener closes

        Ok(Self {
            sock_path: sock_rpc,
            map: subs,
            queue,
            ctx,
        })
    }
    /// Starts a child process
    fn run(&self, fd: RawFd, id: NSID) -> Result<()> {
        let sp = self.sock_path.as_path().to_owned();

        let e = std::env::current_exe()?;
        log::trace!("self exe {:?}", &e);
        let mut cmd: tokio::process::Child = Command::new(e)
            .arg("sub")
            .arg(sp)
            .arg(fd.to_string())
            .uid(0) // run it as root
            .spawn()?;

        let pid = cmd.id().unwrap();
        log::debug!("Subprocess started {}", pid);
        self.ctx
            .reg(ProcessGroup::Sub(id.as_key()), TaskKind::Process(Pid(pid)));

        let h = async move {
            let e = cmd.wait().await?;
            log::warn!("Subprocess exited {}, {}", e, pid);
            Ok(())
        };
        let (t, _r) = TaskOutput::immediately(h, "rpc-proc".to_owned());
        self.ctx
            .reg(ProcessGroup::Sub(id.as_key()), TaskKind::Task(t));
        Ok(())
    }
    /// Unsafe because some operations have to be atomic, or you may cause UB
    pub async unsafe fn broadcast(&self, msg: ToSub) -> Result<()> {
        for mut k in self.map.iter_mut() {
            k.send(msg.clone()).await?;
        }
        Ok(())
    }
    pub async fn kill_subject(&self, subject: NSIDKey) -> Result<()> {
        unsafe {
            self.broadcast(ToSub::Kill(
                ProcessGroup::Subject(subject),
                KillMask::all(),
            ))
            .await
        }
    }
    pub async fn kill_all_subjects(&self) -> Result<()> {
        unsafe {
            self.broadcast(crate::sub::ToSub::KillAllSubjects).await
        }
    }
    pub async fn init_sub(&self, ns: &NSID) -> Result<Sub> {
        let nf = ns.open().await?;
        let (sx, rx) = oneshot::channel::<Sub>();
        self.queue.send((ns.clone(), sx)).unwrap();
        nf.unset_cloexec()?;
        self.run(nf.0.as_raw_fd(), ns.clone())?;
        drop(nf);
        let sub = rx.await?;
        let (u, g) = get_non_priv_user(None, None, None, None)?;
        sub.send(ToSub::Init((*self.paths).clone(), u, g, ns.clone()))
            .await?;
        Ok(sub)
    }
}

impl<N: NMap<V = Sub, K = NSID> + Default> NSMap for SubHub<N> {
    type V = Sub;
    type Inner = N;
    async fn get<'r, Fut: Future<Output = Result<Self::V>>>(
        &'r self,
        k: &<Self::Inner as NMap>::K,
    ) -> Result<(
        <Self::Inner as NMap>::ReadGuard<'r>,
        fn(&'r <Self::Inner as NMap>::ReadGuard<'r>) -> &'r Self::V,
        bool,
    )> {
        self.map
            .get(k, async move |ns| self.init_sub(ns).await)
            .await
    }
    async fn get_mut<'w, Fut: Future<Output = Result<Self::V>>>(
        &'w self,
        k: &<Self::Inner as NMap>::K,
    ) -> Result<(
        <Self::Inner as NMap>::WriteGuard<'w>,
        fn(&'w mut <Self::Inner as NMap>::WriteGuard<'w>) -> &'w mut Self::V,
        bool,
    )>
    where
        Self::V: 'w,
    {
        self.map
            .get_mut(k, async move |ns| self.init_sub(ns).await)
            .await
    }
}

pub enum OpRes {
    NewSub,
    Existing,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ToSub {
    Init(ConfPaths, u32, u32, NSID),
    Flatpak(SubjectInfo<FlatpakV>),
    Named(SubjectInfo<NamedV>),
    PutFd(FdToken, FDRes),
    FetchFd(FDReq),
    /// spawn a tun2proxy process in this NS
    TUN2Proxy(TUN2ProxyE, FdToken),
    Kill(ProcessGroup, KillMask),
    KillAllSubjects,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum FDReq {
    Open(NSID),
    TUN(String),
    TAP(String),
    /// Protocol: isize
    Netlink(isize),
}

#[derive(Serialize, Deserialize, Clone)]
pub enum ToMain {
    /// get FD from another NS
    Route(NSID, FDReq),
    FD(FDRes),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum FDRes {
    /// MTU
    TUN(i32),
    TAP(i32),
    Netlink,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FdPre {
    pub fd: RawFd,
    pub kind: FDRes,
}

pub async fn next<T: for<'a> Deserialize<'a> + Debug>(
    f: &mut Framed<UnixStream, LengthDelimitedCodec>,
    ns: Option<&NSID>,
    sub: bool,
) -> Result<T> {
    if let Some(ns) = ns {
        log::trace!(
            "{}{} waiting for next msg",
            if sub { "sub " } else { "" },
            ns
        );
    }
    let pa = f.next().await;
    match pa {
        Some(pa) => {
            let k = pa?;
            let pa: T = util::from_vec_internal(&k)?;
            Ok(pa)
        }
        None => {
            // the subs exit on socket close
            Err(SocketEOF.into())
        }
    }
}

pub async fn send(
    f: &mut Framed<UnixStream, LengthDelimitedCodec>,
    v: &impl Serialize,
) -> Result<()> {
    f.send(util::to_vec_internal(v)?.into())
        .await
        .map_err(anyhow::Error::from)
}

#[derive(Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct FdToken(u32);

#[cfg(test)]
mod test_stream {
    use super::ToSub;
    use crate::util::from_vec_internal;
    use crate::util::to_vec_internal;
    use anyhow::Ok;
    use anyhow::Result as Res;
    use simple_stream::{
        frame::{FrameBuilder, SimpleFrame, SimpleFrameBuilder},
        Blocking, Plain,
    };
    use std::os::unix::net::UnixStream;
    use std::thread::spawn;

    #[test]
    fn test_simple_stream() -> Res<()> {
        let (sa, sb) = UnixStream::pair()?;
        spawn(move || {
            let mut f: Plain<UnixStream, SimpleFrameBuilder> = Plain::new(sa);
            let buf = to_vec_internal(&ToSub::FetchFd(super::FDReq::TAP("a".to_owned())))?;
            let f1 = SimpleFrame::new(&buf);
            f.b_send(&f1)?;
            Ok(())
        });
        let b = spawn(move || {
            let mut f: Plain<UnixStream, SimpleFrameBuilder> = Plain::new(sb);
            let k = f.b_recv()?;
            let p: ToSub = from_vec_internal(&k.payload())?;
            dbg!(p);
            Ok(())
        });
        b.join();
        Ok(())
    }
}

pub async fn handle(
    mut f: Framed<UnixStream, LengthDelimitedCodec>,
    fd_stream: UnixStream,
) -> Result<()> {
    let pm = ProcessManager::new();
    let sx = pm.sx.clone();
    tokio::spawn(handle_signal(pm.clone()));

    let p = next(&mut f, None, true).await?;
    match p {
        ToSub::Init(path, u, g, subject_ns) => {
            // Sends a netlink socket to the main process
            let mut nsub = NsubState {
                ns: Netns::thread().await?,
                ctx: TaskCtx { pm: sx },
                non_priv_uid: u,
                non_priv_gid: g,
            };
            let mut fd_map: HashMap<FdToken, FdPre> = Default::default();

            loop {
                let p = next(&mut f, Some(&subject_ns), true).await?;
                let mut nft =
                    TokioSocket::new(rtnetlink::netlink_sys::constants::NETLINK_NETFILTER)?; // cloexec is on
                match p {
                    ToSub::Named(info) => {
                        ns_task(info, &mut nsub, &subject_ns, &mut nft).await?;
                    }
                    ToSub::Flatpak(info) => {
                        ns_task(info, &mut nsub, &subject_ns, &mut nft).await?;
                    }
                    ToSub::FetchFd(req) => {
                        match req {
                            FDReq::TUN(name) => {
                                log::debug!("sending TUN fd");
                                let tt = tidy_tuntap::Tap::new(name, false)?;
                                // better to get mtu right here as we have the sockets opened
                                fd_stream.send_fd(tt.as_raw_fd()).await?; // must send fd before notifying main
                                send(&mut f, &ToMain::FD(FDRes::TUN(tt.get_mtu()?))).await?;
                            }
                            FDReq::TAP(name) => {
                                todo!()
                            }
                            FDReq::Netlink(proto) => {
                                log::debug!("sending netlink socket");
                                let sock = TokioSocket::new(proto)?;
                                fd_stream.send_fd(sock.as_raw_fd()).await?;
                                send(&mut f, &ToMain::FD(FDRes::Netlink)).await?;
                            }
                            _ => {
                                unimplemented!()
                            }
                        }
                    }
                    ToSub::PutFd(token, fd) => {
                        let k = fd_map.insert(
                            token,
                            FdPre {
                                fd: fd_stream.recv_fd().await?,
                                kind: fd,
                            },
                        );
                        if k.is_some() {
                            bail!("put FD twice");
                        }
                    }
                    ToSub::TUN2Proxy(args, token) => {
                        use simple_stream::{
                            frame::{FrameBuilder, SimpleFrame, SimpleFrameBuilder},
                            Blocking, Plain,
                        };
                        use std::os::unix::net::UnixStream;

                        let dev = fd_map.remove(&token).ok_or(anyhow!("Fd doesn't exsit"))?;
                        let (sa, sb) = UnixStream::pair()?;
                        sb.unset_cloexec()?;
                        dev.fd.unset_cloexec()?;
                        let process = Command::new(std::env::current_exe()?)
                            .arg("tuntap")
                            .arg(sb.as_raw_fd().to_string())
                            .spawn()?;
                        drop(sb);
                        if let Some(alive) = process.id() {
                            nsub.ctx
                                .pm
                                .send(PidOp::Add(
                                    ProcessGroup::Subject(args.ns.as_key()),
                                    TaskKind::Process(Pid(alive)),
                                ))
                                .unwrap();
                            let mut f: Plain<UnixStream, SimpleFrameBuilder> = Plain::new(sa);
                            let buf = to_vec_internal(&args)?;
                            let f1 = SimpleFrame::new(&buf);
                            f.b_send(&f1)?;
                            let buf = to_vec_internal(&dev)?;
                            let f1 = SimpleFrame::new(&buf);
                            f.b_send(&f1)?;
                        } else {
                            log::error!("Tun2proxy stopped early");
                        }
                    }
                    ToSub::KillAllSubjects => {
                        pm.kill_subjects(KillMask::all()).await;
                    }
                    _ => {
                        unimplemented!()
                    }
                }
            }
        }
        _ => unreachable!(),
    }
}

/// Things to do in the subject NS
async fn ns_task<V: VSpecifics>(
    info: SubjectInfo<V>,
    nsub: &mut NsubState,
    subject_ns: &NSID,
    sock: &mut impl AsyncSocket,
) -> Result<()> {
    let mut eff = Remainder::default();
    {
        let tun = tidy_tuntap::Tun::new(TUN_NAME, false)?;
        let flags = tun.flags().unwrap();
        log::debug!(
            "{}, got TUN {} with flags {:?}",
            &subject_ns,
            TUN_NAME,
            flags
        );
        if !flags.intersects(flags::Flags::IFF_UP) {
            log::debug!("{}, bring TUN up", &subject_ns);
            tun.bring_up()?;
            let flags = tun.flags().unwrap();
            anyhow::ensure!(flags.intersects(flags::Flags::IFF_UP));
        }
        tun_ops(tun)?;
    }
    let lo_k = &"lo".parse()?;

    nl_ctx!(link, conn, nsub.ns.netlink, {
        let lo = link.not_absent(lo_k)?.exist_mut()?;
        conn.set_up(lo).await?;
    });
    nsub.ns.refresh().await?;
    nl_ctx!(link, _conn, nsub.ns.netlink, {
        assert!(matches!(
            link.not_absent(lo_k)?.exist_ref()?.up,
            Exp::Confirmed(true)
        ));
    });
    let k = info.apply_nft_dns().await?;
    eff.merge(k)?;
    eff.apply(sock).await?;
    info.may_run_tun2socks(nsub).await?;
    info.may_run_dnsproxy(nsub).await?;
    Ok(())
}

use thiserror::{self, Error};

#[derive(Error, Debug)]
#[error("socket EOF, probably because main process exited")]
pub struct SocketEOF;
