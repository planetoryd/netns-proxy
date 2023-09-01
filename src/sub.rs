use crate::netlink::nl_ctx;
use crate::{tun2proxy, util};
use anyhow::{bail, Result};
use bytes::{Buf, Bytes, BytesMut};
use dashmap::mapref::one::{Ref, RefMut};
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt, TryFutureExt};
use rtnetlink::netlink_proto::new_connection_with_socket;
use rtnetlink::netlink_sys::{AsyncSocket, TokioSocket};
use rtnetlink::Handle;
use serde::{Deserialize, Serialize};

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

impl SubjectInfo<NamedV> {
    pub async fn run(&mut self, sub: &SubHub) -> Result<()> {
        let (mut s, _) = sub.op(self.ns.clone()).await?;
        s.send(ToSub::Named(self.clone())).await?;
        Ok(())
    }
}

impl SubjectInfo<FlatpakV> {
    pub async fn run(&mut self, sub: &SubHub) -> Result<()> {
        let (mut s, _) = sub.op(self.ns.clone()).await?;
        s.send(ToSub::Flatpak(self.clone())).await?;
        Ok(())
    }
}

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

pub struct TUNFD {
    fd: RawFd,
    mtu: i32,
}

/// Not cloneable
#[derive(Debug)]
pub struct Sub {
    pub sink: SplitSink<Framed<UnixStream, LengthDelimitedCodec>, Bytes>,
    pub ns_q: mpsc::UnboundedSender<oneshot::Sender<RawFd>>,
    pub tun_q: mpsc::UnboundedSender<oneshot::Sender<TUNFD>>,
    pub netlink_q: mpsc::UnboundedSender<oneshot::Sender<RawFd>>,
    pub fd_counter: AtomicU32,
}

impl Sub {
    pub async fn send(&mut self, x: ToSub) -> Result<()> {
        self.sink.send(util::to_vec_internal(&x)?.into()).await?;
        Ok(())
    }
    /// get an fd opened by the sub process
    pub async fn get_nsfd(&mut self, ns: NSID) -> Result<RawFd> {
        let (sx, rx) = oneshot::channel();
        // must send the sx before
        self.ns_q.send(sx).unwrap();
        self.send(ToSub::FetchFd(FDReq::Open(ns))).await?;
        let fd = rx.await?;
        Ok(fd)
    }
    pub fn new_fd_token(&mut self) -> FdToken {
        FdToken(
            self.fd_counter
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
        )
    }
}

#[derive(Debug, Clone)]
pub struct SubHub {
    pub subs: Arc<DashMap<NSID, Sub>>,
    sock_path: PathBuf,
    queue: mpsc::UnboundedSender<(NSID, oneshot::Sender<()>)>,
    ctx: TaskCtx,
}

/// to manipulate an NS
pub type NsubClient<'a> = Ref<'a, NSID, Sub>;

impl SubHub {
    /// only need one per program
    pub async fn new(ctx: TaskCtx, paths: Arc<ConfPaths>) -> Result<Self> {
        let sock_rpc = paths.sock4rpc();
        if sock_rpc.exists() {
            remove_file(sock_rpc.as_path()).await?;
        }
        let subs = Arc::new(DashMap::new());
        let sock = UnixListener::bind(sock_rpc.as_path())?;
        let sub_m = subs.clone();
        let (queue, mut rx) = mpsc::unbounded_channel::<(NSID, oneshot::Sender<()>)>();
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
                let (fds, mut fdr) = mpsc::unbounded_channel();
                let (tun_sx, mut tun_r) = mpsc::unbounded_channel();
                let (nl_sx, mut nl_r) = mpsc::unbounded_channel();

                let f = Sub {
                    sink,
                    ns_q: fds,
                    tun_q: tun_sx,
                    netlink_q: nl_sx,
                    fd_counter: AtomicU32::new(0),
                };

                let h: AbortOnDrop<_> = tokio::spawn(async move {
                    while let Some(byt) = stream.next().await {
                        let pack: ToMain = util::from_vec_internal(&byt?)?;
                        match pack {
                            ToMain::FD(res) => match res {
                                FDRes::NSFD(rfd) => {
                                    if let Some(sx) = fdr.recv().await {
                                        sx.send(rfd)
                                            .map_err(|_| anyhow!("sending NS fd failed"))?;
                                    } else {
                                        break;
                                    }
                                }
                                FDRes::TUN(mtu) => {
                                    let fd = fd_stream.recv_fd().await?;

                                    if let Some(sx) = tun_r.recv().await {
                                        sx.send(TUNFD { fd, mtu })
                                            .map_err(|_| anyhow!("sending TUN fd failed"))?;
                                    } else {
                                        break;
                                    }

                                    // getting TUN fd happens in reverse order.
                                    // push into TUN queue, request sub
                                }
                                FDRes::Netlink => {
                                    let fd = fd_stream.recv_fd().await?;
                                    if let Some(sx) = nl_r.recv().await {
                                        sx.send(fd)
                                            .map_err(|_| anyhow!("sending netlink fd failed"))?;
                                    } else {
                                        break;
                                    }
                                }
                                FDRes::TAP => {
                                    todo!()
                                }
                            },
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
                    let r = sub_m.insert(id, f);
                    assert!(r.is_none());
                    sx.send(()).map_err(|_| anyhow!("sending failed"))?;
                } else {
                    // channel closed. should not happen
                    anyhow::bail!("queue channel closed");
                }
            }
            Ok(())
        }; // must start it now
        let (t, _r) = TaskOutput::immediately(Box::pin(task), "rpc-listener".to_owned());
        ctx.pm
            .send(PidOp::Add(ProcessGroup::Top, TaskKind::Task(t)))
            .unwrap();
        // ends when the listener closes

        Ok(Self {
            sock_path: sock_rpc,
            subs,
            queue,
            ctx,
        })
    }
    /// Starts the child process
    fn run(&self, fd: RawFd, id: NSID) -> Result<()> {
        let sp = self.sock_path.as_path().to_owned();

        let sx = self.ctx.pm.clone();
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
        sx.send(util::PidOp::Add(
            ProcessGroup::Sub(id.clone()),
            util::TaskKind::Process(Pid(pid)),
        ))
        .unwrap();

        let h = async move {
            let e = cmd.wait().await?;
            log::warn!("Subprocess exited {}, {}", e, pid);
            Ok(())
        };
        let (t, _r) = TaskOutput::immediately(Box::pin(h), "rpc-proc".to_owned());
        self.ctx
            .pm
            .send(PidOp::Add(ProcessGroup::Sub(id), TaskKind::Task(t)))
            .unwrap();
        Ok(())
    }
    // gets the handle to operate on an NS
    pub async fn op(&self, id: NSID) -> Result<(RefMut<'_, NSID, Sub>, OpRes)> {
        // Subprocess is started on first use
        let p = match self.subs.get_mut(&id) {
            None => {
                log::trace!("create new rpc-sub");
                let nf = id.open().await?;
                let (sx, rx) = oneshot::channel::<()>();
                self.queue.send((id.clone(), sx)).unwrap();
                // There is a brief period of time. Fork + execve can give a child process the NS fd
                nf.unset_cloexec()?;
                self.run(nf.0.as_raw_fd(), id.clone())?;
                drop(nf);
                rx.await?;
                log::trace!("rpc-sub received");
                (
                    self.subs.get_mut(&id).ok_or(anyhow!("ns missing"))?,
                    OpRes::NewSub,
                )
            }
            Some(k) => (k, OpRes::Existing),
        };
        Ok(p)
    }
    pub async fn broadcast(&self, msg: ToSub) -> Result<()> {
        for mut k in self.subs.iter_mut() {
            k.send(msg.clone()).await?;
        }
        Ok(())
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
    NSFD(RawFd),
    /// MTU
    TUN(i32),
    TAP,
    Netlink,
}

pub struct FdPre {
    fd: RawFd,
    kind: FDRes,
}

impl FdPre {
    /// produce the FD and consume it
    pub fn consume(self) {}
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

pub fn send_blocking(stream: &mut impl std::io::Write, v: impl Serialize) -> Result<()> {
    let mut state = LengthDelimitedCodec::new();
    let mut buf = BytesMut::new();
    state.encode(util::to_vec_internal(&v)?.into(), &mut buf)?;
    while buf.has_remaining() {
        let k = stream.write(buf.chunk())?;
        buf.advance(k);
    }
    Ok(())
}

#[derive(Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct FdToken(u32);

pub fn tuntap_(sock: RawFd) {
    let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(sock) };
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
                        let dev = fd_map.remove(&token).ok_or(anyhow!("Fd doesn't exsit"))?;
                        let (sa, sb) = UnixStream::pair()?;
                        sb.unset_cloexec()?;
                        dev.fd.unset_cloexec()?;
                        let process = Command::new(std::env::current_exe()?)
                            .arg("tuntap_")
                            .arg(sb.as_raw_fd().to_string())
                            .spawn()?;
                        drop(sb);
                        if let Some(alive) = process.id() {
                            nsub.ctx
                                .pm
                                .send(PidOp::Add(
                                    ProcessGroup::Subject(args.ns.clone()),
                                    TaskKind::Process(Pid(alive)),
                                ))
                                .unwrap();
                            let k = args.to_args(dev.fd);
                            let mut f = Framed::new(sa, LengthDelimitedCodec::new());
                            send(&mut f, &k).await?;
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

    info.apply_nft_dns(sock).await?;
    info.may_run_tun2socks(nsub).await?;
    info.may_run_dnsproxy(nsub).await?;
    Ok(())
}

use thiserror::{self, Error};

#[derive(Error, Debug)]
#[error("socket EOF, probably because main process exited")]
pub struct SocketEOF;
