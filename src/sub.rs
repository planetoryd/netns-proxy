use crate::netlink::nl_ctx;
use crate::util;
use anyhow::Result;
use bytes::Bytes;
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
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::{mpsc, oneshot, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tokio_util::codec::LengthDelimitedCodec;

use crate::data::{self, *};

use crate::util::error::DevianceError;
use crate::util::perms::get_non_priv_user;

use anyhow::Ok;

use std::collections::VecDeque;
use std::fmt::Debug;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::sync::Arc;

use sysinfo::{self, ProcessExt, SystemExt};
use tokio::{self, io::AsyncReadExt, process::Command};

use crate::netlink::*;
use crate::util::{AbortOnDrop, Awaitor, PidAwaiter, TaskCtx, TaskOutput};
use anyhow::anyhow;
use dashmap::DashMap;
use tokio_util::codec::Framed;
// I briefly tried to proxy the netink socket. It feels like too much trouble.
// And the kernel could do it without needless proxying

use crate::state::*;
use rtnetlink::proxy;

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

#[derive(Debug)]
pub struct Sub {
    pub st: SplitSink<Framed<UnixStream, LengthDelimitedCodec>, Bytes>,
    pub fd_q: mpsc::UnboundedSender<oneshot::Sender<RawFd>>,
}

pub struct Proc {
    pid: Pid,
}

impl Sub {
    pub async fn send(&mut self, x: ToSub) -> Result<()> {
        self.st.send(util::to_vec_internal(&x)?.into()).await?;
        Ok(())
    }
    /// get an fd opened by the sub process
    pub async fn get_fd(&mut self, ns: NSID) -> Result<RawFd> {
        self.send(ToSub::Open(ns)).await?;
        let (sx, rx) = oneshot::channel();
        self.fd_q.send(sx).unwrap();
        let fd = rx.await?;
        Ok(fd)
    }
}

#[derive(Debug)]
pub struct SubHub {
    sock_path: PathBuf,
    pub subs: Arc<DashMap<NSID, Sub>>,
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
                let f: Framed<UnixStream, LengthDelimitedCodec> =
                    Framed::new(stream, LengthDelimitedCodec::new());
                let (sink, mut stream) = f.split();
                let (fds, mut fdr) = mpsc::unbounded_channel();

                let f = Sub {
                    st: sink,
                    fd_q: fds,
                };

                let h: AbortOnDrop<_> = tokio::spawn(async move {
                    while let Some(byt) = stream.next().await {
                        let pack: ToMain = util::from_vec_internal(&byt?)?;
                        match pack {
                            ToMain::FD(rfd) => {
                                if let Some(sx) = fdr.recv().await {
                                    let fail = sx.send(rfd);
                                    if fail.is_err() {
                                        log::error!("fail to send fd for sub")
                                    }
                                } else {
                                    break;
                                }
                            }
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
        ctx.dae.send(t).unwrap();
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

        let sx = self.ctx.pid.clone();
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
        sx.send(util::PidOp::Add(id, Pid(pid))).unwrap();

        let h = async move {
            let e = cmd.wait().await?;
            log::warn!("Subprocess exited {}, {}", e, pid);
            Ok(())
        };
        let (t, _r) = TaskOutput::immediately(Box::pin(h), "rpc-proc".to_owned());
        self.ctx.dae.send(t).unwrap();
        Ok(())
    }
    // gets the handle to operate on an NS
    pub async fn op(&self, id: NSID) -> Result<(RefMut<'_, NSID, Sub>, OpRes)> {
        let r = match self.subs.get_mut(&id) {
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
            Some(o) => (o, OpRes::Existing),
        };
        Ok(r)
    }
}

pub enum OpRes {
    NewSub,
    Existing,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ToSub {
    Init(ConfPaths, u32, u32, NSID),
    Flatpak(SubjectInfo<FlatpakV>),
    Named(SubjectInfo<NamedV>),
    Open(NSID),
    TUN(String),
    TAP(String)
}

#[derive(Serialize, Deserialize)]
pub enum ToMain {
    FD(RawFd),
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

pub async fn send<T: Serialize>(
    f: &mut Framed<UnixStream, LengthDelimitedCodec>,
    v: &T,
) -> Result<()> {
    f.send(util::to_vec_internal(v)?.into())
        .await
        .map_err(anyhow::Error::from)
}

pub async fn handle(mut f: Framed<UnixStream, LengthDelimitedCodec>) -> Result<()> {
    let dae = Awaitor::new();
    let pw = PidAwaiter::new();
    let sx = pw.sx.clone();
    tokio::spawn(crate::util::handle_sig(pw));

    let p = next(&mut f, None, true).await?;
    match p {
        ToSub::Init(path, u, g, subject_ns) => {
            // Sends a netlink socket to the main process
            proxy::proxy(path.sock4netlink(), None).await?;
            let mut st = NsubState {
                ns: Netns::thread().await?,
                ctx: TaskCtx {
                    dae: dae.sender,
                    pid: sx,
                },
                non_priv_uid: u,
                non_priv_gid: g,
            };

            loop {
                let p = next(&mut f, Some(&subject_ns), true).await?;
                let mut nft = TokioSocket::new(rtnetlink::netlink_sys::constants::NETLINK_NETFILTER)?;
                match p {
                    ToSub::Named(info) => {
                        ns_task(info, &mut st, &subject_ns, &mut nft).await?;
                    }
                    ToSub::Flatpak(info) => {
                        ns_task(info, &mut st, &subject_ns, &mut nft).await?;
                    }
                    ToSub::TUN(name) => {
                        let tt = TunTapInterface::new(&name, Medium::Ip)?;
                        
                    }
                    _ => {
                        unimplemented!()
                    }
                }
            }
        }
        _ => unreachable!(),
    }
    dae.wait().await?;
    Ok(())
}

async fn ns_task<V: VSpecifics>(
    info: SubjectInfo<V>,
    st: &mut NsubState,
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

    nl_ctx!(link, conn, st.ns.netlink, {
        let lo = link.not_absent(lo_k)?.exist_mut()?;
        conn.set_up(lo).await?;
    });
    st.ns.refresh().await?;
    nl_ctx!(link, _conn, st.ns.netlink, {
        assert!(matches!(
            link.not_absent(lo_k)?.exist_ref()?.up,
            Exp::Confirmed(true)
        ));
    });

    info.apply_nft_dns(sock).await?;
    info.run_tun2s(st).await?;
    info.run_dnsp(st).await?;
    Ok(())
}

use thiserror::{self, Error};

#[derive(Error, Debug)]
#[error("socket EOF, probably because main process exited")]
pub struct SocketEOF;
