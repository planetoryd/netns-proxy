use anyhow::{bail, Result};
use dashmap::mapref::one::Ref;
use futures::{AsyncRead, Future, SinkExt, StreamExt, TryFutureExt};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use tarpc::context::current;
use tarpc::server::{BaseChannel, Channel};
use tarpc::tokio_util::codec::{self, LengthDelimitedCodec};
use tokio::io::BufStream;
use tokio::net::UnixDatagram;
use tokio::sync::{mpsc, oneshot, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::data::*;
use crate::util::error::se_ok;
use crate::util::perms::get_non_priv_user;
use crate::*;
use anyhow::Ok;

use nix::unistd::{unlink, Gid, Pid, Uid};

use std::collections::VecDeque;
use std::sync::Arc;
use std::{net::Ipv4Addr, os::fd::RawFd, path::PathBuf};
use std::{os::unix::process::CommandExt, process::Stdio};

use sysinfo::{self, ProcessExt, SystemExt};
use tokio::{
    self,
    io::{AsyncBufReadExt, AsyncReadExt},
    process::Command,
};

use crate::netlink::*;
use crate::util::{ns::*, DaemonSender, Daemons, TaskOutput};

use anyhow::anyhow;
use dashmap::DashMap;
use tarpc::tokio_serde::formats::{Bincode, SymmetricalBincode};
use tarpc::{context, serde_transport};

use tarpc::{client, server};

// I briefly tried to proxy the netink socket. It feels like too much trouble.
// And the kernel could do it without needless proxying

use rtnetlink::proxy::{self, ProxySocketType};
use serde_error::Error as SErr;

#[tarpc::service]
pub trait NsubService {
    async fn enter(id: NSID) -> Result<(), SErr>;
    /// Netlink proxy
    async fn proxy(sock: PathBuf) -> Result<(), SErr>;
    /// Will return when processes exit
    async fn daemons_n(info: SubjectInfo<NamedV>) -> Result<(), SErr>;
    async fn daemons_f(info: SubjectInfo<FlatpakV>) -> Result<(), SErr>;
}

#[tarpc::server]
impl NsubService for NsubRPC {
    async fn enter(self, _: tarpc::context::Context, id: NSID) -> Result<(), SErr> {
        let mut gs = global_state_mut().await?;
        let conn = ConnRef::new(Arc::new(NetlinkConn::new_in_current_ns()));
        gs.ns = Netns::enter(id, conn).await?;
        let mut dae = Daemons::new();
        gs.dae = dae.sender.clone();
        tokio::spawn(async move { dae.run().await });
        se_ok()
    }
    async fn proxy(self, _: tarpc::context::Context, sock: PathBuf) -> Result<(), SErr> {
        tokio::spawn(proxy::proxy::<{ ProxySocketType::PollRecvFrom }>(sock));
        se_ok()
    }
    async fn daemons_n(
        self,
        _: tarpc::context::Context,
        info: SubjectInfo<NamedV>,
    ) -> Result<(), SErr> {
        info.assure_in_ns()?;
        let mut gs = global_state_mut().await?;
        (gs.non_priv_uid, gs.non_priv_gid) = get_non_priv_user(None, None, None, None)?;

        se_ok()
    }
    async fn daemons_f(
        self,
        _: tarpc::context::Context,
        info: SubjectInfo<FlatpakV>,
    ) -> Result<(), SErr> {
        info.assure_in_ns()?;
        let mut gs = global_state_mut().await?;
        (gs.non_priv_uid, gs.non_priv_gid) = get_non_priv_user(None, None, None, None)?;

        se_ok()
    }
}

impl SubjectInfo<NamedV> {
    pub async fn run(&self, dae: &DaemonSender, sub: &NetnspSubCaller) -> Result<()> {
        let (s, _) = sub.op(self.ns.clone()).await?;
        let s = s.to_owned();
        let cloned = self.clone();
        let f = async move {
            let r = s.daemons_n(current(), cloned).await;
            let x = match r.map_err(anyhow::Error::from) {
                Result::Ok(x) => x.map_err(anyhow::Error::from),
                Err(x) => Err(x),
            };
            TaskOutput {
                name: format!("ns"),
                result: x,
                sig: None,
            }
        };
        dae.send(Box::pin(f)).unwrap();
        Ok(())
    }
}

impl SubjectInfo<FlatpakV> {
    pub async fn run(&self, dae: &DaemonSender, sub: &NetnspSubCaller) -> Result<()> {
        let (s, _) = sub.op(self.ns.clone()).await?;
        let s = s.to_owned();
        let cloned = self.clone();
        let n = format!("{}/daemons", self.id);
        let (t, r) = TaskOutput::rpc(
            Box::pin(async move { s.daemons_f(current(), cloned).await }),
            n,
        );
        dae.send(t).unwrap();
        Ok(())
    }
}

#[derive(Clone)]
pub struct NsubRPC;

pub struct NsubState {
    pub ns: Netns,
    pub dae: DaemonSender,
    pub non_priv_uid: u32,
    pub non_priv_gid: u32,
}

static Nsub: Option<RwLock<NsubState>> = None;

pub async fn global_state_mut() -> Result<RwLockWriteGuard<'static, NsubState>> {
    let g: _ = Nsub
        .as_ref()
        .ok_or(anyhow!("Nsub state is None"))?
        .write()
        .await;
    Ok(g)
}

pub async fn global_state() -> Result<RwLockReadGuard<'static, NsubState>> {
    let g: _ = Nsub
        .as_ref()
        .ok_or(anyhow!("Nsub state is None"))?
        .read()
        .await;
    Ok(g)
}

pub struct NetnspSubImpl;

pub struct NetnspSubCaller {
    sock_path: PathBuf,
    subs: Arc<DashMap<NSID, NsubServiceClient>>,
    queue: mpsc::Sender<(NSID, oneshot::Sender<()>)>,
}

/// to manipulate an NS
pub type NsubClient<'a> = Ref<'a, NSID, NsubServiceClient>;

impl NetnspSubCaller {
    /// only need one per program
    pub async fn init(dae: DaemonSender) -> Result<Self> {
        // TODO: security
        let sock_path: PathBuf = "./netnsp.sock".into();
        if sock_path.exists() {
            unlink(sock_path.as_path())?;
        }
        let subs = Arc::new(DashMap::new());
        let mut sock = serde_transport::unix::listen(sock_path.as_path(), Bincode::default).await?;
        let sub_m = subs.clone();
        let (sx, mut rx) = mpsc::channel::<(NSID, oneshot::Sender<()>)>(5);
        let server = tokio::spawn(async move {
            while let Some(s) = sock.next().await {
                let s = s?;
                let c = NsubServiceClient::new(Default::default(), s).spawn();

                // the peer_addr is unnamed, so it must self identify.

                if let Some((id, notif)) = rx.recv().await {
                    c.enter(context::current(), id.clone()).await??;
                    sub_m.insert(id, c);
                    // invariant, notified ==> entry exists
                    notif.send(()).map_err(|_| anyhow!("sending failed"))?;
                } else {
                    // channel closed. should not happen
                    anyhow::bail!("queue channel closed");
                }
            }
            Ok(())
        });
        let (t, r) = TaskOutput::wrapped(Box::pin(server), "RPC server".to_owned());
        dae.send(t).unwrap();

        Ok(Self {
            sock_path,
            subs,
            queue: sx,
        })
    }
    /// start a new sub
    /// new sub for each ns
    fn new_sub(&self) -> Result<()> {
        let sp = self.sock_path.as_path().to_owned();
        // TODO: logic for watching this process
        tokio::spawn(async move {
            let mut cmd = Command::new(std::env::current_exe()?)
                .arg(sp)
                .uid(0) // run it as root
                .spawn()
                .unwrap();
            cmd.wait().await
        });

        Ok(())
    }
    // gets the handle to operate on an NS
    pub async fn op(&self, id: NSID) -> Result<(Ref<'_, NSID, NsubServiceClient>, OpRes)> {
        let r = match self.subs.get(&id) {
            None => {
                let (sx, rx) = oneshot::channel::<()>();
                self.queue.send((id.clone(), sx)).await?;
                self.new_sub()?;
                rx.await?;
                (
                    self.subs.get(&id).ok_or(anyhow!("ns missing"))?,
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
