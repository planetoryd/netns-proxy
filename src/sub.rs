use anyhow::{Result};
use dashmap::mapref::one::{Ref, RefMut};
use futures::{SinkExt, StreamExt, TryFutureExt};

use serde::{Deserialize, Serialize};

use tokio::fs::remove_file;

use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tokio_util::codec::LengthDelimitedCodec;

use crate::data::*;

use crate::util::perms::get_non_priv_user;

use anyhow::Ok;




use std::sync::Arc;
use std::{path::PathBuf};
use std::{os::unix::process::CommandExt};

use sysinfo::{self, ProcessExt, SystemExt};
use tokio::{
    self,
    io::{AsyncReadExt},
    process::Command,
};

use crate::netlink::*;
use crate::util::{Awaitor, DaemonSender, TaskOutput};
use anyhow::anyhow;
use dashmap::DashMap;
use tokio_util::codec::Framed;
// I briefly tried to proxy the netink socket. It feels like too much trouble.
// And the kernel could do it without needless proxying

use rtnetlink::proxy::{self, ProxySocketType};


impl SubjectInfo<NamedV> {
    pub async fn run(&self, _dae: &DaemonSender, sub: &SubHub) -> Result<()> {
        let (mut s, _) = sub.op(self.ns.clone()).await?;
        s.send(bincode::serialize(&ToSub::Named(self.clone()))?.into())
            .await?;
        Ok(())
    }
}

impl SubjectInfo<FlatpakV> {
    pub async fn run(&self, _dae: &DaemonSender, sub: &SubHub) -> Result<()> {
        let (mut s, _) = sub.op(self.ns.clone()).await?;
        s.send(bincode::serialize(&ToSub::Flatpak(self.clone()))?.into())
            .await?;
        Ok(())
    }
}

pub struct NsubState {
    pub ns: Netns,
    pub dae: DaemonSender,
    pub non_priv_uid: u32,
    pub non_priv_gid: u32,
}

static Nsub: Option<RwLock<NsubState>> = None;

/// Contract: do not hold the lock for long.
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

pub struct SubHub {
    sock_path: PathBuf,
    subs: Arc<DashMap<NSID, Framed<UnixStream, LengthDelimitedCodec>>>,
    queue: mpsc::UnboundedSender<(NSID, oneshot::Sender<()>)>,
    dae: DaemonSender,
}

/// to manipulate an NS
pub type NsubClient<'a> = Ref<'a, NSID, Framed<UnixStream, LengthDelimitedCodec>>;

impl SubHub {
    /// only need one per program
    pub async fn new(dae: DaemonSender, paths: Arc<ConfPaths>) -> Result<Self> {
        let sock_rpc = paths.sock4rpc();
        // TODO: what if it's in use
        if sock_rpc.exists() {
            remove_file(sock_rpc.as_path()).await?;
        }
        let subs = Arc::new(DashMap::new());
        let sock = UnixListener::bind(sock_rpc.as_path())?;
        let sub_m = subs.clone();
        let (sx, mut rx) = mpsc::unbounded_channel::<(NSID, oneshot::Sender<()>)>();

        let (u, g) = get_non_priv_user(None, None, None, None)?;
        let task = async move {
            loop {
                let (stream, _anon) = sock.accept().await?;
                let mut f: Framed<UnixStream, LengthDelimitedCodec> =
                    Framed::new(stream, LengthDelimitedCodec::new());
                // the peer_addr is unnamed, so it must self identify.

                if let Some((id, sx)) = rx.recv().await {
                    let k = bincode::serialize(&ToSub::Assign(id.clone(), u, g))?.into();
                    f.send(k).await?;
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

        // ends when the listener closes
        dae.send(t).unwrap();

        Ok(Self {
            sock_path: sock_rpc,
            subs,
            queue: sx,
            dae,
        })
    }
    /// start a new sub
    /// new sub for each ns
    fn new_sub(&self) -> Result<()> {
        let sp = self.sock_path.as_path().to_owned();
        // TODO: logic for watching this process
        let h = async move {
            let e = std::env::current_exe()?;
            log::trace!("curr exe {:?}", &e);
            let mut cmd = Command::new(e)
                .arg(sp)
                .uid(0) // run it as root
                .spawn()
                .unwrap();
            let pid = cmd.id().unwrap();
            log::debug!("subprocess {}", pid);
            let e = cmd.wait().await?;
            log::debug!("subprocess {}", e);
            Ok(())
        };
        let (t, _r) = TaskOutput::immediately(Box::pin(h), "rpc-proc".to_owned());
        self.dae.send(t).unwrap();
        Ok(()) 
    }
    // gets the handle to operate on an NS
    pub async fn op(
        &self,
        id: NSID,
    ) -> Result<(
        RefMut<'_, NSID, Framed<UnixStream, LengthDelimitedCodec>>,
        OpRes,
    )> {
        let r = match self.subs.get_mut(&id) {
            None => {
                log::debug!("create new rpc-sub");
                let (sx, rx) = oneshot::channel::<()>();
                self.queue.send((id.clone(), sx)).unwrap();
                self.new_sub()?;
                rx.await?;
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

#[derive(Serialize, Deserialize)]
pub enum ToSub {
    Assign(NSID, u32, u32),
    Proxy(PathBuf),
    Flatpak(SubjectInfo<FlatpakV>),
    Named(SubjectInfo<NamedV>),
}

pub async fn handle(mut f: Framed<UnixStream, LengthDelimitedCodec>) -> Result<()> {
    let first = f.next().await.unwrap()?;
    let first: ToSub = bincode::deserialize(&first)?;
    let mut dae = Awaitor::new();
    match first {
        ToSub::Assign(id, u, g) => {
            log::trace!("ToSub::Assign");
            let ns = Netns::enter(id).await?;

            let packet = f.next().await.unwrap()?;
            let packet: ToSub = bincode::deserialize(&packet)?;
            match packet {
                ToSub::Proxy(sock) => {
                    log::trace!("ToSub::Proxy");
                    let (t, _r) = TaskOutput::immediately(
                        Box::pin(async move {
                            proxy::proxy::<{ ProxySocketType::PollRecvFrom }>(sock).await
                        }),
                        "proxy-server".to_owned(),
                    );
                    dae.sender.send(t).unwrap();

                    let mut st = NsubState {
                        ns,
                        dae: dae.sender.clone(),
                        non_priv_uid: u,
                        non_priv_gid: g,
                    };
                    
                    let packet = f.next().await.unwrap()?;
                    let packet: ToSub = bincode::deserialize(&packet)?;
                    match packet {
                        ToSub::Named(info) => {
                            info.run_tun2s(&mut st).await?;
                            info.run_dnsp(&mut st).await?;
                        }
                        _ => (),
                    }
                }
                _ => (),
            }
        }
        _ => unreachable!(),
    }
    dae.wait().await?;
    log::debug!("rpc-sub-exit");
    Ok(())
}

#[tokio::test]
async fn test_sub() -> Result<()> {
    flexi_logger::Logger::try_with_env_or_str(
        "trace,netlink_proto=info,rustables=warn,netlink_sys=info",
    )
    .unwrap()
    .log_to_stdout()
    .start()?;

    let mut ro: PathBuf = env!("CARGO_MANIFEST_DIR").parse()?;
    ro.push("testing");
    let mut derivative: PathBuf = ro.clone();
    let _ = std::fs::create_dir(&ro);
    derivative.push("sub_derivative.json");
    let mut settings: PathBuf = ro.clone();
    settings.push("geph1.json");
    let mut sock: PathBuf = ro.clone();
    sock.push("sock");
    let _ = std::fs::create_dir(&sock);

    let paths = Arc::new(ConfPaths {
        settings,
        derivative,
        sock,
    });

    let mut state: NetnspState = NetnspState::load(paths.clone()).await?;
    let mut dae = Awaitor::new();
    let mut mn: MultiNS = MultiNS::new(paths, dae.sender.clone()).await?;
    let id = NSID::from_name(ProfileName("geph1".to_owned())).await?;
    let nl = mn.get_nl(id.clone()).await?;
    let ns = ConnRef::new(Arc::new(nl)).to_netns(id).await?;
    dbg!(&ns);

    dae.wait().await?;

    Ok(())
}
