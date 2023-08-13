use std::{path::Path, sync::Arc, time::Duration};

use anyhow::Result;
use bincode::{deserialize, serialize};
use bytes::Bytes;
use rtnetlink::netlink_packet_route::tc::u32::Sel;
use serde::{Deserialize, Serialize};
use tokio::{
    net::{UnixDatagram, UnixListener, UnixStream},
    sync::{
        mpsc::{self, channel, Receiver, UnboundedSender},
        oneshot,
    },
    task::JoinHandle,
};

use crate::{
    data::ConfPaths,
    util::{PidAwaiter, TaskCtx},
};
use pidfd::PidFd;

#[derive(Serialize, Deserialize)]
pub enum ToServer {
    Ping,
    ReloadConfig,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub enum ToClient {
    Pong,
    ConfigReloaded,
}

pub struct Server;

use tokio_util::codec::Framed;
use tokio_util::codec::LengthDelimitedCodec;

impl Server {
    pub async fn serve(self, paths: Arc<ConfPaths>) -> Result<()> {
        let p = paths.sock4ctrl();
        let pr = p.as_path();
        let client = Client::new(pr).await;
        if let Result::Ok(mut client) = client {
            let r = client.req(ToServer::Ping).await?;
            anyhow::ensure!(r == ToClient::Pong);
            bail!("another netns-proxy instance is running");
        } else {
            if pr.exists() {
                tokio::fs::remove_file(pr).await?;
            }
        }
        let sock = UnixListener::bind(pr)?;
        let p2 = paths.clone();
        // If a restart is in progress, no restart signal is accepted.
        let (restart, mut rx) = channel::<oneshot::Sender<()>>(1);
        tokio::spawn(async move {
            let mut h: JoinHandle<Result<()>>;
            let p2 = p2;
            let mut cback: Option<oneshot::Sender<()>> = None;
            loop {
                if let Some(c) = cback {
                    c.send(()).unwrap();
                }
                let pid_wait = PidAwaiter::new();
                h = tokio::spawn(main_task(p2.clone(), pid_wait.sx.clone()));
                if let Some(cb) = rx.recv().await {
                    log::info!("Abort main task");
                    h.abort(); // drops all things, kills some processes, and sends the pids.
                    pid_wait.kill_n_wait().await;
                    cback = Some(cb);
                } else {
                    break;
                }
            }
            Ok(())
        });
        loop {
            let (us, _anon) = sock.accept().await?;
            tokio::spawn(Self::handle_conn(us, restart.clone()));
        }
        Ok(())
    }
    async fn handle_conn(us: UnixStream, restart: mpsc::Sender<oneshot::Sender<()>>) -> Result<()> {
        let mut f: Framed<UnixStream, LengthDelimitedCodec> =
            Framed::new(us, LengthDelimitedCodec::new());
        while let Some(by) = f.next().await {
            let by = by?;
            let pa: ToServer = bincode::deserialize(&by)?;
            let re: ToClient;
            match pa {
                ToServer::Ping => {
                    re = ToClient::Pong;
                }
                ToServer::ReloadConfig => {
                    let (sx, rx) = oneshot::channel();
                    restart.try_send(sx)?;
                    // restarting
                    rx.await.unwrap();
                    re = ToClient::ConfigReloaded;
                }
            };
            let by = bincode::serialize(&re)?;
            f.send(by.into()).await?;
        }
        Ok(())
    }
}

pub struct Client {
    f: Framed<UnixStream, LengthDelimitedCodec>,
}

impl Client {
    pub async fn new(p: &Path) -> Result<Self> {
        let a = UnixStream::connect(p).await?;
        Ok(Self {
            f: Framed::new(a, LengthDelimitedCodec::new()),
        })
    }
    pub async fn req(&mut self, r: ToServer) -> Result<ToClient> {
        let by: Bytes = bincode::serialize(&r)?.into();
        self.f.send(by).await?;
        let res = self
            .f
            .next()
            .await
            .ok_or(anyhow!("client: conn closed"))??;
        let res: ToClient = bincode::deserialize(&res)?;
        Ok(res)
    }
}

use anyhow::{anyhow, bail, Ok};
use clap::{Parser, Subcommand};

use crate::sub::{handle, SubHub, ToSub};
use crate::util::error::DevianceError;
use crate::util::ns::{get_self_netns_inode, self_netns_identify};
use crate::util::{branch_out, open_wo_cloexec, Awaitor, TaskOutput};
use crate::util::{perms::*, DaemonSender};
use crate::watcher::{FlatpakWatcher, Watcher, WatcherEvent};
use futures::{SinkExt, StreamExt};

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

use crate::data::*;
use crate::netlink::*;

async fn main_task(paths: Arc<ConfPaths>, pid_wait: UnboundedSender<Pid>) -> Result<()> {
    // IP addresses etc. are fixed by putting derivation in the state file
    // Applying a SubjectInfo should work regardless how messed up the user's system state is.
    // Therefore all tasks may be aborted
    let mut state: NetnspState = NetnspState::load(paths.clone()).await?;

    let mut dae = Awaitor::new();
    let ctx = TaskCtx {
        dae: dae.sender.clone(),
        pid: pid_wait,
    };

    let mut mn: MultiNS = MultiNS::new(paths, ctx.clone()).await?;
    mn.init_current().await?;
    state.derive_all_named().await?;
    state.resume(&mut mn, ctx.clone()).await?;
    state.dump().await?;

    let (sx, rx) = unbounded_channel();
    let flp = FlatpakWatcher::new(sx.clone());
    let (t, _) = TaskOutput::immediately(Box::pin(flp.daemon()), "flatpak-watcher".to_owned());
    ctx.dae.send(t).unwrap();

    let (t, _) = TaskOutput::immediately(
        Box::pin(event_handler(rx, state, mn)),
        "event-handler".to_owned(),
    );
    ctx.dae.send(t).unwrap();
    // finally. wait on all tasks.
    log::info!("wait on all tasks");
    dae.wait().await?;

    Ok(())
}

async fn event_handler(
    mut rx: UnboundedReceiver<WatcherEvent>,
    mut state: NetnspState,
    mut mn: MultiNS,
) -> Result<()> {
    while let Some(ev) = rx.recv().await {
        match ev {
            WatcherEvent::Flatpak(fp) => {
                if state.derive_flatpak(fp.clone()).await? {
                    let inf = state.derivative.flatpak.get(&fp.pid).ok_or(DevianceError)?;
                    inf.connect(&mut mn).await?;
                    inf.apply_veths(&mn, &state.derivative).await?;
                    inf.apply_nft_veth(&mut state.incre_nft);
                    state.incre_nft.execute()?;
                    // start all daemons
                    inf.run(&mn.procs).await?;
                } else {
                    log::debug!("Flatpak-watcher: {:?} ignored, no associaed profile", fp);
                }
            } // TODO: watch for other kinds, bwrap, unshared.
        }
    }
    Ok(())
}
