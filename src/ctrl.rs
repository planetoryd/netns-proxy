use std::{path::Path, sync::Arc};

use crate::util::{self, PidOp};
use crate::{
    data::ConfPaths,
    util::{PidAwaiter, TaskCtx},
};
use anyhow::{Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{
        mpsc::{self, channel, UnboundedSender},
        oneshot,
    },
};

#[derive(Serialize, Deserialize, Clone)]
pub enum ToServer {
    Ping,
    ReloadConfig,
    GC(ProfileName),
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub enum ToClient {
    Pong,
    ConfigReloaded,
    GCed,
    Fail,
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
        let (sx_main, mut rx_main) = unbounded_channel::<UnboundedSender<ToServer>>();
        tokio::spawn(async move {
            let mut h: _;
            let p2 = p2;

            let mut cback: Option<oneshot::Sender<()>> = None;
            loop {
                if let Some(c) = cback {
                    c.send(()).unwrap();
                }
                let p3 = p2.clone();
                let pid_wait = PidAwaiter::new();
                let sx = pid_wait.sx.clone();
                let (sx_cmd, rx_cmd) = unbounded_channel();
                sx_main.send(sx_cmd).unwrap();
                h = tokio::spawn(async move {
                    TaskOutput::handle_task_result(
                        main_task(p3, sx, rx_cmd).await,
                        "main".to_owned(),
                    );
                    log::info!("I will continue running though. Try 'nsproxy -c reload'");
                });
                if let Some(cb) = rx.recv().await {
                    log::info!("Abort main task");
                    pid_wait.kill_all().await;
                    h.abort(); // drops all things.
                    cback = Some(cb);
                } else {
                    break;
                }
            }
            Ok(())
        });
        let k: Arc<Mutex<Option<UnboundedSender<ToServer>>>> = Arc::new(Mutex::new(None));
        let k2 = k.clone();
        tokio::spawn(async move {
            while let Some(sx) = rx_main.recv().await {
                let mut x = k2.lock().await;
                let _ = x.insert(sx);
            }
        });

        loop {
            let (us, _anon) = sock.accept().await?;
            tokio::spawn(Self::handle_conn(us, restart.clone(), k.clone()));
        }
        Ok(())
    }
    async fn handle_conn(
        us: UnixStream,
        restart: mpsc::Sender<oneshot::Sender<()>>,
        sx_main: Arc<Mutex<Option<UnboundedSender<ToServer>>>>,
    ) -> Result<()> {
        let mut f: Framed<UnixStream, LengthDelimitedCodec> =
            Framed::new(us, LengthDelimitedCodec::new());

        while let Some(by) = f.next().await {
            let by = by?;
            let pa: ToServer = util::from_vec_internal(&by)?;
            let re: ToClient;
            match &pa {
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
                ToServer::GC(_) => {
                    let k = sx_main.lock().await;
                    if let Some(ref x) = *k {
                        match x.send(pa) {
                            Result::Ok(_) => re = ToClient::GCed,
                            Err(_) => {
                                log::error!("Main_task isn't running");
                                re = ToClient::Fail;
                            }
                        }
                    } else {
                        re = ToClient::Fail;
                    }
                }
            };
            let by = util::to_vec_internal(&re)?;
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
        let by: Bytes = util::to_vec_internal(&r)?.into();
        self.f.send(by).await?;
        let res = self
            .f
            .next()
            .await
            .ok_or(anyhow!("client: conn closed"))??;
        let res: ToClient = util::from_vec_internal(&res)?;
        Ok(res)
    }
}

use crate::util::error::DevianceError;
use crate::util::{Awaitor, TaskOutput};
use crate::watcher::{FlatpakWatcher, MainEvent, Watcher};
use anyhow::{anyhow, bail, Ok};
use futures::{SinkExt, StreamExt};

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

use crate::data::*;
use crate::netlink::*;

async fn main_task(
    paths: Arc<ConfPaths>,
    pid_wait: UnboundedSender<PidOp>,
    mut cmd: UnboundedReceiver<ToServer>,
) -> Result<()> {
    // IP addresses etc. are fixed by putting derivation in the state file
    // Applying a SubjectInfo should work regardless how messed up the user's system state is.
    // Therefore all tasks may be aborted
    let state_r = NetnspState::load(paths.clone()).await;
    let mut state: NetnspState = match state_r {
        Result::Ok(e) => e,
        Err(e) => {
            bail!(e.context("There may be an error in your configuration or state files"));
        }
    };
    state.load_ids();
    let mut dae = Awaitor::new();
    let ctx = TaskCtx {
        dae: dae.sender.clone(),
        pid: pid_wait,
    };

    let mn: MultiNS = MultiNS::new(paths, ctx.clone()).await?;
    mn.init_current().await?;
    state.derivative.update_nsid().await?;
    state.derive_named_all().await?;
    state.dump().await?;
    // All named are derived and NSes are present.
    state.flatpak_ensure()?;

    state.resume(&mn, ctx.clone()).await?;
    state.dump().await?;

    let (sx, rx) = unbounded_channel();
    let flp = FlatpakWatcher::new(sx.clone());
    let (t, _) = TaskOutput::immediately(Box::pin(flp.daemon()), "flatpak-watcher".to_owned());
    ctx.dae.send(t).unwrap();
    let sxx = sx.clone();
    let (t, _) = TaskOutput::immediately(
        Box::pin(async move {
            while let Some(c) = cmd.recv().await {
                sx.send(MainEvent::Command(c)).unwrap();
            }
            Ok(())
        }),
        "command-to-watcher".to_owned(),
    );
    ctx.dae.send(t).unwrap();

    let (t, _) = TaskOutput::immediately(
        Box::pin(event_handler(rx, state, mn, sxx, ctx.clone())),
        "event-handler".to_owned(),
    );
    ctx.dae.send(t).unwrap();
    // finally. wait on all tasks.
    log::info!("wait on all tasks");
    dae.wait().await?;

    Ok(())
}

async fn event_handler(
    mut rx: UnboundedReceiver<MainEvent>,
    mut state: NetnspState,
    mut mn: MultiNS,
    sx: UnboundedSender<MainEvent>,
    ctx: TaskCtx,
) -> Result<()> {
    while let Some(ev) = rx.recv().await {
        match ev {
            MainEvent::Flatpak(fp) => {
                match state.derive_flatpak(fp.clone()).await? {
                    DeriveRes::New => {
                        let inf = state.derivative.flatpak.get_mut(&fp.pid).ok_or(DevianceError)?;
                        let pf = PidAwaiter::wait(fp.pid);
                        if let Some(pf) = pf {
                            let s2 = sx.clone();
                            let (t, _) = TaskOutput::immediately(
                                Box::pin(async move {
                                    pf.await?;
                                    s2.send(MainEvent::SubjectExpire(SubjectKey::Flatpak(fp.pid)))
                                        .unwrap();
                                    // even if flatpak exits right now it has to finish this iteration first.
                                    Ok(())
                                }),
                                "flatpak-pidfd-".to_owned() + &fp.pid.0.to_string(),
                            );
                            ctx.dae.send(t).unwrap();
                            inf.ns.connect(&mn).await?;
                            let inf = state.derivative.flatpak.get(&fp.pid).ok_or(DevianceError)?;
                            inf.apply_veths(&mn, &state.derivative, &mut state.nft)
                                .await?;
                            state.nft.execute()?;
                            state.dump().await?;

                            let inf = state.derivative.flatpak.get_mut(&fp.pid).unwrap();
                            // start all daemons
                            inf.run(&mn.procs).await?;
                        }
                        // else, process exited early
                    }
                    _ => (),
                }
            } // TODO: watch for other kinds, bwrap, unshared.
            MainEvent::Command(cmd) => match cmd {
                ToServer::GC(p) => {
                    if let Some(k) = state.derivative.named_ns.get(&p) {
                        k.garbage_collect(&mn, &state.derivative, &ctx).await?;
                        state.derivative.named_ns.remove(&p);
                        state.dump().await?;
                    } else {
                        log::error!("Attempt to GC; {p:?} doesn't exist");
                    }
                }
                _ => (),
            },
            MainEvent::SubjectExpire(sk) => match sk {
                SubjectKey::Flatpak(fp) => {
                    let si = state.derivative.flatpak.remove(&fp);
                    if let Some(si) = si {
                        si.garbage_collect(&mn, &state.derivative, &ctx).await?;
                        ctx.pid.send(PidOp::Kill(si.ns.clone())).with_context(|| {
                            format!(
                                "trying to kill the processes of {}, sending Pid failed",
                                si.ns
                            )
                        })?;
                        state.dump().await?;
                    } else {
                        // it prolly has been GCed
                    }
                }
                _ => unimplemented!(),
            },
        }
    }
    Ok(())
}
