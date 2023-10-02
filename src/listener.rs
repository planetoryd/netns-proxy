use crate::tasks::*;
use std::{
    path::{Path, PathBuf},
    result::Result as SResult, marker, pin::Pin,
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
use nix::sys::signal::Signal::SIGTERM;
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
};
use tokio_send_fd::SendFd;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use fixed_map::{Key as FKey, Map as FMap};

use std::marker::Send as MSend;

use crate::{
    id_alloc::{self, IDAlloc},
    util::{from_vec_internal, to_vec_internal, wait_pid, AbortOnDropTokio},
};

pub struct Listener {
    conf: ProgramConfig<{ Validate::Done }>,
    tasks: ServerTasks,
    serve_loop: Option<AbortHandle>,
    cb_loop: Option<AbortHandle>,
    sx: UnboundedSender<BoxFunc>,
}

impl Listener {
    #[async_recursion(Sync)]
    async fn sock_accept(sock: UnixListener) -> Result<FutOut> {
        // when the accept() is not being awaited, clients are just blocked.
        if let Result::Ok((ux, _anon)) = sock.accept().await {
            let fds = ux.recv_stream().await?;
            let cred = fds.peer_cred()?;
            let f: Framed<UnixStream, LengthDelimitedCodec> =
                Framed::new(ux, LengthDelimitedCodec::new());
            let f = FramedUS(f);
            let mut k = Server(f, FDStream(fds));
            let id = try_session(
                &mut k,
                async move |proto: <SubIdentify<'_, Client> as PartialDual<
                    '_,
                    Client,
                    Server,
                >>::Dual<End<'_, _>>| { proto.receive().await },
            )
            .await?;
            Ok(Some(Box::new(move |state: &mut Listener, set: FutSetW| {
                // schedule the task to wait for new conns.
                match id {
                    Identify::Control(_) => {
                        let f = Self::handle_ctrl(k, state.sx.clone());
                        ignored_abortable!(Box::pin(async move {
                            f.await?;
                            Ok(None)
                        }) as AbortaFut, set.0);
                    }  
                    Identify::Sub(_) => {
                        todo!()
                    }
                }
                add_abortable_some!(Self::sock_accept(sock), state.serve_loop, set.0);
                Ok(())
            }) as BoxFunc))
        } else {
            Ok(None)
        }
    }
    /// Handle control connection
    async fn handle_ctrl(mut server: Server, mut main: IntClient) -> Result<()> {
        try_session(
            &mut server,
            async move |mut se: <Ctrl<'_, Client> as FullDual<Client, Server>>::Dual| loop {
                match se.branch().await? {
                    CtrlMsg::SubjectMsg(k) => match k {
                        SubjectMsg::GC(k) => {
                            se = se.next(&k);
                            boxfn!(main, state, set, {
                                let sname = k.0;
                                let skey = state
                                    .tasks
                                    .subject_names
                                    .get_by_right(&sname)
                                    .ok_or(InputError)?;
                                state
                                    .tasks
                                    .subject
                                    .get_mut(skey)
                                    .ok_or(InvariantBreach)?
                                    .kill()?;
                                state.tasks.subject.remove(skey);
                                
                            });
                        }
                        SubjectMsg::Initiate(k) => {
                            let mut recv = se.next(&k);
                            let (dev, cont) = recv.receive().await?;
                            let (ns, cont) = cont.receive().await?;
                            boxfn!(main, state, set, {
                                let sname = k.0;
                                let id = state.tasks.sids.alloc_or()?;
                                let skey = SubjectKey(id);
                                state.tasks.subject_names.insert(skey.clone(), sname.clone());
                                state
                                    .tasks
                                    .subject
                                    .get_mut(&skey)
                                    .ok_or(InvariantBreach)?
                                    .run_tuntap(dev, k.1.tun2proxy, ns, &state.conf, &skey, |p| {
                                        abortable_spawn(
                                            Box::pin(async {
                                                // error in PidFuture causes the entire program to crash
                                                let rx = p.await?;
                           
                                                Ok(Some(Box::new(move |state: &mut Listener, set: FutSetW| {
                                                    if !rx.success() {
                                                        log::error!("Process Tun2proxy of {} exited with {}", sname, rx);
                                                    }
                                                    Ok(())
                                                }) as BoxFunc))
                                            }),
                                            set,
                                        )
                                    })?;
                            });
                            se = cont;
                        }
                    },
                    CtrlMsg::ProgramConfig(c) => {
                        se = se.next(&c);
                        todo!();
                        boxfn!(main, state, set, {

                            // let conf: ProgramConfig<Validated> = c.try_into()?;
                            // state.conf = conf;
                        });
                    }
                }
            },
        )
        .await
    }
    #[async_recursion(Sync)]
    async fn handle_fn(mut rx: UnboundedReceiver<BoxFunc>) -> Result<FutOut> {
        let func = rx.next().await.unwrap();
        Ok(Some(Box::new(move |state: &mut Listener, set: FutSetW| {
            // Execute task on the main thread
            func(state, set)?;
            add_abortable_some!(Self::handle_fn(rx), state.cb_loop, set.0);
            Ok(())
        }) as BoxFunc))
    }
    async fn run(mut self) -> Result<()> {
        let sock = UnixListener::bind(&self.conf.server)?;
        let mut set = FutSet::new();
        let (sx, rx) = mpsc::unbounded();
        add_abortable_some!(Self::handle_fn(rx), self.cb_loop, set);
        add_abortable_some!(Self::sock_accept(sock), self.serve_loop, set);
        while let Some(fut_res) = set.next().await {
            match fut_res {
                Err(Aborted) => {}
                Result::Ok(fut_res) => {
                    if let Some(func) = fut_res? {
                        // every future spawned on the set can run a function on this thread
                        func(&mut self, FutSetW(&set))?;
                    }
                }
            }
        }
        Ok(())
    }
}

