#![feature(setgroups)]
use anyhow::{anyhow, Ok, Result};
use clap::{Parser, Subcommand};

use netns_proxy::sub::{NetnspSubCaller, NsubRPC, NsubService};
use netns_proxy::util::error::DevianceError;
use netns_proxy::util::ns::{
    self, enter_ns_by_name, enter_ns_by_pid, get_self_netns_inode, self_netns_identify,
};
use netns_proxy::util::{open_wo_cloexec, Daemons, TaskOutput};
use netns_proxy::util::{perms::*, DaemonSender};
use netns_proxy::watcher::{FlatpakWatcher, Watcher, WatcherEvent};
use tarpc::server::{BaseChannel, Channel};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

use std::collections::HashSet;
use std::env::Args;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::{env, path::PathBuf};
use tokio::{fs::File, io::AsyncReadExt, process::Command, task::JoinSet};

use dashmap::DashMap;
use netns_proxy::data::*;
use netns_proxy::netlink::*;
use netns_proxy::sub;
use netns_proxy::watcher;
use procfs::process::Process;
use tarpc::serde_transport::unix::Incoming;
use tarpc::tokio_serde::formats::{Bincode, SymmetricalBincode};
use tarpc::{context, serde_transport};

#[derive(Parser)]
#[command(
    author,
    version,
    about = "utility for using netns as socks proxy containers.",
    long_about = "utility for using netns as socks proxy containers. may need root. \n example commandline `RUST_LOG=error,netns_proxy=info sudo -E netns-proxy`, errors may be fine"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// stops all suspected netns-proxy processes/daemons
    Stop {},
    /// exec in the netns, with EVERYTHING else untampered. requires SUID
    Exec {
        #[arg(short, long)]
        ns: String,
        #[arg(short, long)]
        cmd: Option<String>,
        #[arg(short, long)]
        pid: Option<i32>,
    },
    Id {},
    Clean {},
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    flexi_logger::Logger::try_with_env_or_str(
        "debug,netnsp_main=trace,netns_proxy=trace,netnsp_sub=trace,netlink_proto=info,rustables=info",
    )
    .unwrap()
    .log_to_stdout()
    .start()?;

    // XXX: polymorphic binary
    if args.len() == 2 {
        // assumed this is the RPC sub
        let path: Result<PathBuf, _> = args[1].parse();
        if path.is_ok() {
            let sock_path = path.unwrap();
            let conn =
                serde_transport::unix::connect(sock_path.as_path(), Bincode::default).await?;
            let b = BaseChannel::with_defaults(conn);
            b.execute(NsubRPC.serve()).await;
            return Ok(());
        }
    }

    let cli = Cli::parse();

    tokio::spawn(async {
        tokio::signal::ctrl_c().await.unwrap();
        log::warn!("Received Ctrl+C");
        std::process::exit(0);
        // let i = nix::unistd::getpgrp();
        // TODO: kill all sub processes in case of crash
    });

    match cli.command {
        Some(Commands::Stop {}) => {
            netns_proxy::util::kill_suspected()?;
        }
        Some(Commands::Id {}) => {
            let got_ns = self_netns_identify()
                .await?
                .ok_or_else(|| anyhow!("no matches under the given netns directory"))?;
            println!("{:?}", got_ns);
        }
        Some(Commands::Clean {}) => {
            // It is hard to steer the system config state into the desired state
            // Things get messed up easily.
            let nl = NetlinkConn::new_in_current_ns();
            let state = NetnspState::load(Default::default()).await?;
            state.clean_net(&nl).await?;
            log::info!("cleaned");
            // The config process resets a lot even though it's not an explicit clean
        }
        Some(Commands::Exec { mut cmd, ns, pid }) => {
            let state = NetnspState::load(Default::default()).await?;
            let curr_inode = NSID::root()?;
            let (u, g) = get_non_priv_user(None, None, None, None)?;

            if curr_inode != state.derivative.root_ns {
                log::error!("ACCESS DENIED");
                std::process::exit(1);
            }

            if cmd.is_none() {
                cmd = Some("fish".to_owned());
            }

            if let Some(pi) = pid {
                let n = NSID::from_pid(Pid(pi.try_into()?))?;
                n.open().await?.enter()?;
            } else {
                let n = NSID::from_name(ProfileName(ns)).await?;
                n.open().await?.enter()?;
            }

            drop_privs_id(nix::unistd::Gid::from_raw(u), nix::unistd::Uid::from_raw(g))?;

            let proc = std::process::Command::new(cmd.unwrap());
            let mut cmd_async: Command = proc.into();
            let mut t = cmd_async.spawn()?;
            t.wait().await?;
        }
        None => {
            // Run as a daemon
            let paths = Arc::new(ConfPaths::default());
            let mut mn: MultiNS = MultiNS::new(paths).await?;
            let mut state: NetnspState = NetnspState::load(Default::default()).await?;
            let mut dae = Daemons::new();
            state.derive_all_named().await?;
            state.initial_nft().await?;
            state.resume(&mut mn, &dae.sender).await?;

            let (sx, rx) = unbounded_channel();
            let flp = FlatpakWatcher::new(sx.clone());
            let (t, _) = TaskOutput::new(Box::pin(flp.daemon()), "flatpak watcher".to_owned());
            dae.sender.send(t).unwrap();

            let (t, _) = TaskOutput::new(
                Box::pin(event_handler(rx, state, dae.sender.clone(), mn)),
                "event handler".to_owned(),
            );
            dae.sender.send(t).unwrap();
            // finally. wait on all tasks.
            dae.run().await?;
        }
    }

    Ok(())
}

async fn event_handler(
    mut rx: UnboundedReceiver<WatcherEvent>,
    mut state: NetnspState,
    dae: DaemonSender,
    mn: MultiNS,
) -> Result<()> {
    while let Some(ev) = rx.recv().await {
        match ev {
            WatcherEvent::Flatpak(fp) => {
                state.derive_flatpak(fp.clone()).await?;
                let inf = state.derivative.flatpak.get(&fp.pid).ok_or(DevianceError)?;
                inf.apply_veths(&mn, &state.derivative).await?;
                // inf.run()
            }
        }
    }
    Ok(())
}
