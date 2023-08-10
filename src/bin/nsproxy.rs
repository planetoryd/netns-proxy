#![feature(setgroups)]
use anyhow::{anyhow, bail, Ok, Result};
use clap::{Parser, Subcommand};

use futures::StreamExt;
use netns_proxy::sub::{handle, SubHub, ToSub};
use netns_proxy::util::error::DevianceError;
use netns_proxy::util::ns::{
    self, enter_ns_by_name, enter_ns_by_pid, get_self_netns_inode, self_netns_identify,
};
use netns_proxy::util::{open_wo_cloexec, Awaitor, TaskOutput};
use netns_proxy::util::{perms::*, DaemonSender};
use netns_proxy::watcher::{FlatpakWatcher, Watcher, WatcherEvent};
use nix::unistd::geteuid;
use tokio::net::UnixStream;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio_util::codec::Framed;
use tokio_util::codec::LengthDelimitedCodec;

use std::collections::HashSet;
use std::env::Args;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::Arc;
use std::{env, path::PathBuf};
use tokio::{fs::File, io::AsyncReadExt, process::Command, task::JoinSet};

use dashmap::DashMap;
use netns_proxy::data::*;
use netns_proxy::netlink::*;
use netns_proxy::sub;
use netns_proxy::watcher;
use procfs::process::Process;
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
    /// Stops all suspected netns-proxy processes/daemons
    Stop {},
    /// Exec in the netns, with everything else untampered. requires SUID
    Exec {
        /// Enter a persistent NS. Their names are the same as the corresponding profiles'.
        #[arg(short, long)]
        ns: Option<String>,
        /// Enter the Net NS of certain process
        #[arg(short, long)]
        pid: Option<i32>,
        /// Command to run.
        #[arg(short, long)]
        cmd: Option<String>,
        /// Print network related info in root ns or the specified NS and exit.
        #[arg(short, long)]
        dbg: bool,
    },
    /// Identify the Netns you are currently in
    Id {},
    /// Clean up all possible things in nftables, netlink, netns, left by netns-proxy.
    Clean {},
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let e = env_logger::Env::new().default_filter_or("error,netns_proxy=debug");
    env_logger::init_from_env(e);

    // XXX: polymorphic binary
    if args.len() == 4 {
        use std::fs::File;
        let path: Result<PathBuf, _> = args[2].parse();
        let fd: Result<i32, _> = args[3].parse();
        if path.is_ok() && fd.is_ok() && args[1] == "sub" {
            let fd = fd?;
            let fd: File = unsafe { File::from_raw_fd(fd) };
            let ns = NsFile(fd);
            ns.enter()?;
            return tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let sock_path = path.unwrap();
                    let conn = UnixStream::connect(sock_path.as_path()).await?;
                    let f: Framed<UnixStream, LengthDelimitedCodec> =
                        Framed::new(conn, LengthDelimitedCodec::new());
                    let x = handle(f).await;
                    if let Err(e) = x {
                        log::warn!("Sub exited, {:?}", e);
                    }
                    return Ok(());

                    Ok(())
                });
        }
    }

    let cli = Cli::parse();

    let euid = geteuid();
    if euid != 0.into() {
        log::warn!("Not running as root.");
    }

    match cli.command {
        Some(Commands::Stop {}) => {
            netns_proxy::util::kill_suspected()?;
        }
        Some(Commands::Id {}) => {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let got_ns = self_netns_identify()
                        .await?
                        .ok_or_else(|| anyhow!("No matches under the given netns directory. It means it's not a persistent, named NS. "))?;
                    println!("{:?}", got_ns);
                    Ok(())
                })?;
        }
        Some(Commands::Clean {}) => {
            log::info!("Clean up the changes netns-proxy made");
            // It is hard to steer the system config state into the desired state
            // Things get messed up easily.
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let nl = NetlinkConn::new_in_current_ns();
                    let state = NetnspState::load(Arc::new(ConfPaths::default()?)).await?;
                    state.clean_net(&nl).await?;
                    log::info!("Cleaned");
                    Ok(())
                })?;

            // The config process resets a lot even though it's not an explicit clean
        }
        Some(Commands::Exec {
            mut cmd,
            ns,
            pid,
            dbg,
        }) => {
            let state = NetnspState::load_sync(Arc::new(ConfPaths::default()?))?;
            let curr_ns = NSID::proc()?;
            let (u, g) = get_non_priv_user(None, None, None, None)?;

            if curr_ns != state.derivative.root_ns {
                log::error!("ACCESS DENIED");
                log::info!(
                    "current {:?}, saved {:?}",
                    curr_ns,
                    state.derivative.root_ns
                );
                std::process::exit(1);
            }
            if cmd.is_none() {
                cmd = Some(
                    env::var("SHELL").map_err(|x| anyhow!("argument cmd not provided; {}", x))?,
                );
            }

            if ns.is_some() && pid.is_some() {
                bail!("You can't specify both PID and NS");
            }

            if let Some(ns) = ns {
                let n = NSID::from_name_sync(ProfileName(ns.clone()))?;
                n.open_sync()?.enter()?;
            } else if let Some(pi) = pid {
                let n = NSID::from_pid(Pid(pi.try_into()?))?;
                n.open_sync()?.enter()?;
            } else {
                if dbg {
                    log::info!("Will not change NS");
                } else {
                    bail!("use --ns or --pid to specify the network namespace.");
                }
            };

            if !dbg {
                drop_privs_id(nix::unistd::Gid::from_raw(u), nix::unistd::Uid::from_raw(g))?;
            }
            // Netns must be entered before the mess of multi threading
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    if dbg {
                        let ns = Netns::proc_current().await?;
                        dbg!(&ns.netlink);
                        netns_proxy::nft::print_all()?;
                    } else {
                        let proc = std::process::Command::new(cmd.unwrap());
                        let mut cmd_async: Command = proc.into();
                        let mut t = cmd_async.spawn()?;
                        t.wait().await?;
                    }
                    Ok(())
                })?;
        }
        None => {
            let k =  tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let paths = Arc::new(ConfPaths::default()?);
                    let mut state: NetnspState = NetnspState::load(paths.clone()).await?;

                    if get_self_netns_inode()? != state.derivative.root_ns.inode {
                        bail!("root_ns mismatch. You are running from a different Netns than what was recorded in the Derivative file");
                    }
                    let mut dae = Awaitor::new();
                    let mut mn: MultiNS = MultiNS::new(paths, dae.sender.clone()).await?;

                    mn.proc_current().await?;
                    state.derive_all_named().await?;
                    state.resume(&mut mn, &dae.sender).await?;

                    let (sx, rx) = unbounded_channel();
                    let flp = FlatpakWatcher::new(sx.clone());
                    let (t, _) = TaskOutput::immediately(
                        Box::pin(flp.daemon()),
                        "flatpak-watcher".to_owned(),
                    );
                    dae.sender.send(t).unwrap();

                    let (t, _) = TaskOutput::immediately(
                        Box::pin(event_handler(rx, state, dae.sender.clone(), mn)),
                        "event-handler".to_owned(),
                    );
                    dae.sender.send(t).unwrap();
                    // finally. wait on all tasks.
                    log::info!("wait on all tasks");
                    dae.wait().await?;
                    log::info!("normal exit");
                    Ok(())
                });
            // must manually print it or something wont be displayed
            println!("main-process error, {:?}", k);
        }
    }
    Ok(())
}

async fn event_handler(
    mut rx: UnboundedReceiver<WatcherEvent>,
    mut state: NetnspState,
    dae: DaemonSender,
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
                    inf.run(&dae, &mn.procs).await?;
                } else {
                    log::debug!("Flatpak-watcher: {:?} ignored, no associaed profile", fp);
                }
            } // TODO: watch for other kinds, bwrap, unshared.
        }
    }
    Ok(())
}
