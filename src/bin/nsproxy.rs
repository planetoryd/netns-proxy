#![feature(setgroups)]
#![feature(decl_macro)]
#![feature(associated_type_bounds)]

use anyhow::{anyhow, bail, ensure, Ok, Result};
use clap::{Parser, Subcommand};

use futures::Future;
use netns_proxy::ctrl::{ToClient, ToServer};
use netns_proxy::util::branch_out;
use netns_proxy::util::ns::self_netns_identify;
use netns_proxy::util::perms::*;
use nix::sched::CloneFlags;
use nix::unistd::geteuid;

use std::env;
use std::sync::Arc;
use tokio::process::Command;

use netns_proxy::data::*;
use netns_proxy::netlink::*;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "utility for using netns as socks proxy containers, and other related tasks",
    long_about = "utility for using netns as socks proxy containers, and other related tasks. It can run as a SUID daemon, a cli controller, or a standalone utility"
)]
struct Cli {
    #[arg(short, long)]
    ctl: bool,
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
        /// Use an empty, new network namespace. This uses syscall unshare, but without the need of sudo.
        #[arg(long)]
        new: bool,
        /// Enter the Net NS of certain process
        #[arg(short, long)]
        pid: Option<i32>,
        /// Print network related info in root ns or the specified NS and exit.
        #[arg(short, long)]
        dbg: bool,
        /// Keep root privileges
        #[arg(short, long)]
        su: bool,
        /// Command to run.
        cmd: Option<String>,
    },
    /// Identify the Netns you are currently in
    Id {},
    /// Clean up changes to the system made according to the state file.
    /// A reboot cleans up everything, though.
    GC {
        /// Enter a persistent NS. Their names are the same as the corresponding profiles'.
        #[arg(short, long)]
        ns: String,
    },
    // Control commands
    /// Reload config by the daemon
    Reload,
}

fn main() -> Result<()> {
    let e = env_logger::Env::new().default_filter_or("warn,netns_proxy=debug,nsproxy=debug");
    env_logger::init_from_env(e);

    // polymorphic binary
    branch_out()?;

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
            async_run(async move {
                let got_ns = self_netns_identify()
                    .await?
                    .ok_or_else(|| anyhow!("No matches under the given netns directory. It means it's not a persistent, named NS. "))?;
                println!("{:?}", got_ns);
                Ok(())
            });
        }
        Some(Commands::Exec {
            mut cmd,
            ns,
            pid,
            dbg,
            new,
            su,
        }) => {
            let state = NetnspState::load_sync(Arc::new(ConfPaths::default()?))?;
            let current_ns = NSIDFrom::Thread.to_id_sync(NSCreate::empty())?;
            let (u, g) = get_non_priv_user(None, None, None, None)?;
            if &current_ns
                != state
                    .derivative
                    .root_ns
                    .as_ref()
                    .ok_or(anyhow!("No root_ns specified in derived file"))?
            {
                log::error!("Access denied. It's not allowed to exec from a non-root NS which is specified in the state file.");
                log::info!(
                    "current {:?}, saved {:?}",
                    current_ns,
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
                let n = NSIDFrom::Named(ProfileName(ns.clone()));
                n.open_sync()?.enter()?;
            } else if let Some(pi) = pid {
                let n = NSIDFrom::Pid(Pid(pi.try_into()?));
                n.open_sync()?.enter()?;
            } else {
                if dbg {
                    log::info!("Will not change NS");
                } else if new {
                    nix::sched::unshare(CloneFlags::CLONE_NEWNET)?;
                } else {
                    bail!("use --ns or --pid to specify the network namespace.");
                }
            };
            if !dbg && !su {
                drop_privs_id(nix::unistd::Gid::from_raw(u), nix::unistd::Uid::from_raw(g))?;
            }
            // Netns must be entered before the mess of multi threading
            async_run(async move {
                if dbg {
                    let ns = Netns::thread().await?;
                    dbg!(&ns.netlink);
                    let k = netns_proxy::nft::print_all().await;
                    if k.is_err() {
                        log::error!("{:?}", k);
                        if euid != 0.into() {
                            log::warn!("You are not running as root. ");
                        }
                    }
                } else {
                    let proc = std::process::Command::new(cmd.unwrap());
                    let mut cmd_async: Command = proc.into();
                    let mut t = cmd_async.spawn()?;
                    t.wait().await?;
                }
                Ok(())
            });
        }
        Some(Commands::Reload) => {
            async_run(async move {
                let p = ConfPaths::default()?;
                let p2 = p.sock4ctrl();
                log::warn!("Config will not take effect if there is a corresponding entry in the derivative/state file");
                let mut client = netns_proxy::ctrl::Client::new(p2.as_path()).await?;
                log::info!("connected");
                let res = client.req(ToServer::ReloadConfig).await?;
                ensure!(res == ToClient::ConfigReloaded);
                log::info!("reloaded");
                Ok(())
            });
        }
        Some(Commands::GC { ns }) => {
            async_run(async move {
                let p = ConfPaths::default()?;
                let p2 = p.sock4ctrl();
                let mut client = netns_proxy::ctrl::Client::new(p2.as_path()).await?;
                log::info!("connected");
                let res = client.req(ToServer::GC(ProfileName(ns))).await?;
                ensure!(res == ToClient::GCed);
                log::info!("cleaned");
                Ok(())
            });
        }
        None => {
            if cli.ctl {
                bail!("a command is required.");
            }
            async_run(async move {
                let paths = Arc::new(ConfPaths::default()?);
                // Paths shall not be changed, even across reloads
                let server = netns_proxy::ctrl::Server;
                server.serve(paths.clone()).await?;
                Ok(())
            });
        }
    }

    Ok(())
}

fn async_run(f: impl Future<Output: std::fmt::Debug>) {
    let k = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f);
    println!("Top-process Errored, {:?}", k);
}
