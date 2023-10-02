#![feature(setgroups)]
#![feature(decl_macro)]
#![feature(associated_type_bounds)]
#![allow(unused)]

use anyhow::{anyhow, bail, ensure, Ok, Result};
use clap::{Parser, Subcommand};

use futures::{Future, SinkExt, StreamExt};
use netlink_ops::netns::{Fcntl, NSCreate, NSIDFrom, Netns, NsFile, Pid};
use netns_proxy::tasks::{Client, FDStream, TUN2Proxy};
use netns_proxy::tun2proxy::tuntap;
use nix::sched::CloneFlags;
use nix::unistd::{geteuid, Gid, Uid};

use netns_proxy::util::{ns::*, perms::*, from_vec_internal};
use std::env;
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::process::Command;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "utility for using netns as socks proxy containers, and other related tasks",
    long_about = "utility for using netns as socks proxy containers, and other related tasks. It can run as a SUID daemon, a cli controller, or a standalone utility"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Exec in the netns, with everything else untampered. You may run this command with, or without SUID, or with sudo.
    Exec {
        /// Enter a persistent NS.
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
    Tuntap {
        dev: RawFd,
        conf: RawFd,
        /// Can be PIDFD, or Netns
        ns: RawFd,
    },
    Sub {
        /// RPC socket
        sock: PathBuf,
        /// NS to enter
        ns: RawFd,
    },
}

fn main() -> Result<()> {
    let e = env_logger::Env::new().default_filter_or("warn,netns_proxy=debug,nsproxy=debug");
    env_logger::init_from_env(e);
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Sub { sock, ns }) => {
            let fd: File = unsafe { File::from_raw_fd(ns) };
            let ns = NsFile(fd);
            ns.set_cloexec()?;
            ns.enter_net()?;
            // NS must be entered before tokio starts, because setns doesn't affect existing threads
            async_run(async move {
                let c = Client::connect(&sock).await?;
                unimplemented!();
                Ok(())
            })
        }
        Some(Commands::Tuntap { dev, conf, ns }) => {
            ns.set_cloexec()?;
            conf.set_cloexec()?;
            dev.set_cloexec()?;
            let ns: File = unsafe { File::from_raw_fd(ns) };
            let ns = NsFile(ns);
            ns.enter_ner_user()?;
            let mut conf: File = unsafe { File::from_raw_fd(conf) };
            let mut buf = Default::default();
            conf.read_to_end(&mut buf)?;
            let conf: TUN2Proxy = from_vec_internal(&buf)?;
            tuntap(conf, dev)?;
            Ok(())
        }
        Some(Commands::Id {}) => {
            async_run(async move {
                let ns = self_netns_identify()
                    .await?
                    .ok_or_else(|| anyhow!("No matches under the given netns directory. It means it's not a persistent, named NS. "))?;
                println!("{:?}", ns);
                Ok(())
            })
        }
        Some(Commands::Exec {
            mut cmd,
            ns,
            pid,
            dbg,
            new,
            su,
        }) => {
            let current_ns = NSIDFrom::Thread.create_sync(NSCreate::empty())?;
            let (u, g) = get_non_priv_user(None, None, None, None)?;
            if cmd.is_none() {
                cmd = Some(
                    env::var("SHELL").map_err(|x| anyhow!("argument cmd not provided; {}", x))?,
                );
            }
            if ns.is_some() && pid.is_some() {
                bail!("You can't specify both PID and NS");
            }
            if let Some(ns) = ns {
                let n = NSIDFrom::Named(ns);
                n.open_sync()?.enter_net()?;
            } else if let Some(pi) = pid {
                let n = NSIDFrom::Pid(Pid(pi.try_into()?));
                n.open_sync()?.enter_ner_user()?;
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
                drop_privs_id(Gid::from_raw(u), Uid::from_raw(g))?;
            }
            // Netns must be entered before the mess of multi threading
            async_run(async move {
                if dbg {
                    let ns = Netns::thread().await?;
                    let euid = geteuid();
                    dbg!(&ns.netlink);
                    let k = netlink_ops::nft::print_all().await;
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
            })
        }
        Some(Commands::GC { ns }) => {
            async_run(async move {
                // send command 
                Ok(())
            })
        }
        None => {
            async_run(async move {
                // start the server

                Ok(())
            })
        }
    }
}

fn async_run(f: impl Future<Output = Result<()>>) -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

fn require_root() {
    let euid = geteuid();
    if euid != 0.into() {
        log::warn!("Not running as root.");
    }
}
