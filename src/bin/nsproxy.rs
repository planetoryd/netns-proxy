#![feature(setgroups)]
use anyhow::{anyhow, Ok, Result};
use clap::{Parser, Subcommand};

use netns_proxy::sub::{NetnspSub, NetnspSubCaller};
use netns_proxy::util::get_non_priv_user;
use netns_proxy::util::open_wo_cloexec;

use std::os::fd::AsRawFd;
use std::{env, path::PathBuf};
use tokio::{fs::File, io::AsyncReadExt, process::Command, task::JoinSet};

use netns_proxy::configurer::*;
use netns_proxy::data::*;

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
    /// configure each profile as a persistent net namespace. pre means before using apps.
    #[arg(short, long)]
    pre: bool,
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
    let mut set = JoinSet::new();

    flexi_logger::Logger::try_with_env_or_str(
        "debug,netnsp_main=trace,netns_proxy=trace,netnsp_sub=trace,netlink_proto=info,rustables=info",
    )
    .unwrap()
    .log_to_stdout()
    .start()
    .unwrap();
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
            let configurer = Configurer::new();
            let state = NetnspState::load(Default::default()).await?;
            state.clean_net(&configurer).await?;
            log::info!("cleaned");
            // The config process resets a lot even though it's not an explicit clean
        }
        Some(Commands::Exec { mut cmd, ns, pid }) => {
            let state = NetnspState::load(Default::default()).await?;
            let curr_inode = get_self_netns_inode()?;
            let (u, g) = get_non_priv_user(None, None, None, None)?;

            if curr_inode != state.res.root_inode {
                log::error!("ACCESS DENIED");
                std::process::exit(1);
            }

            if cmd.is_none() {
                cmd = Some("fish".to_owned());
            }

            if let Some(pi) = pid {
                enter_ns_by_pid(pi)?;
            } else {
                enter_ns_by_name(&ns).await?;
            }

            drop_privs1(nix::unistd::Gid::from_raw(u), nix::unistd::Uid::from_raw(g))?;

            let proc = std::process::Command::new(cmd.unwrap());
            let mut cmd_async: Command = proc.into();
            let mut t = cmd_async.spawn()?;
            t.wait().await?;
        }
        None => {
            // Run as a daemon
            use netns_proxy::util;
            use netns_proxy::watcher;
            let mut state = NetnspState::load(Default::default()).await?;

            let configrer = Configurer::new();

            if cli.pre {
                match config_network(&configrer, &mut state).await {
                    Result::Ok(_) => {
                        state.dump().await?;
                        // start daemons
                        let (puid, pgid) = get_non_priv_user(None, None, None, None)?;
                        for name in state.profile_names() {

                            set.spawn(async move {
                                let mut path = PathBuf::from(NETNS_PATH);
                                path.push(name.clone());

                                let netns_sub: NetnspSubCaller = NetnspSubCaller::default();
                                let nsfile = open_wo_cloexec(&path);
                                let res = netns_sub
                                    .inner_daemon(
                                        name.clone(),
                                        puid.into(),
                                        pgid.into(),
                                        nsfile.as_raw_fd(),
                                        None,
                                    )
                                    .await;

                                (name, res)
                            });
                        }
                    }
                    Err(x) => {
                        log::error!("There is irrecoverable error in configuring. Try reseting the state, like rebooting");
                        let euid = nix::unistd::geteuid();
                        if !euid.is_root() {
                            // the only way of checking if we have the perms is to try. so no mandating root.
                            log::warn!("Your uid is {euid}. Do you have enough perms")
                        }
                        return Err(x);
                    }
                }
            }

            let hold = state.profile_names();
            let watcher = watcher::WatcherState::create(configrer, state).await?;
            let w_t = watcher.start();

            let persis_ns = async move {
                let ns_names1 = util::convert_strings_to_strs(&hold);
                while let Some(res) = set.join_next().await {
                    let idx = res.unwrap();
                    log::warn!(
                        "{} exited, with {:?}. re-cap, {}/{} running",
                        idx.0,
                        idx.1,
                        set.len(),
                        ns_names1.len()
                    );
                }
                Ok(())
            };
            // exit when either of them exits, because it shouldn't.
            let _ = tokio::select! {
                r = tokio::spawn(w_t) => {
                    log::warn!("watcher detached");
                    r?
                }
                r = tokio::spawn(persis_ns) => {
                    log::warn!("persis_ns detached");
                    r?
                }
            }?;
            // XXX try to catch all the results so we don't get baffled when things happen. rust analyzer doesn't warn about it in macros.

            log::info!("exit");
        }
    }

    Ok(())
}
