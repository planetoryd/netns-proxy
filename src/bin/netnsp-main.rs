#![feature(setgroups)]
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use flexi_logger::FileSpec;
use netns_proxy::{enter_ns_by_pid, self_netns_identify, NETNS_PATH, enter_ns_by_name};
use nix::{
    sched::CloneFlags,
    unistd::{getppid, getresuid},
};
use std::{
    env,
    ops::Deref,
    os::{fd::AsRawFd, unix::process::CommandExt},
    path::Path,
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    task::JoinSet,
};

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
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut set = JoinSet::new();

    // this is very safe
    // unsafe {
    //     netns_proxy::logger = Some(
    //         flexi_logger::Logger::try_with_env_or_str("error,netnsp_main=debug,netns_proxy=debug")
    //             .unwrap()
    //             .log_to_file(FileSpec::default())
    //             .duplicate_to_stdout(flexi_logger::Duplicate::All)
    //             .start()
    //             .unwrap(),
    //     );
    // }

    unsafe {
        netns_proxy::logger = Some(
            flexi_logger::Logger::try_with_env_or_str("error,netnsp_main=debug,netns_proxy=debug")
                .unwrap()
                .log_to_stdout()
                .start()
                .unwrap(),
        );
    }
    let cli = Cli::parse();

    tokio::spawn(async {
        tokio::signal::ctrl_c().await.unwrap();
        log::warn!("Received Ctrl+C");
        let i = nix::unistd::getpgrp();
        // TODO: kill all sub processes in case of crash
    });

    match cli.command {
        Some(Commands::Stop {}) => {
            netns_proxy::kill_suspected();
        }
        Some(Commands::Id {}) => {
            let got_ns = self_netns_identify()
                .await?
                .ok_or_else(|| anyhow!("no matches under the given netns directory"))?;
            println!("{:?}", got_ns);
        }
        Some(Commands::Exec { mut cmd, ns, pid }) => {
            let path = "./netnsp.json";
            let mut file = File::open(path).await?;
            let mut contents = String::new();
            file.read_to_string(&mut contents).await?;

            let config: netns_proxy::ConfigRes = serde_json::from_str(&contents)?;
            let curr_inode = netns_proxy::get_self_netns_inode()?;
            let self_pid = nix::unistd::getpid();

            let parent_pid = nix::unistd::getppid();
            let parent_process = match Process::new(parent_pid.into()) {
                Ok(process) => process,
                Err(_) => panic!("cannot access parent process"),
            };
            let puid = parent_process.status()?.euid;
            let pgid = parent_process.status()?.egid;

            if curr_inode != config.root_inode {
                log::error!("ACCESS DENIED");
                std::process::exit(1);
            }

            if cmd.is_none() {
                cmd = Some("fish".to_owned());
            }
            log::info!(
                "uid: {:?}, gid: {:?}, pid: {:?}",
                nix::unistd::getresuid()?,
                nix::unistd::getresgid()?,
                self_pid
            );
            if let Some(pi) = pid {
                enter_ns_by_pid(pi)?;
            } else {
                enter_ns_by_name(&ns).await?;
            }

            netns_proxy::drop_privs1(
                nix::unistd::Gid::from_raw(pgid),
                nix::unistd::Uid::from_raw(puid),
            )?;

            let proc = std::process::Command::new(cmd.unwrap());

            // proc.args(&[""]);

            let mut cmd_async: Command = proc.into();
            let mut t = cmd_async.spawn()?;
            t.wait().await?;
        }
        None => {
            let path = Path::new("./secret.json");
            let mut file = File::open(path).await?;
            let mut contents = String::new();
            file.read_to_string(&mut contents).await?;

            let secret: netns_proxy::Secret = serde_json::from_str(&contents)?;
            let ns_names: Vec<String> = secret.params.into_keys().collect();
            let ns_names1 = ns_names.iter().map(|s| s.as_str()).collect::<Vec<&str>>();

            match netns_proxy::config_network(ns_names.clone()).await {
                Ok(r) => {
                    let serialized = serde_json::to_string_pretty(&r)?;

                    let mut file = tokio::fs::File::create("./netnsp.json").await?;
                    log::info!("config result generated in ./netnsp.json. note that this file is freshly generated each run.");

                    file.write_all(serialized.as_bytes()).await?;

                    let mut sp = env::current_exe()?;
                    sp.pop();
                    sp.push("netnsp-sub");
                    let sp1 = sp.into_os_string();
                    // start daemons
                    // let pid = nix::unistd::getpid();

                    let parent_pid = nix::unistd::getppid();
                    let parent_process = match Process::new(parent_pid.into()) {
                        Ok(process) => process,
                        Err(_) => panic!("cannot access parent process"),
                    };
                    let puid = parent_process.status()?.euid;
                    let pgid = parent_process.status()?.egid;

                    let ns_names2 = ns_names.clone();
                    for name in ns_names2 {
                        let spx = sp1.clone();

                        set.spawn(async move {
                            let spx = spx.clone();

                            log::info!("wait on {:?}, ns {}", spx, &name);

                            let mut cmd = Command::new(spx.clone())
                                .arg(&name)
                                .arg(puid.to_string())
                                .arg(pgid.to_string())
                                .uid(0)
                                .spawn()
                                .unwrap();
                            let task = cmd.wait();
                            let res = task.await;
                            (name, res)
                        });
                    }

                    while let Some(res) = set.join_next().await {
                        let idx = res.unwrap();
                        log::error!(
                            "{} exited, with {:?}. re-cap, {}/{} running",
                            idx.0,
                            idx.1,
                            set.len(),
                            ns_names1.len()
                        );
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
    }

    Ok(())
}
