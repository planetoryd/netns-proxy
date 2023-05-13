#![feature(setgroups)]
use clap::{Parser, Subcommand};
use flexi_logger::FileSpec;
use libc;
use netns_proxy::TASKS;
use nix::{
    sched::CloneFlags,
    unistd::{getppid, getresuid},
};
use std::{
    env,
    ops::Deref,
    os::{fd::AsRawFd, unix::process::CommandExt},
};
use sysinfo::{Gid, Pid, PidExt, ProcessExt, System, SystemExt};
use tokio::{
    io::AsyncWriteExt,
    process::{Child, Command},
    task::JoinSet,
};

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
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
        // for some obscure reason the sigterm is only sent to the parent when you hit ctrl c
        // do a clean exit
        Command::new("pkill")
            .arg("-c")
            .arg("-g")
            .arg(i.as_raw().to_string())
            .spawn()
            .unwrap()
            .wait()
            .await
            .unwrap();
    });

    match cli.command {
        Some(Commands::Stop {}) => {
            netns_proxy::kill_suspected();
        }
        Some(Commands::Exec { mut cmd, ns }) => {
            let got_ns_ = String::from_utf8(
                Command::new("ip")
                    .args(["netns", "identify"])
                    .arg(sysinfo::get_current_pid()?.to_string())
                    .output()
                    .await?
                    .stdout,
            )?;
            let got_ns = got_ns_.trim();
            log::info!("current ns {}", got_ns);

            if !got_ns.is_empty() {
                log::error!("ACCESS DENIED");
                std::process::exit(1);
            }

            if cmd.is_none() {
                cmd = Some("fish".to_owned());
            }
            let sysi = System::new_all();
            let par = sysi
                .process(sysinfo::Pid::from_u32(getppid().as_raw() as u32))
                .unwrap();
            let puid = par.user_id().unwrap().deref();
            let pgid1 = par.group_id().unwrap();
            let pgid = pgid1.deref();
            nix::sched::setns(
                netns_proxy::nsfd(&ns)?.as_raw_fd(),
                CloneFlags::CLONE_NEWNET,
            )?;

            let got_ns_ = String::from_utf8(
                Command::new("ip")
                    .args(["netns", "identify"])
                    .arg(sysinfo::get_current_pid()?.to_string())
                    .output()
                    .await?
                    .stdout,
            )?;
            let got_ns = got_ns_.trim();
            log::info!("current ns {}", got_ns);

            if got_ns != ns {
                log::error!("entering netns failed, {} != {}", got_ns, ns);
                std::process::exit(1);
            }

            netns_proxy::drop_privs1(
                nix::unistd::Gid::from_raw(*pgid),
                nix::unistd::Uid::from_raw(*puid),
            )
            .await?;

            let mut proc = std::process::Command::new(cmd.unwrap());

            // proc.args(&[""]);

            let mut cmd_async: Command = proc.into();
            let mut t = cmd_async.spawn()?;
            t.wait().await?;
        }
        None => match netns_proxy::config_network().await {
            Ok(r) => {
                let serialized = serde_json::to_string_pretty(&r)?;

                let mut file = tokio::fs::File::create("./netnsp.json").await?;
                log::info!("result generated in json");

                file.write_all(serialized.as_bytes()).await?;

                let mut sp = env::current_exe()?;
                sp.pop();
                sp.push("netnsp-sub");
                let sp1 = sp.into_os_string();
                // start daemons

                for ns in netns_proxy::TASKS {
                    let spx = sp1.clone();

                    set.spawn(async move {
                        let spx = spx.clone();
                        log::info!("wait on {:?} {ns}", spx);
                        let mut cmd = Command::new(spx.clone()).arg(ns).spawn().unwrap();
                        let task = cmd.wait();
                        let res = task.await;
                        (ns, res)
                    });
                }

                while let Some(res) = set.join_next().await {
                    let idx = res.unwrap();
                    log::error!(
                        "{} exited, with {:?}. re-cap, {}/{} running",
                        idx.0,
                        idx.1,
                        set.len(),
                        TASKS.len()
                    );
                }
            }
            Err(x) => {
                log::error!("config network failed {x}")
            }
        },
    }

    Ok(())
}
