use std::env;

use clap::{Parser, Subcommand};
use flexi_logger::FileSpec;
use netns_proxy::TASKS;
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // this is very safe
    unsafe {
        netns_proxy::logger = Some(
            flexi_logger::Logger::try_with_env_or_str("error,netnsp_main=debug,netns_proxy=debug")
                .unwrap()
                .log_to_file(FileSpec::default())
                .duplicate_to_stdout(flexi_logger::Duplicate::All)
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

    match &cli.command {
        Some(Commands::Stop {}) => {
            // kill_suspected();
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
                // start daemons

                let mut set = JoinSet::new();
                static mut KIDS: Vec<Child> = Vec::new();
                for ns in netns_proxy::TASKS {
                    unsafe {
                        KIDS.push(Command::new(&sp).arg(ns).spawn()?);
                        set.spawn(async move {
                            let res = KIDS.last_mut().unwrap().wait().await;
                            (ns, res)
                        });
                    }
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
