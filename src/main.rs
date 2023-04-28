#![feature(ip)]
#![feature(async_closure)]
use clap::{Parser, Subcommand};
use flexi_logger::FileSpec;
use futures::TryStreamExt;
use ipgen::subnet;
use ipnetwork::IpNetwork;
use rtnetlink::{new_connection, Handle, LinkAddRequest, NetworkNamespace};
use std::os::fd::AsRawFd;
use std::time::Duration;
use std::{
    borrow::Borrow,
    path::{Path, PathBuf},
    process::exit,
};
use sysinfo::{self, ProcessExt, System, SystemExt};

use async_compat::CompatExt;
use flexi_logger::writers::FileLogWriter;
use fork::{chdir, close_fd, fork, setsid, Fork};
use smol::{io, net, prelude, Unblock};
// Standard procedure
// Creates various netns, base-vpn, socks, i2p, lokinet, un-firewalled
// Kill other running processes, suspected
// Fork, setns, drop privs, start daemons

static mut curr_netns: &str = "";
static mut logger: Option<flexi_logger::LoggerHandle> = None;

fn kill_suspected() {
    let s = System::new_all();
    for (pid, process) in s.processes() {
        // kill by saved pids
        // or by matching commandlines
        println!("{} {:?}", pid, process.cmd());
    }
}

fn veth_from_ns(nsname: &str, host: bool) -> String {
    if host {
        format!("{nsname}_vh")
    } else {
        format!("{nsname}_vn")
    }
}

pub fn daemon_with_parent(nochdir: bool, noclose: bool) -> Result<Fork, i32> {
    let r = fork();
    match r {
        Ok(Fork::Parent(_)) => Ok(Fork::Parent(-1)), // This is not the actual pid of desired child
        Ok(Fork::Child) => setsid().and_then(|_| {
            if !nochdir {
                chdir()?;
            }
            if !noclose {
                close_fd()?;
            }
            match fork() {
                Ok(Fork::Parent(pid_we_want)) => exit(0),
                Ok(Fork::Child) => Ok(Fork::Child),
                Err(n) => Err(n),
            }
        }),
        Err(n) => Err(n),
    }
}

async fn inner_daemon(ns_path: String, ns_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (connection, handle, _) = new_connection().unwrap();
    smol::spawn(connection).detach();
    // as for now, the code above works, the new process is in the netns, checked on 4/24
    // get lo up and check netns
    log::debug!("get interface lo");

    let mut vn = handle.link().get().match_name("lo1".to_owned()).execute();
    match vn.try_next().await {
        Ok(x) => {
            if let Some(lm) = x {
                log::debug!("set lo up");
                handle.link().set(lm.header.index).up().execute().await?;
            }
            log::error!("lo not found");
        }
        _ => {
            log::error!("interface lo, not found");
            // exit(1);
        }
    }
    Ok(())
    // exit(0);
}

fn fork_n_daemonize(ns_path: String, ns_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    match daemon_with_parent(true, true).unwrap() {
        Fork::Child => {
            unsafe {
                logger.as_ref().unwrap().reset_flw(&FileLogWriter::builder(
                    FileSpec::default().discriminant(ns_name),
                ))?;
            }
            log::info!("netns-proxy of {ns_path}, daemon started");
            NetworkNamespace::unshare_processing(ns_path.clone())?;

            smol::block_on(async_compat::Compat::new(inner_daemon(ns_path, ns_name)))?;

            // tokio::time::sleep(tokio::time::Duration::from_secs(10000)).await;
        }
        Fork::Parent(_) => {
            // execution continues in sudo, not going to do anything here
        }
    }
    Ok(())
}

// Trys to add an netns. If it exists, remove it.
// Get the NS up.
async fn config_ns(
    ns_name: &str,
    f: fn(&str, bool) -> String,
    handle: &rtnetlink::Handle,
) -> Result<(), Box<dyn std::error::Error>> {
    let res = NetworkNamespace::add(ns_name.to_owned()).await;
    match res {
        Ok(_) => {
            log::debug!("{ns_name} created")
        }
        Err(_) => {
            // likely dup
            // NetworkNamespace::del(ns_name.to_owned()).await?; // FIXME
            // NetworkNamespace::add(ns_name.to_owned()).await?;
            // log::debug!("success in creating {ns_name}") // XXX this crates sucks. important messages aren't necessarily errors

            // removal of ns fails at even number times. cant fix
            log::debug!("{ns_name} exists") // XXX this crates sucks. important messages aren't necessarily errors
        }
    }

    let mut vh = handle.link().get().match_name(f(&ns_name, true)).execute();
    match vh.try_next().await {
        Ok(x) => {
            if let Some(lm) = x {
                handle.link().del(lm.header.index).execute().await?;
            }
        }
        _ => (),
    }

    let mut vn = handle.link().get().match_name(f(&ns_name, false)).execute();
    match vn.try_next().await {
        Ok(x) => {
            if let Some(lm) = x {
                handle.link().del(lm.header.index).execute().await?;
            }
        }
        _ => (),
    }

    handle
        .link()
        .add()
        .veth(f(ns_name, true), f(ns_name, false).into())
        .execute()
        .await?;

    // Get a subnet in 10.0 for the veth pair
    let subnet_veth = IpNetwork::new(
        ipgen::ip(f(&ns_name, true).as_str(), "10.0.0.0/8".parse().unwrap())?,
        16,
    )?
    .to_string();
    let subnet6_veth = IpNetwork::new(
        ipgen::ip(f(&ns_name, true).as_str(), "fc00::/16".parse().unwrap())?, // XXX I believe ipgen has a bug
        125,
    )?
    .to_string();

    let ip_vh = ipgen::ip(f(&ns_name, true).as_str(), subnet_veth.parse()?)?;
    let ip_vn = ipgen::ip(f(&ns_name, false).as_str(), subnet_veth.parse()?)?;

    let ip6_vh = ipgen::ip(f(&ns_name, true).as_str(), subnet6_veth.parse()?)?;
    let ip6_vn = ipgen::ip(f(&ns_name, false).as_str(), subnet6_veth.parse()?)?;

    let mut vh = handle.link().get().match_name(f(&ns_name, true)).execute();
    let lm = vh.try_next().await?.unwrap();
    handle
        .address()
        .add(lm.header.index, ip_vh, 16)
        .execute()
        .await?;
    handle
        .address()
        .add(lm.header.index, ip6_vh, 125)
        .execute()
        .await?;
    handle.link().set(lm.header.index).up().execute().await?;

    let mut vn = handle.link().get().match_name(f(&ns_name, false)).execute();
    let lm = vn.try_next().await?.unwrap();
    handle
        .address()
        .add(lm.header.index, ip_vn, 16)
        .execute()
        .await?;
    handle
        .address()
        .add(lm.header.index, ip6_vn, 125)
        .execute()
        .await?;
    handle.link().set(lm.header.index).up().execute().await?;

    log::info!("veth subnet {subnet_veth}, {subnet6_veth}, host {ip_vh}, {ip6_vh}, guest {ip_vn}, {ip6_vn}");

    assert!(!ip_vh.is_global());
    assert!(!ip6_vh.is_global());
    let mut p = PathBuf::from(rtnetlink::NETNS_PATH);
    p.push(ns_name);
    let nsfd = std::fs::File::open(p)?;
    handle
        .link()
        .set(lm.header.index)
        .setns_by_fd(nsfd.as_raw_fd())
        .execute()
        .await?;

    // brilliant me, File::open(p)?.as_raw_fd() got the file closed before use, fixed it
    log::trace!("ns {ns_name} configured");
    Ok(())
}

async fn config_network() -> Result<(), Box<dyn std::error::Error>> {
    let (connection, handle, _) = new_connection().unwrap();
    smol::spawn(connection).detach();

    let base_ns = "base_p".to_owned();
    config_ns(&base_ns, veth_from_ns, &handle).await?;

    let i2p = "i2p".to_owned();
    config_ns(&i2p, veth_from_ns, &handle).await?;

    let clean_ip1 = "clean_ip1".to_owned();
    config_ns(&clean_ip1, veth_from_ns, &handle).await?;

    let clean_ipv6 = "clean_ipv6".to_owned();
    config_ns(&clean_ipv6, veth_from_ns, &handle).await?;

    Ok(())
}

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

fn main() -> Result<(), String> {
    // this is very safe
    unsafe {
        logger = Some(
            flexi_logger::Logger::try_with_env_or_str("error,netns_proxy=debug")
                .unwrap()
                .log_to_file(FileSpec::default())
                .duplicate_to_stdout(flexi_logger::Duplicate::All)
                .start()
                .unwrap(),
        );
    }
    let cli = Cli::parse();

    smol::block_on(async_compat::Compat::new(async {
        match &cli.command {
            Some(Commands::Stop {}) => {
                // kill_suspected();
            }
            None => match config_network().await {
                Ok(_) => {}
                Err(x) => {
                    log::error!("config network failed {x}")
                }
            },
        }
    }));

    match &cli.command {
        Some(Commands::Stop {}) => {}
        None => {
            let base_ns = "base_p".to_owned();
            let mut p = PathBuf::from(rtnetlink::NETNS_PATH);
            p.push(&base_ns);
            if let Err(x) = fork_n_daemonize(p.to_str().unwrap().to_owned(), &base_ns) {
                log::error!("{x}");
            }
        }
    }

    Ok(())
}
