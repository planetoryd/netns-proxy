#![feature(ip)]
#![feature(async_closure)]
#![feature(async_fn_in_trait)]
#![feature(exit_status_error)]
#![feature(setgroups)]
#![feature(get_mut_unchecked)]
use anyhow::Result;

use anyhow::Ok;

use nix::unistd::Pid;
use tokio::{self};

use netns_proxy::sub::{NetnspSub, NetnspSubImpl};

// There should be one netnsp-sub process for each managed netns
// Start new processes because tokio spans across threads.
use procspawn;
#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args();
    args.next();
    let arglen = args.len();
    flexi_logger::Logger::try_with_env_or_str(
        "debug,netns_proxy::tcproxy=trace,netlink_proto=info,rustables=info",
    )
    .unwrap()
    .log_to_stdout()
    .start()
    .unwrap();
    let netnsub = NetnspSubImpl {};

    if arglen >= 4 {
        if let Err(err) = netnsub
            .inner_daemon(
                args.next().unwrap(),
                args.next().unwrap().parse::<u32>()?.into(),
                args.next().unwrap().parse::<u32>()?.into(),
                args.next().unwrap().parse()?,
                args.next()
                    .and_then(|x| Some(Pid::from_raw(x.parse::<i32>().unwrap()))),
            )
            .await
        {
            log::error!("{:?}", err);
            std::process::exit(1);
        };
    } else {
        if arglen == 2 {
            netnsub
                .remove_vethb_in_ns(args.next().unwrap().parse()?, args.next().unwrap())
                .await?;
        } else if arglen == 3 {
            netnsub
                .config_in_ns_up(
                    args.next().unwrap().parse()?,
                    args.next().unwrap(),
                    args.next().unwrap().parse()?,
                )
                .await?;
        } else {
            std::process::exit(1);
        }
    }
    Ok(())
}
