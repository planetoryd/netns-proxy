use anyhow::Result;
use netns_proxy::configurer::{self, NETNS_PATH};

// this will run inside netns

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args();
    args.next();
    let arglen = args.len();
    if arglen >= 4 {
        if let Err(err) = netns_proxy::inner_daemon(
            args.next(),
            args.next(),
            args.next(),
            args.next(),
            args.next(),
        )
        .await
        {
            return Err(err);
        };
    } else {
        if arglen == 2 {
            configurer::config_in_ns(args.next().unwrap().parse()?, args.next().unwrap()).await?;
        } else {
            std::process::exit(1);
        }
    }

    Ok(())
}
