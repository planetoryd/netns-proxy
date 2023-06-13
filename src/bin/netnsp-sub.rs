use anyhow::Result;
use std::env::args;

// this will run inside netns

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = args();

    let mut p = std::path::PathBuf::from(netns_proxy::NETNS_PATH);
    args.next().unwrap();
    let nsname = args.next().unwrap();
    p.push(nsname.clone());

    if let Err(err) = netns_proxy::inner_daemon(
        p.to_string_lossy().into_owned(),
        &nsname,
        args.next(),
        args.next(),
    )
    .await
    {
        log::error!("{}; {}", nsname, err);
        std::process::exit(1);
    };

    Ok(())
}
