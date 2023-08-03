use anyhow::Result;

use anyhow::Ok;
use netns_proxy::data::*;
use netns_proxy::sub::handle;
use tokio::net::UnixStream;
use tokio_util::codec::Framed;
use tokio_util::codec::LengthDelimitedCodec;

use std::path::PathBuf;
use std::sync::Arc;

use tokio::{self};

use netns_proxy::netlink::*;
use netns_proxy::util::Awaitor;

// binary for testing

#[tokio::main]
async fn main() -> Result<()> {
    flexi_logger::Logger::try_with_env_or_str(
        "trace,netlink_proto=info,rustables=warn,netlink_sys=info",
    )
    .unwrap()
    .log_to_stdout()
    .start()?;
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 {
        // assumed this is the RPC sub
        let path: Result<PathBuf, _> = args[1].parse();
        if path.is_ok() {
            let sock_path = path.unwrap();
            let conn = UnixStream::connect(sock_path.as_path()).await?;
            let f: Framed<UnixStream, LengthDelimitedCodec> =
                Framed::new(conn, LengthDelimitedCodec::new());
            handle(f).await?;
            return Ok(());
        }
    }

    let mut ro: PathBuf = env!("CARGO_MANIFEST_DIR").parse()?;
    ro.push("testing");
    let mut derivative: PathBuf = ro.clone();
    let _ = std::fs::create_dir(&ro);
    derivative.push("sub_derivative.json");
    let mut settings: PathBuf = ro.clone();
    settings.push("geph1.json");
    let mut sock: PathBuf = ro.clone();
    sock.push("sock");
    let _ = std::fs::create_dir(&sock);

    let paths = Arc::new(ConfPaths {
        settings,
        derivative,
        sock,
    });

    let _state: NetnspState = NetnspState::load(paths.clone()).await?;
    let mut dae = Awaitor::new();
    // bind socket the listener for nl socket proxies
    // bind sub hub
    let mn: MultiNS = MultiNS::new(paths, dae.sender.clone()).await?;
    let id = NSID::from_name(ProfileName("geph1".to_owned())).await?;
    let nl = mn.get_nl(id.clone()).await?;
    let ns = ConnRef::new(Arc::new(nl)).to_netns(id).await?;
    dbg!(&ns);

    dae.wait().await?;

    Ok(())
}
