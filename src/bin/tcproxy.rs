

use anyhow::Result;
use netns_proxy::{
    tcproxy,
};

#[tokio::main]
async fn main() -> Result<()> {
    flexi_logger::Logger::try_with_env_or_str("trace")
        .unwrap()
        .log_to_stdout()
        .start()
        .unwrap();
    let mut args = std::env::args();
    args.next();
    tcproxy::start_proxy(args.next().unwrap().parse()?).await?;
    Ok(())
}
