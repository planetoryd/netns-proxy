

use anyhow::Result;
use netns_proxy::{
    tcproxy,
};

#[tokio::main]
async fn main() -> Result<()> {

    let mut args = std::env::args();
    args.next();
    tcproxy::start_proxy(args.next().unwrap().parse()?).await?;
    Ok(())
}
