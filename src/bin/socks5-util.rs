// tool for testing socks5 proxies

use anyhow::Result;
use socksv5::v5::{self, SocksV5AuthMethod};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[tokio::main]
async fn main() -> Result<()> {

    let mut args = std::env::args();
    args.next();

    let addr = "127.0.0.1:9909";
    log::trace!("connect");
    let mut stream = TcpStream::connect(addr).await?;
    let (mut r, mut w) = stream.split();
    // Ver Authlen Auth
    v5::write_handshake(&mut w, [SocksV5AuthMethod::Noauth]).await?;
    log::trace!("sent hs");
    // Ver Choice
    let authc = v5::read_auth_method(&mut r).await?;
    dbg!(authc);

    v5::write_request(
        &mut w,
        v5::SocksV5Command::Connect,
        v5::SocksV5Host::Domain("ip.me".into()),
        80,
    )
    .await?;
    let res = v5::read_request_status(&mut r).await?;
    dbg!(res);
    let mut buf: Vec<u8> = "GET / HTTP/1.1
Host: example.com
"
    .into();
    w.write_all(&mut buf).await?;

    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let res = r.read_buf(&mut buf).await?;
    dbg!(String::from_utf8(buf)?);

    // todo
    // tcp/domain, tcp/host, udp, udp/dns
    Ok(())
}
