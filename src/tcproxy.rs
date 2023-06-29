use std::net::{Ipv4Addr, SocketAddr};

use tokio::{
    net::{TcpListener, TcpSocket, TcpStream},
    try_join,
};

use anyhow::Result;

use crate::configurer;

// for use in the gateway-ish ns instances
// some socks proxies have strict a security policy, and I couldn't bother studying nftables.
pub async fn start_proxy(port: u16) -> Result<()> {
    let selfns = configurer::self_netns_identify().await;
    let proxy_server =
        TcpListener::bind(SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), port + 1)).await?;
    // If we don't do this, it will say Address already in use, and starts a loop with itself.
    // the latter seems solvable but let's just just port+1
    log::trace!("tcproxy in ns {:?}", selfns);

    loop {
        let (socket, _) = proxy_server.accept().await?;
        log::debug!("new conn on {}", port);
        tokio::spawn(async move {
            let _r = handle_client_conn(socket, port).await;
        });
    }

    Ok(())
}

async fn handle_client_conn(mut client_conn: TcpStream, port: u16) -> Result<()> {
    let socket = TcpSocket::new_v4()?;
    // so that the server being proxied sees 127.0.0.1
    socket.bind("127.0.0.1:1212".parse()?)?;

    let mut main_server_conn = socket
        .connect(SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), port))
        .await?;
    let (mut client_recv, mut client_send) = client_conn.split();
    let (mut server_recv, mut server_send) = main_server_conn.split();

    let handle_one = async { tokio::io::copy(&mut server_recv, &mut client_send).await };
    let handle_two = async { tokio::io::copy(&mut client_recv, &mut server_send).await };

    try_join!(handle_one, handle_two)?;

    Ok(())
}
