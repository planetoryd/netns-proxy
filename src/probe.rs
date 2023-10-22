use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::RawFd;

use anyhow::Result;
use netlink_ops::netns::Pid;
use rumpsteak::choices;
use rumpsteak::session;
use rumpsteak::try_session;
use rumpsteak::Choices;
use rumpsteak::End;
use rumpsteak::FullDual;
use rumpsteak::Receive;
use rumpsteak::Role;
use rumpsteak::Send;
use tokio_send_fd::SendFd;
use tokio_util::codec::Framed;
use tokio_util::codec::LengthDelimitedCodec;

use crate::config::WCloneFlags;
use crate::tasks::DevFd;
use crate::tasks::FDStream;
use crate::tasks::FramedUS;
use crate::tasks::FD;
use serde::{Deserialize, Serialize};

#[derive(Role)]
struct ProbeSub(#[route(Probe, Msg)] FramedUS, #[route(Probe, FD)] FDStream);

#[derive(Role)]
pub struct Probe(
    #[route(ProbeSub, Msg)] FramedUS,
    #[route(ProbeSub, FD)] FDStream,
);

nix::ioctl_write_int!(tunsetowner, 'T', 204);
nix::ioctl_write_int!(tunsetpersist, 'T', 203);

/// Can be used to make the TUN/TAP interface persistent.
pub fn tun_ops(fd: RawFd) -> Result<()> {
    // unsafe { tunsetowner(fd, 1000)? };
    unsafe { tunsetpersist(fd, 1)? };

    Ok(())
}

pub async fn serve(peer: RawFd) -> Result<()> {
    use nix::sched::setns;

    let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(peer) };
    let stream = tokio::net::UnixStream::from_std(stream)?;
    let fdstr = stream.recv_stream().await?;
    let f: Framed<tokio::net::UnixStream, LengthDelimitedCodec> =
        Framed::new(stream, LengthDelimitedCodec::new());
    let mut psub = ProbeSub(FramedUS(f), FDStream(fdstr));
    try_session(
        &mut psub,
        async move |ses: <Probing<'_, Probe> as FullDual<Probe, ProbeSub>>::Dual| {
            let (enter, cont) = ses.receive().await?;
            setns(enter.fd, enter.flags.0)?;
            // It should make current thread and future spawned threads change netns.
            let (cr, cont) = cont.receive().await?;
            let tun = tidy_tuntap::Device::new(cr.name, cr.typ, false)?;
            tun_ops(tun.as_raw_fd())?;
            let e = cont
                .send(DevFd {
                    fd: tun.as_raw_fd(),
                })
                .await?;

            Result::<_, anyhow::Error>::Ok(((), e))
        },
    )
    .await?;
    Ok(())
}

pub async fn start() -> Result<Probe> {
    let (ax, bx) = tokio::net::UnixStream::pair()?;
    let (fax, fbx) = tokio::net::UnixStream::pair()?;
    // start a process to take the DevFD
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command.arg("probe").arg(bx.as_raw_fd().to_string());
    let _child = command.spawn()?;
    ax.send_stream(fbx).await?;
    let f: Framed<tokio::net::UnixStream, LengthDelimitedCodec> =
        Framed::new(ax, LengthDelimitedCodec::new());
    Ok(Probe(FramedUS(f), FDStream(fax)))
}

#[session]
pub type Probing = Send<
    ProbeSub,
    (FramedUS, Enter),
    Send<ProbeSub, (FramedUS, CreateDevice), Receive<ProbeSub, (FDStream, DevFd), End>>,
>;

#[choices]
#[derive(Serialize, Deserialize)]
pub enum Msg {
    CreateDevice(),
    Enter(),
}

#[derive(Serialize, Deserialize)]
pub struct Enter {
    /// NSFD or PIDFD
    pub fd: RawFd,
    pub flags: WCloneFlags,
}

#[derive(Serialize, Deserialize)]
pub struct CreateDevice {
    name: String,
    typ: tidy_tuntap::Mode,
}
