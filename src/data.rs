use derivative::Derivative;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use std::{
    collections::{BinaryHeap, HashMap, HashSet},
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::process::CommandExt,
    path::PathBuf,
    process::Stdio,
    str::FromStr,
    sync::Arc,
};

use tokio::{io::AsyncBufReadExt, process::Command};

use crate::{
    netlink::{ConnRef, MultiNS, VPairKey},
    nft,
    sub::NsubState,
    util::{watch_both, TaskOutput},
};
use tokio::{self, io::AsyncReadExt};

use anyhow::{anyhow, bail, ensure, Ok, Result};

use crate::util::error::*;

// generated info and state store
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Derivative {
    // separate maps, separate indexing
    pub named_ns: HashMap<ProfileName, SubjectInfo<NamedV>>,
    pub flatpak: HashMap<Pid, SubjectInfo<FlatpakV>>,
    pub ns_list: HashMap<NSRef, NSID>,
    pub root_ns: NSID,
}

trait PidMap {
    /// retain only running processes
    async fn retain_running(&mut self) -> Result<()>;
}

impl<T> PidMap for HashMap<Pid, T> {
    async fn retain_running(&mut self) -> Result<()> {
        let mut pids = HashSet::new();
        let mut entries = tokio::fs::read_dir("/proc").await?;

        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name();

            if let Result::Ok(pid) = file_name.to_string_lossy().parse::<u32>() {
                pids.insert(pid);
            }
        }
        self.retain(|p, _v| pids.contains(&p.0));
        Ok(())
    }
}

impl Derivative {
    pub async fn init(&mut self) -> Result<()> {
        self.update_rootns()?;
        log::warn!(
            "The netns of current process will be assumed to be root_ns. It's recorded in the derivative file for the use of all later launches"
        );
        Ok(())
    }
    /// Update root_ns NSID's Pid
    pub fn update_rootns(&mut self) -> Result<()> {
        let n = NSID::proc()?;
        if self.root_ns.inode != 0 {
            if n != self.root_ns {
                bail!("Root NS mismatch. You are running this process from a different NS than what was recorded.");
            }
        }
        self.root_ns = n;
        Ok(())
    }
    /// clear invalid ones
    pub async fn clean_flatpak(&mut self, set: &HashMap<FlatpakID, ProfileName>) -> Result<()> {
        self.flatpak
            .retain(|_p, s| set.contains_key(&s.specifics.id));
        self.flatpak.retain_running().await?;
        Ok(())
    }
    pub fn clean_named(&mut self, conf: &HashMap<ProfileName, Arc<SubjectProfile>>) {
        self.named_ns.retain(|e, _| conf.contains_key(e));
    }
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub struct Settings {
    pub profiles: HashMap<ProfileName, Arc<SubjectProfile>>,
    pub flatpak: HashMap<FlatpakID, ProfileName>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, Hash, PartialEq, Eq)]
#[serde(transparent)]
pub struct ProfileName(pub String);

#[derive(Serialize, Deserialize, Default, Clone, Debug, Hash, PartialEq, Eq)]
#[serde(transparent)]
pub struct FlatpakID(pub String);

impl FromStr for FlatpakID {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

impl From<String> for FlatpakID {
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[derive(Debug)]
pub struct NetnspState {
    // persistent
    pub derivative: Derivative,
    pub settings: Settings,
    // runtime state
    pub paths: Arc<ConfPaths>,
    pub nft_refresh_once: bool,
    pub ids: BinaryHeap<UniqueInstance>,
    pub incre_nft: nft::IncrementalNft,
}

pub trait UnIns {
    fn new_unique<'a, N: UniqueName>(&'a mut self, unique_name: N);
    fn get_unique(&self) -> Option<&UniqueInstance>;
}

impl UnIns for BinaryHeap<UniqueInstance> {
    fn new_unique<'a, N: UniqueName>(&'a mut self, unique_name: N) {
        let id = if let Some(max) = self.peek() {
            max.id + 1
        } else {
            0
        };
        let n = UniqueInstance::new(id, unique_name.to_string());
        self.push(n);
    }
    // this fn has to be separated from new_unique due to borrow checker
    fn get_unique(&self) -> Option<&UniqueInstance> {
        self.peek()
    }
}

pub trait UniqueName: ToString {}

impl ToString for ProfileName {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}
impl ToString for FlatpakID {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}
impl ToString for FlatpakBaseName {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

impl UniqueName for ProfileName {}

pub struct FlatpakBaseName(pub String);

impl FlatpakBaseName {
    pub fn new(fid: &FlatpakID, pid: Pid) -> Self {
        let mut n = String::from(fid.0.clone());
        n.push_str(&pid.0.to_string());
        FlatpakBaseName(n)
    }
}

impl UniqueName for FlatpakBaseName {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfPaths {
    pub settings: PathBuf,
    pub derivative: PathBuf,
    /// directory for sockets
    pub sock: PathBuf,
}

// Each instance has a unique NetnsInfo
// identified by pid OR persistent name
pub type InstanceID = either::Either<i32, String>;

impl ConfPaths {
    // must ensure one ConfPaths per root ns
    pub fn default() -> Result<Self> {
        // because it is a system-wide program.
        let run_base: PathBuf = "/var/lib/netns-proxy".parse()?;
        let conf_base: PathBuf = "/etc/netns-proxy".parse()?;
        std::fs::create_dir_all(&run_base)?;
        std::fs::create_dir_all(&conf_base)?;
        let r = Self {
            settings: conf_base.join("conf.json"),
            derivative: run_base.join("state.json"),
            sock: run_base,
        };
        Ok(r)
    }
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SubjectProfile {
    /// veth connections between NSes
    pub vconnections: Vec<RVethConn>,
    /// establish user space forwarding, to proxies
    pub proxies: Vec<RProxy>,
    /// additional processes to start
    pub procs: RProcTasks,
    pub tun2socks: RTUNedSocks,
    pub dnsproxy: DNSProxyR,
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub enum NSRef {
    Root,
    Pid(Pid),
    Named(ProfileName),
}

impl From<FlatpakV> for NSRef {
    fn from(value: FlatpakV) -> Self {
        Self::Pid(value.pid)
    }
}

impl From<NamedV> for NSRef {
    fn from(value: NamedV) -> Self {
        Self::Named(value.0)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
/// connection from subject NS to target NS
pub struct RVethConn {
    pub target: NSRef,
}

/// userland proxy. used when, for ex. the source proxy only listens on 127.1
/// src can be the same as subject NS.
/// ip in src ns is implied to be 127.1
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RProxy {
    pub src: NSRef,
    /// port in src ns
    pub port: u16,
    pub port_local: u16,
}
// sometimes netfilter forwarding can be hard to set up, so this can be used.

/// Addr through which the subject accesses an external object
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum AddrRef {
    /// veth conn in reference, and whether use v6 (true for v6)
    VConn(RVethConn, bool, u16),
    Proxy(RProxy),
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
/// start external processes, as daemons if it doesn't quit
pub struct RProcTasks {
    pub su: Option<CmdParams>,
    pub normal: Option<CmdParams>,
}

/// TUNified socks proxy pattern
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RTUNedSocks {
    #[serde(default = "SubjectProfile::default_tun2socks")]
    pub enable: bool,
    pub src: AddrRef,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
pub struct DNSProxyR {
    #[serde(default = "SubjectProfile::default_dnsproxy")]
    pub enable: bool,
    #[serde(default = "SubjectProfile::default_dns_v6")]
    pub v6: bool,
    #[serde(default = "SubjectProfile::default_dns_port")]
    pub port: u16,
    /// override args entirely
    pub args: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
pub struct CmdParams {
    pub program: String,
    pub argv: Vec<String>,
    pub user: Option<String>,
}

pub const TUN_NAME: &str = "s_tun";

/// This is runtime state that is only valid during runtime.
/// On startup, it's filled by deriving from the profiles and global state
/// Dumped only for observation purpose.
/// Derive, apply it and mutate it during the process.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SubjectInfo<V: VSpecifics> {
    pub id: UniqueInstance,
    pub vaddrs: HashMap<NSRef, VethConn>,
    /// Supplied at runtime, for the runtime
    pub specifics: V, // variant specific info
    pub ns: NSID,
    pub dnsp_args: Option<Vec<String>>,
    /// socks5 proxy
    pub tun2s: Option<SocketAddr>, // ip without CIDR
    pub profile: Option<Arc<SubjectProfile>>,
}

impl<V: VSpecifics> SubjectInfo<V> {
    /// get or create a subprocess, and get the Netns instance
    pub async fn connect(&self, mn: &mut MultiNS) -> Result<()> {
        log::debug!("Connect NS for subject {}", self.ns);
        let n = mn.get_nl(self.ns.clone()).await?;
        let nl = ConnRef::new(Arc::new(n));
        let ns = nl.to_netns(self.ns.clone()).await?;
        mn.ns.write().await.insert(self.ns.clone(), ns.into());
        Ok(())
    }
    pub fn assure_in_ns(&self) -> Result<()> {
        let c = NSID::proc()?;
        anyhow::ensure!(c == self.ns);
        Ok(())
    }
    /// These two methods return shortly. Tasks are passed to the awaiter
    /// Conforms to PidAwaiter
    pub async fn run_tun2s(&self, st: &mut NsubState) -> Result<()> {
        use crate::netlink::*;
        use crate::util::watch_log;

        if !self.profile.as_ref().unwrap().tun2socks.enable {
            return Ok(());
        } else {
            log::info!("Run tun2socks for {}", self.ns);
        }

        let mut tun2 = std::process::Command::new("tun2socks");
        tun2.uid(st.non_priv_uid.into())
            .gid(st.non_priv_gid.into())
            .groups(&[st.non_priv_gid.into()]);
        let prxy = format!("socks5://{}", self.tun2s.unwrap().to_string());
        tun2.args(&["-device", TUN_NAME, "-proxy", &prxy]);
        let mut tun2_async: Command = tun2.into();
        tun2_async.stdout(Stdio::piped());
        let mut tun2h = tun2_async.spawn()?;
        let pid = Pid(tun2h.id().ok_or(anyhow!("Tun2socks stopped"))?);
        st.ctx.pid.send(pid).unwrap();
        use tokio_stream::wrappers::LinesStream;
        let stdout = tun2h.stdout.take().unwrap();
        let reader = LinesStream::new(tokio::io::BufReader::new(stdout).lines());
        let (tx, rx) = tokio::sync::oneshot::channel();
        let pre = format!("{}/tun2socks", self.id);
        tokio::spawn(watch_log(Box::pin(reader), Some(tx), pre.clone()));
        rx.await?; // wait for first line to appear
        let tunk: LinkKey = TUN_NAME.parse()?;
        let tun = st.ns.netlink.links.get_mut(&tunk).ok_or(DevianceError)?;
        tun.up(st.ns.netlink.conn.get()).await?;
        let _ = st
            .ns
            .netlink
            .conn
            .get()
            .ip_add_route(tun.index, None, Some(true))
            .await;
        let _ = st
            .ns
            .netlink
            .conn
            .get()
            .ip_add_route(tun.index, None, Some(false))
            .await;

        let (t, _r) = TaskOutput::immediately_std(Box::pin(async move { tun2h.wait().await }), pre);
        st.ctx.dae.send(t).unwrap();

        Ok(())
    }
    pub async fn run_dnsp(&self, st: &mut NsubState) -> Result<()> {
        use crate::netlink::*;

        if !self.profile.as_ref().unwrap().dnsproxy.enable {
            return Ok(());
        } else {
            log::info!("Run dnsproxy for {}", self.ns);
        }

        let mut dnsp = std::process::Command::new("dnsproxy");
        dnsp.uid(st.non_priv_uid.into())
            .gid(st.non_priv_gid.into())
            .groups(&[st.non_priv_gid.into()]);

        dnsp.args(self.dnsp_args.as_ref().unwrap());
        let mut dnsp_a: Command = dnsp.into();
        dnsp_a.stdout(Stdio::piped());
        dnsp_a.stderr(Stdio::piped());
        let mut dns_h = dnsp_a.spawn()?;
        let pid = Pid(dns_h.id().ok_or(anyhow!("Dnsproxy stopped"))?);
        st.ctx.pid.send(pid).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let pre = format!("{}/dnsproxy", self.id);
        watch_both(&mut dns_h, pre.clone(), Some(tx))?;
        rx.await?; // wait for first line to appear
        let (t, _r) = TaskOutput::immediately_std(Box::pin(async move { dns_h.wait().await }), pre);
        st.ctx.dae.send(t).unwrap();

        Ok(())
    }
}

impl SubjectProfile {
    fn default_conn_root() -> bool {
        true
    }
    fn default_tun_port() -> u32 {
        9909
    }
    fn default_tun2socks() -> bool {
        true
    }
    fn default_dnsproxy() -> bool {
        true
    }
    /// prefer v4 for dns
    fn default_dns_v6() -> bool {
        false
    }
    fn default_dns_port() -> u16 {
        5353
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FlatpakV {
    pub id: FlatpakID,
    pub pid: Pid,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Name for netns
pub struct NamedV(pub ProfileName);

impl VSpecifics for NamedV {}
impl VSpecifics for FlatpakV {}
/// variant specifics
pub trait VSpecifics: Into<NSRef> + Clone {}

/// a for subject ns, b for target ns
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VethConn {
    pub subnet_veth: IpNetwork,
    pub subnet6_veth: IpNetwork,
    pub ip_va: IpNetwork,
    pub ip6_va: IpNetwork,
    pub ip_vb: IpNetwork,
    pub ip6_vb: IpNetwork,
    pub key: VPairKey,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, Hash, PartialEq, Eq)]
#[serde(transparent)]
pub struct Pid(pub u32);

/// Uniqueness has to be guaranteed in every field.
/// Unique instance, as per named ns, per flatpak app
#[derive(Derivative, Clone, Debug, Serialize, Deserialize)]
#[derivative(PartialOrd, Ord, PartialEq, Eq)]
pub struct UniqueInstance {
    id: u16,
    /// Unique name
    #[derivative(PartialEq = "ignore")]
    #[derivative(PartialOrd = "ignore")]
    #[derivative(Ord = "ignore")]
    name: String,
    /// Netlink compliant name
    #[derivative(PartialEq = "ignore")]
    #[derivative(PartialOrd = "ignore")]
    #[derivative(Ord = "ignore")]
    link_base: String,
}

impl Display for UniqueInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("ID{}/{}", self.id, self.name))
    }
}

impl UniqueInstance {
    pub fn new(id: u16, name: String) -> Self {
        Self {
            id,
            name: name.clone(),
            link_base: if name.len() < 12 {
                name
            } else {
                "nsp".to_owned() + &id.to_string()
            },
        }
    }
}

/// resolve with global state
pub trait ResolvableG<V: VSpecifics, D> {
    async fn resolve_g(&self, global: &NetnspState, uq: &UniqueInstance, v: &V) -> Result<D>;
}

pub trait ResolvableS<V: VSpecifics, D> {
    fn resolve(&self, subject: &SubjectInfo<V>) -> Result<D>;
}

impl NSRef {
    pub async fn resolve_d<'a>(&'a self, de: &'a Derivative) -> Result<NSID> {
        match self {
            Self::Root => Ok(de.root_ns.to_owned()),
            Self::Pid(p) => {
                let x = if let Some(k) = de.flatpak.get(p) {
                    k.ns.clone()
                } else {
                    NSID::from_pid(p.clone())?
                };
                Ok(x)
            }
            Self::Named(n) => {
                let x = if let Some(k) = de.named_ns.get(n) {
                    k.ns.clone()
                } else {
                    NSID::from_name(n.to_owned()).await?
                };
                Ok(x)
            }
        }
    }
}

impl<V: VSpecifics> ResolvableS<V, SocketAddr> for RTUNedSocks {
    fn resolve(&self, subject: &SubjectInfo<V>) -> Result<SocketAddr> {
        self.src.resolve(subject)
    }
}

// AddrRef is situated in a Subject's Info. It refers to a certain Target NS
impl<V: VSpecifics> ResolvableS<V, SocketAddr> for AddrRef {
    fn resolve(&self, subject: &SubjectInfo<V>) -> Result<SocketAddr> {
        match self {
            Self::Proxy(p) => {
                // resolves to the userland proxy
                // here it means the local endpoint
                Ok(SocketAddr::new("127.0.0.1".parse()?, p.port_local))
            }
            Self::VConn(p, v6, port) => {
                let vc = subject.vaddrs.get(&p.target).ok_or(DevianceError)?;
                let ipn = if *v6 { vc.ip6_vb } else { vc.ip_vb };
                Ok(SocketAddr::new(ipn.ip(), *port))
            }
        }
    }
}
impl RC for AddrRef {}

/// marker trait for chained resolution
trait RC {}

impl<D: RC, T: ResolvableS<NamedV, D>> ResolvableG<NamedV, D> for T {
    async fn resolve_g(&self, global: &NetnspState, _uq: &UniqueInstance, v: &NamedV) -> Result<D> {
        let subject = global.derivative.named_ns.get(&v.0).ok_or(DevianceError)?;
        self.resolve(subject)
    }
}

impl<D: RC, T: ResolvableS<FlatpakV, D>> ResolvableG<FlatpakV, D> for T {
    async fn resolve_g(
        &self,
        global: &NetnspState,
        _uq: &UniqueInstance,
        v: &FlatpakV,
    ) -> Result<D> {
        let subject = global.derivative.flatpak.get(&v.pid).ok_or(DevianceError)?;
        self.resolve(subject)
    }
}

impl<V: VSpecifics> ResolvableG<V, Vec<String>> for DNSProxyR {
    async fn resolve_g(
        &self,
        _global: &NetnspState,
        _uq: &UniqueInstance,
        _v: &V,
    ) -> Result<Vec<String>> {
        match &self.args {
            None => {
                let p = self.port.to_string();
                let r = if self.v6 {
                    vec![
                        "-l",
                        "127.0.0.1",
                        "-l",
                        "127.0.0.53",
                        "-l",
                        "::1",
                        "-p",
                        &p,
                        "-u",
                        "tcp://[2620:119:35::35]:53",
                        "--cache",
                    ]
                } else {
                    vec![
                        "-l",
                        "127.0.0.1",
                        "-l",
                        "127.0.0.53", // systemd-resolved
                        "-l",
                        "::1",
                        "-p",
                        &p,
                        "-u",
                        "tcp://1.1.1.1:53",
                        "--cache",
                    ]
                };
                let ve: Vec<String> = r.into_iter().map(|x| x.to_owned()).collect();
                Ok(ve)
            }
            Some(e) => Ok(e.clone()),
        }
    }
}

impl<V: VSpecifics> ResolvableS<V, VethConn> for RVethConn {
    fn resolve(&self, subject: &SubjectInfo<V>) -> Result<VethConn> {
        let num: u16 = subject.vaddrs.len().try_into()?;
        let num8: u8 = num.try_into()?;
        let id = subject.id.id;
        let id8: u8 = id.try_into()?;
        let pre4: u8 = 24;
        let pre6: u8 = 112;

        let subnet_veth = IpNetwork::new(Ipv4Addr::new(10, id8, num8, 0).into(), pre4)?;
        let subnet6_veth = IpNetwork::new(
            Ipv6Addr::new(0xfc0f, 0x2cdd, 0xeeff, id, num, 0, 0, 0).into(),
            pre6,
        )?;
        let ip_va = IpNetwork::new(Ipv4Addr::new(10, id8, num8, 1).into(), pre4)?;
        let ip_vb = IpNetwork::new(Ipv4Addr::new(10, id8, num8, 2).into(), pre4)?;
        let ip6_va = IpNetwork::new(
            Ipv6Addr::new(0xfc0f, 0x2cdd, 0xeeff, id, num, 0, 0, 1).into(),
            pre6,
        )?;
        let ip6_vb = IpNetwork::new(
            Ipv6Addr::new(0xfc0f, 0x2cdd, 0xeeff, id, num, 0, 0, 2).into(),
            pre6,
        )?;
        let v = VethConn {
            subnet6_veth,
            subnet_veth,
            ip6_va,
            ip6_vb,
            ip_va,
            ip_vb,
            key: (subject.id.link_base.to_owned() + &num.to_string())
                .parse()
                .unwrap(),
        };
        Ok(v)
    }
}

impl<V: VSpecifics> ResolvableG<V, SubjectInfo<V>> for Arc<SubjectProfile> {
    async fn resolve_g(
        &self,
        global: &NetnspState,
        uq: &UniqueInstance,
        v: &V,
    ) -> Result<SubjectInfo<V>> {
        // The resolutions are order-sensitive.
        let re: NSRef = (v.clone()).into();
        let mut s = SubjectInfo {
            id: uq.clone(),
            vaddrs: HashMap::new(),
            specifics: v.clone(),
            ns: re.resolve_d(&global.derivative).await?.to_owned(),
            dnsp_args: None,
            tun2s: None,
            profile: Some(self.to_owned()),
        };
        for vc in self.vconnections.iter() {
            let v1 = vc.resolve(&s)?;
            s.vaddrs.insert(vc.target.clone(), v1);
        }
        s.dnsp_args = Some(self.dnsproxy.resolve_g(global, uq, v).await?);
        s.tun2s = Some(self.tun2socks.resolve(&s)?);

        Ok(s)
    }
}

#[derive(Derivative, Default, Serialize, Deserialize, Debug, Clone)]
#[derivative(Hash, PartialEq, Eq)]
pub struct NSID {
    pub inode: u64,
    #[derivative(Hash = "ignore")]
    #[derivative(PartialEq = "ignore")]
    pub pid: Option<Pid>,
    #[derivative(Hash = "ignore")]
    #[derivative(PartialEq = "ignore")]
    pub name: Option<ProfileName>,
    #[derivative(Hash = "ignore")]
    #[derivative(PartialEq = "ignore")]
    pub path: Option<PathBuf>,
}

impl Display for NSID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref name) = self.name {
            f.write_fmt(format_args!("(NS {}, Inode {})", name.0, self.inode))
        } else if let Some(ref p) = self.pid {
            f.write_fmt(format_args!("(NS of PID {}, Inode {})", p.0, self.inode))
        } else if let Some(ref p) = self.path {
            f.write_fmt(format_args!("(NS {:?}, Inode {})", p, self.inode))
        } else {
            f.write_fmt(format_args!("(NS with inode {})", self.inode))
        }
    }
}

mod presets {
    use std::{fs, sync::Arc};

    use crate::data::*;
    use anyhow::Result;

    #[test]
    fn sample() -> Result<()> {
        let mut s = Settings::default();
        let v1 = RVethConn {
            target: NSRef::Root,
        };
        s.profiles.insert(
            ProfileName("geph1".into()),
            Arc::new(SubjectProfile {
                vconnections: vec![v1.clone()],
                proxies: vec![],
                procs: RProcTasks::default(),
                tun2socks: RTUNedSocks {
                    src: AddrRef::VConn(v1, false, 9909),
                    enable: true,
                },
                dnsproxy: DNSProxyR {
                    enable: true,
                    ..Default::default()
                },
            }),
        );
        s.flatpak.insert(
            FlatpakID("com.belmoussaoui.Decoder".into()),
            ProfileName("geph1".into()),
        );
        let se = serde_json::to_string_pretty(&s)?;
        let re: Settings = serde_json::from_str(&se)?;
        let mut ro: PathBuf = env!("CARGO_MANIFEST_DIR").parse()?;
        ro.push("testing/geph1.json");
        fs::write(ro, se)?;
        assert_eq!(s, re);
        Ok(())
    }

    #[test]
    fn derivative_for_pass() -> Result<()> {
        let mut de = Derivative::default();
        de.root_ns = NSID::proc()?;
        let se = serde_json::to_string_pretty(&de)?;
        let mut ro: PathBuf = env!("CARGO_MANIFEST_DIR").parse()?;
        ro.push("testing/pass.json");
        fs::write(ro, se)?;
        Ok(())
    }
}
