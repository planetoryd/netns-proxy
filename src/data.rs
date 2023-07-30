use dashmap::DashMap;
use derivative::Derivative;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use std::{
    cell::RefCell,
    collections::{BinaryHeap, HashMap, HashSet},
    fmt::{format, Display},
    marker::ConstParamTy,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::process::CommandExt,
    path::PathBuf,
    process::Stdio,
    str::FromStr,
    sync::Arc,
};

use tokio::{io::AsyncBufReadExt, process::Command, sync::RwLock};

use crate::{
    netlink::{ConnRef, MultiNS, Netns, VPairKey},
    nft,
    sub::NsubState,
    util::{convert_strings_to_strs, perms::get_non_priv_user, DaemonSender, TaskOutput},
};
use tokio::{self, io::AsyncReadExt};

use anyhow::{Ok, Result};

use crate::util::error::*;

// generated info and state store
#[derive(Serialize, Deserialize, Default)]
pub struct Derivative {
    // separate maps, separate indexing
    pub named_ns: HashMap<ProfileName, SubjectInfo<NamedV>>,
    pub flatpak: HashMap<Pid, SubjectInfo<FlatpakV>>,
    /// could be mutiple instances per FlatpakID. for now just prefer, the first instance.
    pub flatpak_names: HashMap<FlatpakID, Pid>,
    pub ns_list: HashMap<NSRef, NSID>,
    pub root_ns: NSID,
}

impl Derivative {
    pub async fn init(&mut self) -> Result<()> {
        self.root_ns = NSID::root()?;
        Ok(())
    }
    /// clear invalid ones
    pub fn clean_flatpak(&mut self, set: &HashMap<FlatpakID, ProfileName>) {
        let mut removed = HashSet::new();
        for (p, s) in self.flatpak.iter() {
            if !set.contains_key(&s.specifics.id) {
                removed.insert(p.clone());
            }
        }
        self.flatpak.retain(|a, _| !removed.contains(a));
        // TODO: deal with flatpak_names
    }
    pub fn clean_named(&mut self, conf: &HashMap<ProfileName, Arc<SubjectProfile>>) {
        self.named_ns.retain(|e, _| conf.contains_key(e));
    }
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
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

use serde_with::{serde_as, FromInto};

pub struct NetnspState {
    // persistent
    pub derivative: Derivative,
    pub settings: Settings,
    // runtime state
    pub paths: ConfPaths,
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

#[derive(Serialize, Deserialize, Debug)]
pub struct ConfPaths {
    pub settings: PathBuf,
    pub derivative: PathBuf,
    /// directory for sockets
    pub sock: PathBuf,
}

// Each instance has a unique NetnsInfo
// identified by pid OR persistent name
pub type InstanceID = either::Either<i32, String>;

impl Default for ConfPaths {
    fn default() -> Self {
        Self {
            settings: "./conf.json".parse().unwrap(),
            derivative: "./netnsp.json".parse().unwrap(),
            sock: "./nsp/".parse().unwrap(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
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
    Flatpak(FlatpakID),
    Named(ProfileName),
}

impl From<FlatpakV> for NSRef {
    fn from(value: FlatpakV) -> Self {
        Self::Flatpak(value.id)
    }
}
impl From<NamedV> for NSRef {
    fn from(value: NamedV) -> Self {
        Self::Named(value.0)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
/// connection from subject NS to target NS
pub struct RVethConn {
    pub target: NSRef,
}

/// userland proxy. used when, for ex. the source proxy only listens on 127.1 
/// src can be the same as subject NS. 
/// ip in src ns is implied to be 127.1
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RProxy {
    pub src: NSRef,
    /// port in src ns
    pub port: u16,
    pub port_local: u16,
}
// sometimes netfilter forwarding can be hard to set up, so this can be used.

/// Addr through which the subject accesses an external object
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AddrRef {
    /// veth conn in reference, and whether use v6 (true for v6)
    VConn(RVethConn, bool, u16),
    Proxy(RProxy),
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
/// start external processes, as daemons if it doesn't quit
pub struct RProcTasks {
    pub su: Option<CmdParams>,
    pub normal: Option<CmdParams>,
}

/// TUNified socks proxy pattern
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RTUNedSocks {
    #[serde(default = "SubjectProfile::default_tun2socks")]
    pub enable: bool,
    pub src: AddrRef,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct DNSProxyR {
    #[serde(default = "SubjectProfile::default_dnsproxy")]
    pub enable: bool,
    #[serde(default = "SubjectProfile::default_dns_v6")]
    pub v6: bool,
    /// override args entirely
    pub args: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct CmdParams {
    pub program: String,
    pub argv: Vec<String>,
    pub user: Option<String>,
}

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
    #[serde(skip)]
    pub profile: Option<Arc<SubjectProfile>>,
}

impl<V: VSpecifics> SubjectInfo<V> {
    pub async fn connect(&self, mn: &mut MultiNS) -> Result<()> {
        let n = mn.new_for(self.ns.clone()).await?;
        mn.netlinks
            .insert(self.ns.clone(), ConnRef::new(Arc::new(n)));
        let nl = mn.netlinks.get(&self.ns).unwrap();
        let ns = nl.clone().to_netns(self.ns.clone()).await?;
        mn.subs.insert(self.ns.clone(), ns);
        Ok(())
    }
    pub fn assure_in_ns(&self) -> Result<()> {
        let c = NSID::proc()?;
        anyhow::ensure!(c == self.ns);
        Ok(())
    }
    pub async fn run_tun2s(&self, st: &mut NsubState) -> Result<()> {
        use crate::netlink::*;
        use crate::util::{watch_both, watch_log};
        let tun_name = "s_tun";
        let mut tun2 = std::process::Command::new("tun2socks");
        tun2.uid(st.non_priv_uid.into())
            .gid(st.non_priv_gid.into())
            .groups(&[st.non_priv_gid.into()]);
        let prxy = format!("socks5://{}", self.tun2s.unwrap().to_string());
        tun2.args(&["-device", tun_name, "-proxy", &prxy]);
        let mut tun2_async: Command = tun2.into();
        tun2_async.stdout(Stdio::piped());
        let mut tun2h = tun2_async.spawn()?;
        let stdout = tun2h.stdout.take().unwrap();
        let reader = tokio::io::BufReader::new(stdout).lines();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let pre = format!("{}/tun2socks", self.id);
        tokio::spawn(watch_log(reader, Some(tx), pre.clone()));
        rx.await?; // wait for first line to appear
        let tunk: LinkKey = tun_name.parse()?;
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

        let (t, r) = TaskOutput::subprocess(Box::pin(async move { tun2h.wait().await }), pre);
        st.dae.send(t).unwrap();

        Ok(())
    }
    pub async fn run_dnsp(&self, st: &mut NsubState) -> Result<()> {
        use crate::netlink::*;
        use crate::util::{watch_both, watch_log};
        let tun_name = "s_tun";
        let mut tun2 = std::process::Command::new("tun2socks");
        tun2.uid(st.non_priv_uid.into())
            .gid(st.non_priv_gid.into())
            .groups(&[st.non_priv_gid.into()]);
        let prxy = format!("socks5://{}", self.tun2s.unwrap().to_string());
        tun2.args(&["-device", tun_name, "-proxy", &prxy]);
        let mut tun2_async: Command = tun2.into();
        tun2_async.stdout(Stdio::piped());
        let mut tun2h = tun2_async.spawn()?;
        let stdout = tun2h.stdout.take().unwrap();
        let reader = tokio::io::BufReader::new(stdout).lines();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let pre = format!("{}/tun2socks", self.id);
        tokio::spawn(watch_log(reader, Some(tx), pre.clone()));
        rx.await?; // wait for first line to appear
        let tunk: LinkKey = tun_name.parse()?;
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

        let (t, r) = TaskOutput::subprocess(Box::pin(async move { tun2h.wait().await }), pre);
        st.dae.send(t).unwrap();

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
        f.write_fmt(format_args!("#{}/{}", self.id, self.name))
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
    fn resolve_g(&self, global: &NetnspState, uq: &UniqueInstance, v: &V) -> Result<D>;
}

pub trait ResolvableS<V: VSpecifics, D> {
    fn resolve(&self, subject: &SubjectInfo<V>) -> Result<D>;
}

impl NSRef {
    pub fn resolve_d<'a>(&'a self, de: &'a Derivative) -> Result<&NSID> {
        match self {
            Self::Root => Ok(&de.root_ns),
            Self::Flatpak(f) => {
                let p = de.flatpak_names.get(f).ok_or(DevianceError)?;
                let x = de.flatpak.get(p).ok_or(DevianceError)?;
                Ok(&x.ns)
            }
            Self::Named(n) => {
                let x = de.named_ns.get(n).ok_or(DevianceError)?;
                Ok(&x.ns)
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
    fn resolve_g(&self, global: &NetnspState, uq: &UniqueInstance, v: &NamedV) -> Result<D> {
        let subject = global.derivative.named_ns.get(&v.0).ok_or(DevianceError)?;
        self.resolve(subject)
    }
}

impl<D: RC, T: ResolvableS<FlatpakV, D>> ResolvableG<FlatpakV, D> for T {
    fn resolve_g(&self, global: &NetnspState, uq: &UniqueInstance, v: &FlatpakV) -> Result<D> {
        let subject = global.derivative.flatpak.get(&v.pid).ok_or(DevianceError)?;
        self.resolve(subject)
    }
}

impl<V: VSpecifics> ResolvableG<V, Vec<String>> for DNSProxyR {
    fn resolve_g(&self, global: &NetnspState, uq: &UniqueInstance, v: &V) -> Result<Vec<String>> {
        match &self.args {
            None => {
                let r = if self.v6 {
                    vec![
                        "-l",
                        "127.0.0.1",
                        "-l",
                        "127.0.0.53",
                        "-l",
                        "::1",
                        "-p",
                        "53",
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
                        "53",
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
    fn resolve_g(
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
            ns: re.resolve_d(&global.derivative)?.to_owned(),
            dnsp_args: None,
            tun2s: None,
            profile: Some(self.to_owned()),
        };
        for vc in self.vconnections.iter() {
            let v1 = vc.resolve(&s)?;
            s.vaddrs.insert(vc.target.clone(), v1);
        }
        s.dnsp_args = Some(self.dnsproxy.resolve_g(global, uq, v)?);
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
