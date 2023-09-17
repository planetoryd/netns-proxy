use crate::{
    netlink::{NSCreate, Netns, Subject},
    nft::{Mergeable, NftState},
    schedule::{
        DerivationEvent, DeriveRes, Dump, Load, NMap, NSMap, NSWaitfree, NetnspState, Scheduler,
    },
    state::ExistenceMap,
    sub::{NLFilter, SubHub},
    util::{self, KillMask, TaskCtx},
};
use bimap::BiMap;
use derivative::Derivative;
use futures::Future;
use ipnetwork::IpNetwork;
use ron::ser::PrettyConfig;
use rtnetlink::netlink_sys::{AsyncSocket, TokioSocket};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BinaryHeap, HashMap, HashSet},
    fmt::Display,
    hash::Hash,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::{fd::RawFd, unix::process::CommandExt},
    path::PathBuf,
    process::Stdio,
    str::FromStr,
    sync::Arc,
};

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt},
    process::Command,
};

use crate::{
    ctrl::ToServer,
    netlink::{NLTracked, NetnsMap, VPairKey},
    nft,
    sub::{NsubState, ToMain, ToSub},
    util::{watch_both, TaskOutput},
};
use tokio::{self, io::AsyncReadExt};

use anyhow::{anyhow, bail, ensure, Context, Ok, Result};

use crate::netlink::nl_ctx;
use crate::util::error::*;
use crate::util::*;

// generated info and state store
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Derivative {
    // separate maps, separate indexing
    pub named_ns: HashMap<ProfileName, SubjectInfo<NamedV>>,
    pub flatpak: HashMap<Pid, SubjectInfo<FlatpakV>>,
    pub root_ns: Option<NSID>,
}

pub trait DerivativeT {
    type V: VSpecifics;
    type K;
    async fn may_derive(
        &mut self,
        k: &Self::K,
        func: impl Future<Output = Result<SubjectInfo<Self::V>>>,
        sche: &mut impl DerivationEvent<UniqueInstance>,
    ) -> Result<DeriveRes>;
}

impl<K: Eq + PartialEq + Hash + Clone, V: VSpecifics> DerivativeT for HashMap<K, SubjectInfo<V>> {
    type V = V;
    type K = K;
    async fn may_derive(
        &mut self,
        k: &Self::K,
        func: impl Future<Output = Result<SubjectInfo<Self::V>>>,
        sche: &mut impl DerivationEvent<UniqueInstance>,
    ) -> Result<DeriveRes> {
        if self.contains_key(k) {
            sche.on_visit(self.get(k).unwrap().id.clone());
            Ok(DeriveRes::Existent)
        } else {
            let p = func.await?;
            let i = p.id.clone();
            self.insert(k.to_owned(), p);
            sche.on_derive(i);
            Ok(DeriveRes::New)
        }
    }
}

impl Load for Derivative {
    async fn load_or_create_async(paths: &ConfPaths) -> Result<Self> {
        if paths.derivative.exists() {
            let mut file = tokio::fs::File::open(&paths.derivative).await?;
            let mut contents = String::new();
            file.read_to_string(&mut contents).await?;
            let mut k: Derivative = ron::from_str(&contents)?;
            k.check_update_rootns()?;
            Ok(k)
        } else {
            let mut n = Derivative::default();
            n.init();
            Ok(n)
        }
    }
    fn load_or_create(paths: &ConfPaths) -> Result<Self> {
        if paths.derivative.exists() {
            let mut file = std::fs::File::open(paths.derivative)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            let mut k: Derivative = ron::from_str(&contents)?;
            k.check_update_rootns()?;
            Ok(k)
        } else {
            let mut n = Derivative::default();
            n.init();
            Ok(n)
        }
    }
}

impl Dump for Derivative {
    async fn dump_async(&self, paths: &ConfPaths) -> Result<()> {
        let derivative = ron::ser::to_string_pretty(self, PrettyConfig::new())?;
        let mut file = tokio::fs::File::create(&paths.derivative).await?;
        file.write_all(derivative.as_bytes()).await?;
        Ok(())
    }
    fn dump(&self, paths: &ConfPaths) -> Result<()> {
        let derivative = ron::ser::to_string_pretty(self, PrettyConfig::new())?;
        let mut file = std::fs::File::create(paths.derivative)?;
        file.write_all(derivative.as_bytes())?;
        Ok(())
    }
}

impl Load for Settings {
    async fn load_or_create_async(paths: &ConfPaths) -> Result<Self> {
        let settings: Settings;
        if paths.settings.exists() {
            let mut file = tokio::fs::File::open(&paths.settings).await?;
            let mut contents = String::new();
            file.read_to_string(&mut contents).await?;
            settings = serde_json::from_str(&contents)?;
        } else {
            settings = Default::default();
            log::info!("Generating default settings");
            let serialized = serde_json::to_string_pretty(&settings)?;
            let mut file = tokio::fs::File::create(&paths.settings).await?;
            file.write_all(serialized.as_bytes()).await?;
            log::warn!("Blank settings written to {:?}", &paths.settings);
        }
        Ok(settings)
    }
    fn load_or_create(paths: &ConfPaths) -> Result<Self> {
        let settings: Settings;
        if paths.settings.exists() {
            let mut file = std::fs::File::open(paths.settings)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            settings = serde_json::from_str(&contents)?;
        } else {
            settings = Default::default();
            log::info!("Generating default settings");
            let serialized = serde_json::to_string_pretty(&settings)?;
            let mut file = std::fs::File::create(paths.settings)?;
            file.write_all(serialized.as_bytes())?;
            log::warn!("Blank settings written to {:?}", &paths.settings);
        }
        Ok(settings)
    }
}

impl From<ProfileName> for SubjectKey {
    fn from(value: ProfileName) -> Self {
        Self::Named(value)
    }
}

impl From<Pid> for SubjectKey {
    fn from(value: Pid) -> Self {
        Self::Flatpak(value)
    }
}

trait PidMap: Sized {
    /// retain only running processes
    async fn retain_running(&mut self) -> Result<Self>;
}

impl<T> PidMap for HashMap<Pid, T> {
    async fn retain_running(&mut self) -> Result<Self> {
        let mut pids = HashSet::new();
        let mut entries = tokio::fs::read_dir("/proc").await?;

        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name();

            if let Result::Ok(pid) = file_name.to_string_lossy().parse::<u32>() {
                pids.insert(pid);
            }
        }
        let rm: HashMap<_, _> = self.extract_if(|p, _v| !pids.contains(&p.0)).collect();
        Ok(rm)
    }
}

impl Derivative {
    pub fn init(&mut self) -> Result<()> {
        self.check_update_rootns()?;
        log::warn!(
            "The netns of current process will be assumed to be root_ns. It's recorded in the derivative file for the use of all later launches"
        );
        Ok(())
    }
    pub fn check_update_rootns(&mut self) -> Result<()> {
        if let Some(ns) = &self.root_ns {
            ns.ensure_sync().context("Root NS mismatch. You are running this process from a different NS than what was recorded.")?;
        } else {
            self.root_ns = Some(NSIDFrom::Root.to_id_sync(NSCreate::empty())?);
        }
        Ok(())
    }
    pub async fn clean_flatpak(
        &mut self,
        set: &HashMap<FlatpakID, ProfileName>,
        sys: &NetnsMap<impl NMap<V = Netns>>,
        sche: &mut impl DerivationEvent<UniqueInstance>,
    ) -> Result<()> {
        let mut rm: HashMap<_, _> = self
            .flatpak
            .extract_if(|_p, s| !set.contains_key(&s.specifics.id))
            .collect();
        let mut rm2 = self.flatpak.retain_running().await?;
        rm.extend(rm2.drain());
        for (_, s) in rm {
            s.garbage_collect(sys, &self, sche).await?;
        }
        for (_, s) in self.flatpak {
            s.ns.ensure().await?;
        }
        Ok(())
    }
    pub async fn clean_named(
        &mut self,
        conf: &HashMap<ProfileName, Arc<SubjectProfile>>,
        sys: &NetnsMap<impl NMap<V = Netns>>,
        sche: &mut impl DerivationEvent<UniqueInstance>,
    ) -> Result<()> {
        let rm: HashMap<_, _> = self
            .named_ns
            .extract_if(|e, _| !conf.contains_key(e))
            .collect();
        for (_, s) in rm {
            s.garbage_collect(sys, &self, sche).await?;
        }
        for (_, s) in self.named_ns {
            s.ns.ensure().await?;
        }
        Ok(())
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

impl ProfileName {
    pub fn ns_path(self) -> PathBuf {
        use rtnetlink::NetworkNamespace;
        NetworkNamespace::path_of(self.0)
    }
}

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

#[derive(Default, Debug)]
pub struct Remainder<NSKey: Hash + Clone + Eq> {
    map: HashMap<NSKey, NSEffect>,
    /// Modified as compared to the previous version of this struct
    modified: HashSet<NSKey>,
}

/// Temporary place to keep effect
#[derive(Debug)]
pub struct NSEffect {
    pub nft: NftState,
}

impl<NSKey: Hash + Clone + Eq> Remainder<NSKey> {
    pub fn nft_merge(&mut self, ns: NSKey, Δ: NSEffect) -> Result<()> {
        match self.map.entry(ns) {
            Entry::Vacant(v) => {
                v.insert(Δ);
            }
            Entry::Occupied(mut x) => {
                x.get_mut().merge(Δ)?;
            }
        }
        self.modified.insert(ns);
        Ok(())
    }
    /// Assumes that sockets exist
    pub async fn apply(
        &mut self,
        nf: &NLFilter<impl NMap<V = TokioSocket, K = NSKey>>,
    ) -> Result<()> {
        for e in self.modified.drain() {
            let (g, k, _) = nf.get_mut(&e).await?;
            let k = k(&mut g);
            self.map.get_mut(&e).unwrap().nft.apply(k).await?;
        }
        Ok(())
    }
}

impl Mergeable for NSEffect {
    fn merge(&mut self, Δ: Self) -> Result<()> {
        self.nft.merge(Δ.nft)
    }
}

use std::collections::hash_map::Entry;

impl<K: Hash + Clone + Eq> Mergeable for Remainder<K> {
    fn merge(&mut self, Δ: Self) -> Result<()> {
        for (k, e) in Δ.map {
            self.nft_merge(k, e)?;
        }
        Ok(())
    }
}

pub trait UnIns {
    fn new_unique<'a, N: UniqueName>(&'a mut self, unique_name: N);
    fn last_unique(&self) -> Option<&UniqueInstance>;
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
    fn last_unique(&self) -> Option<&UniqueInstance> {
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
            derivative: run_base.join("state.ron"),
            sock: run_base,
        };
        Ok(r)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SubjectProfile {
    /// veth connections between NSes
    pub vconns: Vec<RVethConn>,
    /// additional processes to start
    pub procs: RProcTasks,
    pub tun2socks: RTUNedSocks,
    pub dnsproxy: DNSProxyR,
    pub tun2proxy: TUN2ProxyR,
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

/// Addr through which the subject accesses an external object
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct AddrRef {
    /// veth conn in reference, and whether use v6 (true for v6)
    vconn: RVethConn,
    v6: bool,
    port: u16,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
/// start external processes, as daemons if it doesn't quit
pub struct RProcTasks {
    pub su: Option<CmdParams>,
    pub normal: Option<CmdParams>,
}

/// TUNified socks proxy pattern
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub enum RTUNedSocks {
    #[default]
    Disabled,
    SrcAddrPort(AddrRef),
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
pub enum DNSProxyR {
    #[default]
    Disabled,
    Enabled(DNSProxyC),
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DNSProxyC {
    #[serde(default = "SubjectProfile::default_dns_v6")]
    pub v6: bool,
    #[serde(default = "SubjectProfile::default_dns_port")]
    pub port: u16,
    // Should be Some() when in SubjectInfo. Optional when in SubjectProfile
    #[serde(default)]
    pub args: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
pub enum TUN2ProxyR {
    #[default]
    Disabled,
    Enabled(TUN2ProxyC),
}

/// TUN will be put in the subject NS
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TUN2ProxyC {
    /// Url to upstream proxy
    pub url: String,
    /// Where should network traffic be sent from
    pub put: NSRef,
    pub dns: TUN2DNS,
    /// Disabling will remove ipv6 entries from DNS (if TUN2DNS::Upstream enabled)
    #[serde(default)]
    pub ipv6: bool,
    #[serde(default)]
    pub tap: bool,
}

/// Derived
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TUN2ProxyE {
    pub source: TUN2ProxyC,
    /// resolved
    pub ns: NSID,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub enum TUN2ProxyD {
    #[default]
    Disabled,
    Enabled(TUN2ProxyE),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TUN2DNS {
    /// Resolve names with proxy
    Proxy,
    /// Resolve names through proxy
    Upstream(IpAddr),
}

impl From<TUN2DNS> for Option<IpAddr> {
    fn from(value: TUN2DNS) -> Self {
        match value {
            TUN2DNS::Proxy => None,
            TUN2DNS::Upstream(s) => Some(s),
        }
    }
}

impl Default for DNSProxyC {
    fn default() -> Self {
        Self {
            v6: SubjectProfile::default_dns_v6(),
            port: SubjectProfile::default_dns_port(),
            args: None,
        }
    }
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
pub struct CmdParams {
    pub program: String,
    pub argv: Vec<String>,
    pub user: Option<String>,
}

pub const TUN_NAME: &str = "s_tun";

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SubjectInfo<V: VSpecifics> {
    pub id: UniqueInstance,
    pub ns: NSID,
    pub vaddrs: HashMap<NSID, VethConn>,
    pub specifics: V, // variant specific info
    pub dnsproxy: DNSProxyR,
    /// socks5 proxy
    #[serde(default)]
    pub tun2socks: Option<SocketAddr>, // ip without CIDR
    /// Resolved NS to put tun2proxy
    pub tun2proxy: TUN2ProxyD,
    pub deps: BiMap<NSRef, NSID>,
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

impl VSpecifics for NamedV {
    fn msg_run(&self, si: SubjectInfo<Self>) -> ToSub {
        ToSub::Named(si)
    }
}
impl VSpecifics for FlatpakV {
    fn msg_run(&self, si: SubjectInfo<Self>) -> ToSub {
        ToSub::Flatpak(si)
    }
}
/// variant specifics
pub trait VSpecifics: Into<NSRef> + Clone {
    fn msg_run(&self, si: SubjectInfo<Self>) -> ToSub;
}

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

#[derive(Serialize, Deserialize, Default, Clone, Debug, Hash, PartialEq, Eq, Copy)]
#[serde(transparent)]
pub struct Pid(pub u32);

/// Uniqueness has to be guaranteed in every field.
#[derive(Derivative, Clone, Debug, Serialize, Deserialize)]
#[derivative(PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct UniqueInstance {
    id: u16,
    /// Unique name
    #[derivative(PartialEq = "ignore")]
    #[derivative(PartialOrd = "ignore")]
    #[derivative(Ord = "ignore")]
    #[derivative(Hash = "ignore")]
    name: String,
    /// Netlink compliant name
    #[derivative(PartialEq = "ignore")]
    #[derivative(PartialOrd = "ignore")]
    #[derivative(Ord = "ignore")]
    #[derivative(Hash = "ignore")]
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
    async fn resolve_global(&self, global: &NetnspState, uq: &UniqueInstance, v: &V) -> Result<D>;
}

pub trait ResolvableS<V: VSpecifics, D> {
    fn resolve_subject(&self, subject: &SubjectInfo<V>) -> Result<D>;
}

impl NSRef {
    pub async fn resolve_derivative<'a>(&'a self, de: &'a Derivative) -> Result<NSID> {
        match self {
            Self::Root => Ok(de.root_ns.as_ref().unwrap().to_owned()),
            Self::Pid(p) => {
                let x = if let Some(k) = de.flatpak.get(p) {
                    k.ns.clone()
                } else {
                    NSIDFrom::Pid(p.clone()).to_id(NSCreate::empty()).await?
                };
                Ok(x)
            }
            Self::Named(n) => {
                let x = if let Some(k) = de.named_ns.get(n) {
                    k.ns.clone()
                } else {
                    NSIDFrom::Named(n.clone()).to_id(NSCreate::Named).await?
                };
                Ok(x)
            }
        }
    }
}

impl<V: VSpecifics> ResolvableS<V, Option<SocketAddr>> for RTUNedSocks {
    fn resolve_subject(&self, subject: &SubjectInfo<V>) -> Result<Option<SocketAddr>> {
        match self {
            RTUNedSocks::Disabled => Ok(None),
            RTUNedSocks::SrcAddrPort(src) => src.resolve_subject(subject).map(Option::from),
        }
    }
}

// AddrRef is situated in a Subject's Info. It refers to a certain Target NS
impl<V: VSpecifics> ResolvableS<V, SocketAddr> for AddrRef {
    fn resolve_subject(&self, subject: &SubjectInfo<V>) -> Result<SocketAddr> {
        let vc = subject
            .vaddrs
            .get(&self.vconn.target)
            .ok_or(DevianceError)?;
        let ipn = if self.v6 { vc.ip6_vb } else { vc.ip_vb };
        Ok(SocketAddr::new(ipn.ip(), self.port))
    }
}
impl RC for AddrRef {}

/// marker trait for chained resolution
trait RC {}

impl<D: RC, T: ResolvableS<NamedV, D>> ResolvableG<NamedV, D> for T {
    async fn resolve_global(
        &self,
        global: &NetnspState,
        _uq: &UniqueInstance,
        v: &NamedV,
    ) -> Result<D> {
        let subject = global.derivative.named_ns.get(&v.0).ok_or(DevianceError)?;
        self.resolve_subject(subject)
    }
}

impl<D: RC, T: ResolvableS<FlatpakV, D>> ResolvableG<FlatpakV, D> for T {
    async fn resolve_global(
        &self,
        global: &NetnspState,
        _uq: &UniqueInstance,
        v: &FlatpakV,
    ) -> Result<D> {
        let subject = global.derivative.flatpak.get(&v.pid).ok_or(DevianceError)?;
        self.resolve_subject(subject)
    }
}

impl TUN2ProxyR {
    pub async fn resolve_derivative<'a>(&'a self, de: &'a Derivative) -> Result<TUN2ProxyD> {
        match self {
            Self::Disabled => Ok(TUN2ProxyD::Disabled),
            Self::Enabled(k) => Ok(TUN2ProxyD::Enabled(TUN2ProxyE {
                source: k.clone(),
                ns: k.put.resolve_derivative(de).await?,
            })),
        }
    }
}

/// It's possible that dns args might need paras from global state. Therefore as such
impl<V: VSpecifics> ResolvableG<V, DNSProxyR> for DNSProxyR {
    async fn resolve_global(
        &self,
        _global: &NetnspState,
        _uq: &UniqueInstance,
        _v: &V,
    ) -> Result<Self> {
        match self {
            Self::Enabled(c) => {
                let mut rsv = c.clone();
                if rsv.args.is_none() {
                    let p = c.port.to_string();
                    let r = if c.v6 {
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
                    rsv.args = Some(ve);
                }
                Ok(Self::Enabled(rsv))
            }
            _ => Ok(self.clone()),
        }
    }
}

impl<V: VSpecifics> ResolvableS<V, VethConn> for RVethConn {
    fn resolve_subject(&self, subject: &SubjectInfo<V>) -> Result<VethConn> {
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
    async fn resolve_global(
        &self,
        global: &NetnspState,
        uq: &UniqueInstance,
        v: &V,
    ) -> Result<SubjectInfo<V>> {
        let runtime: NSRef = (v.clone()).into();
        let mut s = SubjectInfo {
            id: uq.clone(),
            vaddrs: HashMap::new(),
            specifics: v.clone(),
            // which creates the NS
            ns: runtime
                .resolve_derivative(&global.derivative)
                .await?
                .to_owned(),
            dnsproxy: self.dnsproxy.resolve_global(global, uq, v).await?,
            tun2socks: None,
            tun2proxy: self
                .tun2proxy
                .resolve_derivative(&global.derivative)
                .await?,
            deps: Default::default(),
        };
        for vc in self.vconns.iter() {
            let v1 = vc.resolve_subject(&s)?;
            let ns = vc.target.resolve_derivative(&global.derivative).await?;
            s.vaddrs.insert(ns.clone(), v1);
            s.deps.insert(vc.target.clone(), ns);
        }
        s.tun2socks = self.tun2socks.resolve_subject(&s)?;

        Ok(s)
    }
}

#[derive(Derivative, Serialize, Deserialize, Debug, Clone)]
#[serde_with::skip_serializing_none]
#[derivative(Hash, PartialEq, Eq)]
pub struct NSID {
    /// Only Inode is used as key
    pub inode: u64,
    #[derivative(Hash = "ignore")]
    #[derivative(PartialEq = "ignore")]
    pub from: NSIDFrom,
    /// Inode match with the from, and NS exists
    /// It may be thread/process-dependent
    #[serde(skip_serializing)]
    #[serde(default)]
    #[derivative(Hash = "ignore")]
    #[derivative(PartialEq = "ignore")]
    pub validated: bool,
    /// Cached path, only valid when validated
    #[serde(skip_serializing)]
    #[serde(default)]
    #[derivative(Hash = "ignore")]
    #[derivative(PartialEq = "ignore")]
    pub path: Option<PathBuf>,
}

impl NSID {
    pub fn as_key(&self) -> NSIDKey {
        NSIDKey { inode: self.inode }
    }
}

#[derive(Hash, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Copy, Default)]
pub struct NSIDKey {
    pub inode: u64,
}

#[derive(Derivative, Serialize, Deserialize, Clone)]
#[derivative(Debug)]
pub enum NSIDFrom {
    #[derivative(Debug = "transparent")]
    Named(ProfileName),
    #[derivative(Debug = "transparent")]
    Pid(Pid),
    #[derivative(Debug = "transparent")]
    Path(PathBuf),
    Root,
    Thread,
}

// bincode can not handle #[serde_with::skip_serializing_none]

/// Test serde for state file
/// 1. should support enum as map keys
/// 2. should support skip_serializing
#[test]
fn test_serde_state() -> Result<()> {
    let ns = NSIDFrom::Thread.to_id_sync(NSCreate::empty())?;

    let ser: Vec<u8> = util::to_vec_internal(&ns)?;
    let de: NSID = util::from_vec_internal(&ser)?;

    let ser = util::to_vec_internal(&ToServer::ReloadConfig)?;

    let n = ToMain::FD(crate::sub::FDRes::TAP);
    let ser: Vec<u8> = util::to_vec_internal(&n)?;
    let de: ToMain = util::from_vec_internal(&ser)?;

    let mut m: HashMap<NSRef, i32> = Default::default();
    m.insert(NSRef::Pid(Pid(2)), 3);
    let ser: Vec<u8> = util::to_vec_internal(&m)?;
    let de: HashMap<NSRef, i32> = util::from_vec_internal(&ser)?;

    Ok(())
}

impl Display for NSID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("[NS{}-{:?}]", self.inode, self.from))
    }
}

mod presets {
    use std::{fs, sync::Arc};

    use crate::data::*;

    #[test]
    fn sample() -> Result<()> {
        let mut s = Settings::default();
        let v1 = RVethConn {
            target: NSRef::Root,
        };
        s.profiles.insert(
            ProfileName("geph".into()),
            Arc::new(SubjectProfile {
                vconns: vec![v1.clone()],
                procs: RProcTasks::default(),
                tun2socks: RTUNedSocks::SrcAddrPort(AddrRef {
                    port: 9909,
                    vconn: v1.clone(),
                    v6: false,
                }),
                dnsproxy: DNSProxyR::Enabled(DNSProxyC::default()),
                tun2proxy: TUN2ProxyR::Disabled,
            }),
        );
        s.profiles.insert(
            ProfileName("i2p".into()),
            Arc::new(SubjectProfile {
                vconns: vec![v1.clone()],
                procs: RProcTasks::default(),
                tun2socks: RTUNedSocks::Disabled,
                dnsproxy: DNSProxyR::Disabled,
                tun2proxy: TUN2ProxyR::Disabled,
            }),
        );
        s.profiles.insert(
            ProfileName("geph1".into()),
            Arc::new(SubjectProfile {
                vconns: vec![
                    v1.clone(),
                    RVethConn {
                        target: NSRef::Named(ProfileName("i2p".into())),
                    },
                ],
                procs: RProcTasks::default(),
                tun2socks: RTUNedSocks::Disabled,
                dnsproxy: DNSProxyR::Disabled,
                tun2proxy: TUN2ProxyR::Disabled,
            }),
        );
        s.flatpak.insert(
            FlatpakID("com.belmoussaoui.Decoder".into()),
            ProfileName("i2p".into()),
        );
        s.flatpak.insert(
            FlatpakID("io.github.NhekoReborn.Nheko".into()),
            ProfileName("geph".into()),
        );
        let se = serde_json::to_string_pretty(&s)?;
        let re: Settings = serde_json::from_str(&se)?;
        let mut ro: PathBuf = env!("CARGO_MANIFEST_DIR").parse()?;
        ro.push("testing/geph.json");
        fs::write(ro, se)?;
        assert_eq!(s, re);

        let se = ron::ser::to_string_pretty(&s, Default::default())?;
        let mut ro: PathBuf = env!("CARGO_MANIFEST_DIR").parse()?;
        ro.push("testing/geph.ron");
        fs::write(ro, se)?;

        Ok(())
    }

    #[test]
    fn derivative_for_pass() -> Result<()> {
        let mut de = Derivative::default();
        de.root_ns = NSIDFrom::Root.to_id_sync(NSCreate::empty())?.into();
        let se = serde_json::to_string_pretty(&de)?;
        let mut ro: PathBuf = env!("CARGO_MANIFEST_DIR").parse()?;
        ro.push("testing/pass.json");
        fs::write(ro, se)?;
        Ok(())
    }
}
