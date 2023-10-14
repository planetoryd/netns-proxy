use std::{
    collections::HashMap, default, fs::create_dir_all, net::IpAddr, path::PathBuf, sync::Arc,
};

use crate::{flatpak::FlatpakID, id_alloc};
use amplify::s;
use anyhow::bail;
use nix::sched::CloneFlags;
use schematic::{Config, ConfigLoader, Format};
use serde::{Deserialize, Serialize};
use std::result::Result as SResult;

#[test]
fn test() {
    let k = ConfigLoader::<ServerConf>::new().load().unwrap();
    Format::Json;
    println!("{:?}", &k.config);
}

#[test]
fn test_serve() {}

#[derive(Config, Debug, Serialize, Clone, Deserialize)]
pub struct ServerConf {
    #[setting(default = "/usr/bin/slirp4netns")]
    pub slirp4netns: PathBuf,
    /// Socket path
    #[setting(default = "/var/lib/netns-proxy/sock")]
    pub server: PathBuf,
    /// Directory for tuntap confs
    #[setting(default = "/run/netns-proxy/tuntap/")]
    pub tuntap_conf: PathBuf,
}

pub struct Validated<T>(pub T);

impl TryFrom<ServerConf> for Validated<ServerConf> {
    type Error = anyhow::Error;
    fn try_from(value: ServerConf) -> SResult<Self, Self::Error> {
        if !value.slirp4netns.exists() {
            bail!("slirp4netns not available, as specified in the config");
        }
        create_dir_all(value.server.parent().unwrap())?;
        create_dir_all(value.tuntap_conf.parent().unwrap())?;

        Ok(Validated(value))
    }
}

pub trait ConfFile {
    fn conf_file_name(&self) -> String;
}

impl ConfFile for id_alloc::ID {
    fn conf_file_name(&self) -> String {
        self.to_string()
    }
}

impl Validated<ServerConf> {
    pub fn tuntap_conf_path(&self, subject: impl ConfFile) -> PathBuf {
        let mut path = self.0.tuntap_conf.clone();
        path.set_file_name(subject.conf_file_name());
        path
    }
}

#[derive(Config, Debug, Serialize)]
pub struct Profiles {
    pub flatpak: HashMap<FlatpakID, ProfileName>,
    pub profiles: HashMap<ProfileName, TUN2Proxy>,
}

pub type ProfilesA = Arc<Profiles>;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct ProfileName(String);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Config)]
pub struct TUN2Proxy {
    /// Url to upstream proxy
    #[setting(default = "socks5://127.0.0.1:9909")]
    pub url: String,
    // /// Where should network traffic be sent from, ie. the NS where Tun2proxy is run
    // pub put: NSID,
    pub dns: TUN2DNS,
    /// Disabling will remove Ipv6 entries from DNS (when TUN2DNS::Upstream is enabled)
    #[serde(default)]
    pub ipv6: bool,
    /// Treat the FD as Tap
    #[serde(default)]
    pub tap: bool,
    #[setting(default = 1500)]
    pub mtu: usize,
    pub setns: WCloneFlags,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub enum TUN2DNS {
    /// Resolve names with proxy. This is usually better
    #[default]
    Proxy,
    /// Resolve names through proxy
    Upstream(IpAddr),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WCloneFlags(#[serde(with = "int_repr")] pub CloneFlags);

impl Default for WCloneFlags {
    fn default() -> Self {
        Self(CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWUSER)
    }
}

mod int_repr {
    use libc::c_int;
    use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

    type IntRep = c_int;
    type Flags = super::CloneFlags;

    pub fn serialize<S>(date: &Flags, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        date.bits().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Flags, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw: IntRep = IntRep::deserialize(deserializer)?;
        Flags::from_bits(raw).ok_or(serde::de::Error::custom(format!(
            "Unexpected flags value {}",
            raw
        )))
    }
}
