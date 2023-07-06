use crate::watcher::ActiveProfiles;

use serde::{Deserialize, Serialize};

use std::collections::HashMap;

use tokio::{self, io::AsyncReadExt};



// generated info and state store
#[derive(Serialize, Deserialize, Default)]
pub struct ConfigRes {
    // resultant/generated info for each persistent/named netns
    pub namedns: HashMap<String, NetnsInfo>,
    // Flatpak instance pids to profile names. Transient.
    pub flatpak: Option<ActiveProfiles>,
    pub root_inode: u64,
    // Counter, for any number x > counter such that x is never used
    // which ensures non-collision within the scope of one ConfigRes
    // currently not in use. I don't bother deleting it
    pub counter: u16,
}

// It may contain secret proxy parameters, so let's just consider them a secret as a whole
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Secret {
    // netns_name to params
    // aka, Profiles
    pub params: HashMap<String, NetnsParams>,
    // Flatpak app IDs to profile names
    pub flatpak: HashMap<String, String>,
}

pub struct NetnspState {
    pub res: ConfigRes,
    pub conf: Secret,
    pub paths: ConfPaths,
    pub nft_refresh_once: bool,
}

pub struct ConfPaths {
    pub conf: String,
    pub res: String,
}

// Each instance has a unique NetnsInfo
// identified by pid OR persistent name
pub type InstanceID = either::Either<i32, String>;

impl Default for ConfPaths {
    fn default() -> Self {
        Self {
            conf: "./secret.json".to_owned(),
            res: "./netnsp.json".to_owned(),
        }
    }
}

// aka, Profiles
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct NetnsParams {
    // the program to be run along
    // it is run as non-root, but not sandboxed too.
    pub cmd: Option<NetnsParamCmd>,
    // tun target port, defaults to 9909
    pub tunport: Option<u32>,
    // whether you want to chain proxies
    // set to true and Tun2socks will direct traffic to socks5://target_ip:hport
    // set to false and traffic will be directed to socks5:://veth_host:hport
    #[serde(default)]
    pub chain: bool,
    // if you have an ipv6 only proxy
    // this would force all DNS to go ipv6
    #[serde(default)]
    pub ipv6: bool,
    pub dns_argv: Option<Vec<String>>,
    // this will be run as root
    pub su_cmd: Option<NetnsParamCmd>,
    // establish a veth connection to a named netns
    pub connect: Option<String>,
    // enable tun2socks. both default to true
    pub tun2socks: Option<bool>,
    // enable dnsproxy
    pub dnsproxy: Option<bool>,
    // expose a port from localhost
    // WARN: the external port will be expose_port + 1
    pub expose_port: Option<u16>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct NetnsParamCmd {
    pub program: String,
    pub argv: Vec<String>,
    pub user: Option<String>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct NetnsInfo {
    pub base_name: String, // has no length limit
    pub subnet_veth: String,
    pub subnet6_veth: String,
    pub ip_vh: String,
    pub ip6_vh: String,
    pub ip_vn: String,
    pub ip6_vn: String,
    // veth name for connecting the root ns
    pub veth_base_name: String, // veth names have length limit
    pub id: u16,                // unique
    // veth ip of the other end of NS->NS veth connection
    // typicall intended for TUN2socks
    pub tun_ip: Option<String>, // ip without CIDR
    // base name of NS->NS veth
    pub link_base_name: Option<String>,
}
