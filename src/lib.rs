#![feature(ip)]
#![feature(async_closure)]
#![feature(async_fn_in_trait)]
#![feature(exit_status_error)]
#![feature(setgroups)]
#![feature(get_mut_unchecked)]

use nix::libc::{kill, SIGTERM};

use std::collections::HashMap;

use sysinfo::{self, PidExt, ProcessExt, System, SystemExt};
use tokio::{self};
pub mod data;
pub mod configurer;
mod nft;
pub mod sub;
pub mod tcproxy;
pub mod util;
pub mod watcher;

use data::*;
use configurer::*;


// Standard procedure
// Creates various netns, base-vpn, socks, i2p, lokinet, un-firewalled
// Kill other running processes, suspected
// Fork, setns, drop privs, start daemons
