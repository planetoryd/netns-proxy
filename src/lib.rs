#![feature(negative_impls)]
#![feature(ip)]
#![feature(async_closure)]
#![feature(async_fn_in_trait)]
#![feature(exit_status_error)]
#![feature(setgroups)]
#![feature(get_mut_unchecked)]
#![feature(adt_const_params)]
#![feature(assert_matches)]
#![feature(generators, generator_trait)]

pub mod data;
pub mod netlink;
pub mod nft;
pub mod sub;
pub mod tcproxy;
pub mod util;
pub mod watcher;


// Standard procedure
// Creates various netns, base-vpn, socks, i2p, lokinet, un-firewalled
// Kill other running processes, suspected
// Fork, setns, drop privs, start daemons
