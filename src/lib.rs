#![feature(negative_impls)]
#![feature(ip)]
#![feature(async_closure)]
#![feature(async_fn_in_trait)]
#![feature(exit_status_error)]
#![feature(setgroups)]
#![feature(get_mut_unchecked)]
#![feature(assert_matches)]
#![feature(generators, generator_trait)]
#![feature(error_generic_member_access)]
#![feature(associated_type_defaults)]
#![feature(iterator_try_collect)]
#![feature(hash_extract_if)]
#![feature(let_chains)]
#![feature(impl_trait_in_assoc_type)]
#![feature(decl_macro)]
#![feature(generic_const_exprs)]
#[allow(unused_braces)]

pub mod data;
pub mod netlink;
pub mod nft;
pub mod sub;
pub mod util;
pub mod watcher;
pub mod ctrl;
pub mod state;
pub mod tun2proxy;
pub mod schedule;

// Standard procedure
// Creates various netns, base-vpn, socks, i2p, lokinet, un-firewalled
// Kill other running processes, suspected
// Fork, setns, drop privs, start daemons
