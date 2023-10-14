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
#![feature(return_position_impl_trait_in_trait)]
#![feature(type_changing_struct_update)]
#![feature(adt_const_params)]
// #![allow(unused)]
#![deny(unused_must_use)]
#![allow(unused_braces)]
#![allow(incomplete_features)]
#![allow(unreachable_code)]

pub mod watcher;
pub mod flatpak;
pub mod id_alloc;
pub mod tasks;
pub mod tun2proxy;
pub mod util;
pub mod listener;
pub mod config;
pub mod probe;