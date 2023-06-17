use mnl;
use nftnl::{
    nft_expr, nftnl_sys::libc, Batch, Chain, FinalizedBatch, MsgType, ProtoFamily, Rule, Table,
};
use std::{
    ffi::{self, CString},
    io,
    net::Ipv4Addr,
};

use anyhow::{Ok, Result};

const TABLE_NAME: &str = "netnsp";
const FO_CHAIN: &str = "block-forward";

pub fn apply_block_forwad(veth_list: &[&str]) -> Result<()> {
    log::info!("applying nft rules for {:?}", veth_list);

    let mut batch = Batch::new();
    let table = Table::new(&CString::new(TABLE_NAME).unwrap(), ProtoFamily::Inet);
    batch.add(&table, MsgType::Del); // remove it first. otherwise it gets duplicates
    batch.add(&table, MsgType::Add);
    let mut fo_chain = Chain::new(&CString::new(FO_CHAIN).unwrap(), &table);
    fo_chain.set_policy(nftnl::Policy::Accept); // we don't drop all packets by default. the decision is up to the user
    fo_chain.set_hook(nftnl::Hook::Forward, 0);
    // target the packets that would be forwarded, priority doesn't matter because it will be traversed eventually
    batch.add(&fo_chain, MsgType::Add);

    for s in veth_list {
        batch.add(&drop_interface_rule(s, &fo_chain)?, MsgType::Add);
    }

    let finalized_batch = batch.finalize();

    // Send the entire batch and process any returned messages.
    send_and_process(&finalized_batch)?;

    Ok(())
}

fn send_and_process(batch: &FinalizedBatch) -> Result<()> {
    // Create a netlink socket to netfilter.
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
    // Send all the bytes in the batch.
    socket.send_all(batch)?;

    // Try to parse the messages coming back from netfilter. This part is still very unclear.
    let portid = socket.portid();
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let very_unclear_what_this_is_for = 2;
    while let Some(message) = socket_recv(&socket, &mut buffer[..])? {
        match mnl::cb_run(message, very_unclear_what_this_is_for, portid)? {
            mnl::CbResult::Stop => {
                break;
            }
            mnl::CbResult::Ok => (),
        }
    }
    Ok(())
}

fn socket_recv<'a>(socket: &mnl::Socket, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>> {
    let ret = socket.recv(buf)?;
    if ret > 0 {
        Ok(Some(&buf[..ret]))
    } else {
        Ok(None)
    }
}

fn drop_interface_rule<'L>(name: &str, chain: &'L Chain) -> Result<Rule<'L>> {
    let mut r = Rule::new(&chain);
    let i = iface_index(name)?;

    r.add_expr(&nft_expr!(meta iif));
    r.add_expr(&nft_expr!(cmp == i));
    r.add_expr(&nft_expr!(verdict drop));

    Ok(r)
}

// Look up the interface index for a given interface name.
fn iface_index(name: &str) -> Result<libc::c_uint> {
    let c_name = CString::new(name)?;
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(index)
    }
}
