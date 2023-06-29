use rustables::{
    expr::{Cmp, CmpOp, Immediate, Meta, MetaType, VerdictKind},
    iface_index, list_chains_for_table, list_rules_for_chain, list_tables, Batch, Chain, Hook,
    MsgType, ProtocolFamily, Rule, Table,
};
use std::collections::{HashMap, HashSet};

use anyhow::{Ok, Result};

pub const TABLE_NAME: &str = "netnsp";
pub const FO_CHAIN: &str = "block-forward";

#[derive(Default, Debug)]
pub struct NftState {
    // name -> table. indexed
    tables: HashMap<String, NftTable>,
}

#[derive(Default, Debug)]
pub struct NftTable {
    table: Table,
    chains: HashMap<String, NftChain>,
}

#[derive(Default, Debug)]
pub struct NftChain {
    chain: Chain,
    rules: HashSet<Rule>,
    // I think they are not ordered
}

// it's actually quite awkward to spend so much effort synchronizing the nft state and local state.

// ensure those rules exist
// if not, incrementally update
pub fn ensure_rules(proposal: NftState) -> Result<()> {
    let ts: Vec<Table> = list_tables()?;
    let e_set: HashSet<&String> = ts.iter().flat_map(|table| table.get_name()).collect();
    // do a quick scan for consistency, and if diff is small, update incrementally, else remove & re-add
    let mut batch: Batch = Batch::new();
    for (name, ta) in proposal.tables {
        if e_set.contains(&name) {
            // the comparison isn't that strict / careful. mostly against misconfig, not adversaries
            let chains = list_chains_for_table(&ta.table)?;
            let c_set: HashSet<&String> =
                chains.iter().flat_map(|table| table.get_name()).collect();
            for (c_name, ca) in ta.chains {
                if c_set.contains(&c_name) {
                    let mut rules: Vec<Rule> = list_rules_for_chain(&ca.chain)?;
                    for r in rules.iter_mut() {
                        r.essentialize();
                    }
                    let exi_set: HashSet<&Rule> = HashSet::from_iter(rules.iter());
                    let expec_set: HashSet<&Rule> = HashSet::from_iter(ca.rules.iter());
                    if exi_set.is_subset(&expec_set) {
                        // add all the missing rules
                        let add_diff = &expec_set - &exi_set;
                        for expr in add_diff.iter() {
                            batch.add(*expr, MsgType::Add);
                        }
                        log::trace!(
                            "incrementally adding {} new rules to chain {}",
                            add_diff.len(),
                            c_name
                        )
                    } else {
                        // remove and re-add
                        // we take full-control of a chain
                        log::trace!("chain {} contaminated, re-adding", c_name);
                        for rule in rules {
                            batch.add(&rule, MsgType::Del);
                        }
                        for rule in &ca.rules {
                            batch.add(rule, MsgType::Add);
                        }
                        // Note that after I decided to always re-add veths, the existing/expected rules will always be different
                        // specifically in the CMP data of interface indices, and therefore, re-added.
                    }
                } else {
                    // add chain
                    log::trace!("adding new chain {}", c_name);
                    batch.add(&ca.chain, MsgType::Add);
                    for rule in &ca.rules {
                        batch.add(rule, MsgType::Add);
                    }
                }
            }
            // do nothing to other chains if they exist
        } else {
            log::trace!("adding new table {}", name);
            batch.add(&ta.table, MsgType::Add);
            for (_c_name, ca) in ta.chains.iter() {
                batch.add(&ca.chain, MsgType::Add);
                for rule in &ca.rules {
                    batch.add(rule, MsgType::Add);
                }
            }
            // add table
        }
    }
    // do nothing to other tables if any
    log::trace!("ensure_rules, batch.send");
    batch.send()?;

    Ok(())
}

pub fn apply_block_forwad(veth_list: &[&str]) -> Result<()> {
    log::info!("applying nft rules to block forwarding of {:?}", veth_list);
    let table = Table::new(ProtocolFamily::Inet).with_name(TABLE_NAME.to_owned());
    let chain = Chain::new(&table)
        .with_name(FO_CHAIN)
        .with_hook(Hook::new(rustables::HookClass::Forward, 0))
        .with_policy(rustables::ChainPolicy::Accept);
    let mut rules: HashSet<Rule> = HashSet::new();

    for v in veth_list {
        rules.insert(drop_interface_rule(v, &chain)?);
    }

    let prop = NftState {
        tables: HashMap::from_iter([(
            TABLE_NAME.to_owned(),
            NftTable {
                table,
                chains: HashMap::from([(FO_CHAIN.to_owned(), NftChain { chain, rules })]),
            },
        )]),
    };

    ensure_rules(prop)?;

    Ok(())
}

pub fn drop_interface_rule(i_name: &str, chain: &Chain) -> Result<Rule> {
    let mut r = Rule::new(&chain)?;
    let i = iface_index(i_name)?;

    r = r
        .with_expr(Meta::new(MetaType::Iif))
        .with_expr(Cmp::new(CmpOp::Eq, i.to_le_bytes()))
        .with_expr(Immediate::new_verdict(VerdictKind::Drop));

    Ok(r)
}
