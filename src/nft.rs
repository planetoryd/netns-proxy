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
    let exis_tables: Vec<Table> = list_tables()?;
    let exis_tables_names: HashSet<&String> = exis_tables
        .iter()
        .flat_map(|table| table.get_name())
        .collect();
    // do a quick scan for consistency, and if diff is small, update incrementally, else remove & re-add
    let mut batch: Batch = Batch::new();
    for (p_table_name, proposed_table) in proposal.tables {
        if exis_tables_names.contains(&p_table_name) {
            // the comparison isn't that strict / careful. mostly against misconfig, not adversaries
            let exis_chains = list_chains_for_table(&proposed_table.table)?;
            let exis_chain_names: HashSet<&String> = exis_chains
                .iter()
                .flat_map(|chain| chain.get_name())
                .collect();
            for (c_name, p_chain) in proposed_table.chains {
                if exis_chain_names.contains(&c_name) {
                    let mut exis_rules: Vec<Rule> = list_rules_for_chain(&p_chain.chain)?;
                    for r in exis_rules.iter_mut() {
                        r.essentialize();
                    }

                    let exi_set: HashSet<&Rule> = HashSet::from_iter(exis_rules.iter());
                    let expec_set: HashSet<&Rule> = HashSet::from_iter(p_chain.rules.iter());
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
                        for rule in exis_rules {
                            // remove every old rule
                            batch.add(&rule, MsgType::Del);
                        }
                        for rule in &p_chain.rules {
                            batch.add(rule, MsgType::Add);
                        }
                    }
                } else {
                    // add chain
                    log::trace!("adding new chain {}", c_name);
                    batch.add(&p_chain.chain, MsgType::Add);
                    for rule in &p_chain.rules {
                        batch.add(rule, MsgType::Add);
                    }
                }
            }
            // do nothing to other chains if they exist
        } else {
            log::trace!("adding new table {}", p_table_name);
            batch.add(&proposed_table.table, MsgType::Add);
            for (_, p_chain) in proposed_table.chains.iter() {
                batch.add(&p_chain.chain, MsgType::Add);
                for rule in &p_chain.rules {
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

#[derive(Default, Debug)]
pub struct IncrementalNft {
    links: Vec<String>,
}

use rustables::*;
impl IncrementalNft {
    pub fn drop_packets_from(&mut self, name: String) {
        log::info!("add nft rule for {}", name);
        self.links.push(name);
    }
    /// blocking socket
    pub fn execute(&mut self) -> Result<()> {
        let table = Table::new(ProtocolFamily::Inet).with_name(TABLE_NAME.to_owned());
        let chain = Chain::new(&table)
            .with_hook(Hook::new(HookClass::Forward, 0))
            .with_name(FO_CHAIN)
            .with_policy(ChainPolicy::Accept);
        let mut batch: Batch = Batch::new();
        for name in self.links.iter() {
            let rule = drop_interface_rule(name, &chain)?;
            batch.add(&rule, MsgType::Add);
        }
        batch.send()?;
        self.links.clear();

        Ok(())
    }
}
