use rtnetlink::netlink_sys::{AsyncSocket, TokioSocket};
use rustables::{
    expr::{
        Cmp, CmpOp, ExpressionRaw, ExpressionVariant, Immediate, Meta, MetaType, Nat, NatType,
        RawExpression, VerdictKind,
    },
    iface_index, list_chains_for_table_async, list_rules_for_chain_async, list_tables_async,
    nlmsg::NfNetlinkObject,
    util::Essence,
    Batch, Chain, Hook, MsgType, ProtocolFamily, Rule, Table,
};
use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

use anyhow::{Ok, Result};

pub const TABLE_NAME: &str = "netnsp";
pub const FO_CHAIN: &str = "block-forward";

#[derive(Default, Debug)]
pub struct NftState {
    // name -> table. indexed
    tables: Vec<PTable>,
}

#[derive(Default, Debug)]
pub struct PTable {
    table: Table,
    chains: Vec<PChain>,
}

#[derive(Default, Debug)]
pub struct PChain {
    chain: Chain,
    rules: HashSet<Rule>,
    // I think they are not ordered
}

pub trait NftObj: rustables::nlmsg::NfNetlinkObject + Hash + Eq + Essence {}

pub trait Subbed: Sized {
    type ST: NftObj;
    type SP: Concrete<T = Self::ST>;
    type STIter: IntoIterator<Item = Self::ST> = Vec<Self::ST>;
    type SPIter<'a>: IntoIterator<Item = &'a Self::SP> = &'a Vec<Self::SP>
    where
        Self::SP: 'a,
        Self: 'a ;
    async fn sub_objs_existing<S: AsyncSocket>(&self, sock: &mut S) -> Result<Self::STIter>;
    fn sub_props(&self) -> Result<Self::SPIter<'_>>;
    fn exclusive() -> bool {
        false
    }
    async fn process<S: AsyncSocket>(
        &self,
        batch: &mut Batch,
        sock: &mut S,
    ) -> Result<HashSet<Self::ST>> {
        let props = self.sub_props()?;
        let prop_objs = props.into_iter().map(|x| x.obj());
        let objs = self.sub_objs_existing(sock).await?;
        let prop_set: HashSet<_> = HashSet::from_iter(prop_objs.into_iter());
        let obj_set: HashSet<_> = HashSet::from_iter(objs.into_iter().map(|mut e| {
            e.essentialize();
            e
        }));
        let objsr = HashSet::from_iter(&obj_set);
        let surplus = &objsr - &prop_set;
        let missing = &prop_set - &objsr;
        if Self::exclusive() {
            for s in surplus {
                batch.add(s, MsgType::Del);
            }
        }
        for m in missing {
            batch.add(m, MsgType::Add);
        }
        Ok(obj_set)
    }
}

/// with concrete NFT data
pub trait Concrete {
    type T: NftObj;
    fn obj(&self) -> &Self::T;
}

pub trait Fetch<T>: Sized {
    async fn fetch<S: AsyncSocket>(ext: T, sock: &mut S) -> Result<Self>;
}

impl Fetch<()> for NftState {
    async fn fetch<S: AsyncSocket>(_ext: (), sock: &mut S) -> Result<Self> {
        let mut nf = NftState::default();
        let k = nf.sub_objs_existing(sock).await?;
        nf.tables.clear();
        for p in k {
            nf.tables.push(PTable::fetch(p, sock).await?);
        }

        Ok(nf)
    }
}

impl Fetch<Table> for PTable {
    async fn fetch<S: AsyncSocket>(ext: Table, sock: &mut S) -> Result<Self> {
        let mut t = Self {
            table: ext,
            ..Default::default()
        };
        let k = t.sub_objs_existing(sock).await?;

        t.chains.clear();
        for p in k {
            t.chains.push(PChain::fetch(p, sock).await?);
        }
        Ok(t)
    }
}

impl Fetch<Chain> for PChain {
    async fn fetch<S: AsyncSocket>(ext: Chain, sock: &mut S) -> Result<Self> {
        let mut c = Self {
            chain: ext,
            ..Default::default()
        };
        c.rules = HashSet::from_iter(c.sub_objs_existing(sock).await?.into_iter());
        Ok(c)
    }
}

pub trait Fat {
    /// process recursively for state application
    async fn compose<S: AsyncSocket>(&self, batch: &mut Batch, sock: &mut S) -> Result<()>;
}

impl Fat for PChain {
    async fn compose<S: AsyncSocket>(&self, batch: &mut Batch, sock: &mut S) -> Result<()> {
        let _objs = self.process(batch, sock).await?;
        Ok(())
    }
}

impl Fat for PTable {
    async fn compose<S: AsyncSocket>(&self, batch: &mut Batch, sock: &mut S) -> Result<()> {
        let _objs = self.process(batch, sock).await?;
        for p in self.sub_props()? {
            p.compose(batch, sock).await?;
        }
        Ok(())
    }
}

impl Fat for NftState {
    async fn compose<S: AsyncSocket>(&self, batch: &mut Batch, sock: &mut S) -> Result<()> {
        let _objs = self.process(batch, sock).await?;
        for p in self.sub_props()? {
            p.compose(batch, sock).await?;
        }
        Ok(())
    }
}

impl<N: NfNetlinkObject + Essence + Eq + Hash> NftObj for N {}

impl Concrete for PTable {
    type T = Table;
    fn obj(&self) -> &Self::T {
        &self.table
    }
}

impl Subbed for NftState {
    type SP = PTable;
    type ST = Table;
    async fn sub_objs_existing<S: AsyncSocket>(&self, sock: &mut S) -> Result<Self::STIter> {
        Ok(list_tables_async(sock).await?)
    }
    fn sub_props(&self) -> Result<Self::SPIter<'_>> {
        Ok(&self.tables)
    }
}

impl Subbed for PTable {
    type SP = PChain;
    type ST = Chain;
    fn sub_props(&self) -> Result<Self::SPIter<'_>> {
        Ok(&self.chains)
    }
    async fn sub_objs_existing<S: AsyncSocket>(&self, sock: &mut S) -> Result<Self::STIter> {
        Ok(list_chains_for_table_async(&self.table, sock).await?)
    }
    fn exclusive() -> bool {
        true
    }
}

impl Concrete for PChain {
    type T = Chain;
    fn obj(&self) -> &Self::T {
        &self.chain
    }
}

impl Subbed for PChain {
    type ST = Rule;
    type SP = Rule;
    type SPIter<'a> = &'a HashSet<Self::SP>;
    fn exclusive() -> bool {
        true
    }
    async fn sub_objs_existing<S: AsyncSocket>(&self, sock: &mut S) -> Result<Self::STIter> {
        Ok(list_rules_for_chain_async(&self.chain, sock).await?)
    }
    fn sub_props(&self) -> Result<Self::SPIter<'_>> {
        Ok(&self.rules)
    }
}

impl Concrete for Rule {
    type T = Self;
    fn obj(&self) -> &Self::T {
        self
    }
}

pub async fn print_all() -> Result<()> {
    let mut sock = TokioSocket::new(rtnetlink::netlink_sys::constants::NETLINK_NETFILTER)?;
    let nf = NftState::fetch((), &mut sock).await?;
    dbg!(nf);
    Ok(())
}

pub enum NftConf {
    RedirDNS(u16),
    ForwardPort(u16),
}

/// redirect all DNS traffic to localhost:port
const DNS_CHAIN: &str = "out";
pub fn redirect_dns(port: u16) -> Result<NftState> {
    let table = Table::new(ProtocolFamily::Inet).with_name(TABLE_NAME.to_owned());
    let chain = Chain::new(&table)
        .with_name(DNS_CHAIN)
        .with_hook(Hook::new(rustables::HookClass::Out, 0))
        .with_type(ChainType::Nat)
        .with_flags(1 as u32)
        .with_policy(rustables::ChainPolicy::Accept);

    let mut exp = RawExpression::default();
    let raw: ExpressionRaw = [
        8, 0, 1, 0, 0, 0, 0, 1, 8, 0, 2, 0, 0, 0, 0, 1, 8, 0, 3, 0, 0, 0, 0, 2,
    ]
    .to_vec()
    .into();

    exp.set_name("redir");
    exp.set_data(raw);
    let mut rules: HashSet<Rule> = HashSet::new();
    let r1 = Rule::new(&chain)?
        .protocol(Protocol::UDP)
        .dport(53, Protocol::UDP)
        .with_expr(Immediate::new_data(
            port.to_be_bytes().to_vec(),
            expr::Register::Reg1,
        ))
        .with_expr(exp);
    rules.insert(r1);

    let prop = NftState {
        tables: vec![PTable {
            table,
            chains: vec![PChain { chain, rules }],
        }],
    };

    Ok(prop)
}

impl NftState {
    pub async fn apply<S: AsyncSocket>(self, sock: &mut S) -> Result<Self> {
        let mut b = Batch::new();
        self.compose(&mut b, sock).await?;
        b.send_async(sock).await?;
        Ok(self)
    }
}

#[test]
fn test_dns_prop() {
    let p = redirect_dns(5353).unwrap();
    dbg!(p);
}

pub async fn apply_block_forwad(veth_list: &[&str], sock: &mut impl AsyncSocket) -> Result<()> {
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
        tables: vec![PTable {
            table,
            chains: vec![PChain { chain, rules }],
        }],
    };

    prop.apply(sock).await?;

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

pub fn drop_interface_rule_index(index: u32, chain: &Chain) -> Result<Rule> {
    let mut r = Rule::new(&chain)?;

    r = r
        .with_expr(Meta::new(MetaType::Iif))
        .with_expr(Cmp::new(CmpOp::Eq, index.to_le_bytes()))
        .with_expr(Immediate::new_verdict(VerdictKind::Drop));

    Ok(r)
}

#[derive(Default, Debug)]
pub struct IncrementalNft {
    links: Vec<u32>,
}

use rustables::*;
impl IncrementalNft {
    pub fn drop_packets_from(&mut self, index: u32) {
        log::info!("Add nft rule for {}", index);
        self.links.push(index);
    }
    // TODO: blocking socket
    pub async fn execute(&mut self, sock: &mut impl AsyncSocket) -> Result<()> {
        let table = Table::new(ProtocolFamily::Inet).with_name(TABLE_NAME.to_owned());
        let chain = Chain::new(&table)
            .with_hook(Hook::new(HookClass::Forward, 0))
            .with_name(FO_CHAIN)
            .with_policy(ChainPolicy::Accept);
        let mut batch: Batch = Batch::new();
        for index in self.links.iter() {
            let rule = drop_interface_rule_index(*index, &chain)?;
            batch.add(&rule, MsgType::Add);
        }
        batch.send_async(sock).await?;
        self.links.clear();

        Ok(())
    }
}
