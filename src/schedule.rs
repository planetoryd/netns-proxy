use std::any::TypeId;
use std::borrow::BorrowMut;
use std::collections::{BinaryHeap, HashMap};
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::Add;
use std::pin::Pin;

use crate::data::{
    ConfPaths, Derivative, NSIDKey, NSRef, Remainder, Settings, SubjectInfo, SubjectProfile,
    VSpecifics,
};
use crate::netlink::{nl_ctx, LinkAB, Netns, NetnsMap};
use crate::nft::{NftState, self};
use crate::sub::{NLFilter, Sub, SubHub};
use crate::util::error::{DevianceError, ProgrammingError};
use anyhow::{bail, Result};
use async_scheduler::{rkey, AsyncScheduler, Demand, FnPlan, ReqType, RsrcKey, ScheSubject};
use dashmap::mapref::entry::Entry;
use dashmap::mapref::one::{Ref, RefMut};
use dashmap::try_result::TryResult;
use dashmap::DashMap;
use derivative::Derivative;
use futures::Future;
use ron::ser::PrettyConfig;
use rtnetlink::netlink_sys::TokioSocket;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot;

use crate::{
    data::*,
    nft::{redirect_dns, Mergeable},
    sub::ToSub,
    util::{flatpak_perms_checkup, perms::get_non_priv_user, TaskCtx, TaskOutput},
};

use futures::{future::Ready, FutureExt, SinkExt, StreamExt, TryFutureExt};
use ipnetwork::IpNetwork;

use serde::{Deserialize, Serialize};

use tokio::{io::AsyncWriteExt, sync::RwLock};

use crate::{
    data::Pid,
    sub::{self},
    util::{self, convert_strings_to_strs},
};

use anyhow::{anyhow, Ok};

use nix::{fcntl::FdFlag, sched::CloneFlags};

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    default,
    fmt::Debug,
    ops::{Deref, Index},
    os::fd::FromRawFd,
    str::FromStr,
    sync::Arc,
};

use std::{
    net::Ipv4Addr,
    os::fd::RawFd,
    path::{Path, PathBuf},
};
use tokio::{self, fs::File, io::AsyncReadExt};

use crate::util::{ns::*, AssumeUnwrap};

pub enum SubjectState {
    Dirty,
    /// Preparation done
    PreNetfilter,
    /// At netfilter, means netfilter config done
    Netfilter,
    /// It's just started. Not necessarily running/working.
    Started,
    Suspended,
}

impl async_scheduler::Key for NSID {}

type Scheduler =
    AsyncScheduler<SubjectState, Remainder<NSID>, NetnspState, NSID, UniqueInstance, u8>;

impl<V: VSpecifics> ScheSubject for SubjectInfo<V> {
    type S = SubjectState;
    type SK = UniqueInstance;
    type TK = ();
    type GS = NetnspState;
    type E = Remainder<NSID>;
    fn initial_status(&self) -> Self::S {
        SubjectState::Dirty
    }
    fn subject_key(&self) -> &Self::SK {
        &self.id
    }
    fn next_task<'f>(
        &'f self,
        status: Self::S,
    ) -> Vec<FnPlan<'f, Self::SK, Self::TK, Self::RKey, Self::GS, Self::E, Self::S>> {
        match status {
            SubjectState::Dirty => {
                let mut req = HashMap::default();
                req.insert(rkey!(Netns / self.ns.clone()), ReqType::W);
                req.insert(rkey!(Sub / self.ns.clone()), ReqType::W);
                for (n, c) in &self.vaddrs {
                    req.insert(rkey!(Netns / n.to_owned()), ReqType::W);
                    req.insert(rkey!(Sub / n.to_owned()), ReqType::W);
                }
                [FnPlan {
                    req,
                    subject: self.subject_key(),
                    tkey: (),
                    exec: Some(Box::new(move |nsp: &Self::GS| {
                        Box::pin(async move {
                            let mut ef = Remainder::default();
                            let mut ret = NftState::default();

                            let (sg, sn, _) = nsp.netns.get(&self.ns).await?;
                            let mut subject_ns = sn(&sg);

                            for (n, c) in self.vaddrs.iter() {
                                if n == self.ns {
                                    // Would cause a deadlock.
                                    bail!(
                                        "VethConn can not have a connection to subject NS itself"
                                    );
                                }
                                let (sg, sn, _) = nsp.netns.get(n).await?;
                                let mut t_ns = sn(&sg);
                                c.apply(&mut subject_ns, &mut t_ns).await?;
                                let re = self.deps.get_by_right(n).assume()?;
                                match re {
                                    NSRef::Root => {
                                        let k = c.key.link(LinkAB::B);
                                        t_ns.netlink.get_link(k.clone()).await?;
                                        nl_ctx!(link, _conn, t_ns.netlink, {
                                            let li = link.not_absent(&k)?.exist_ref()?;
                                            ret.merge(nft::block_forward([li.index])?);
                                        });
                                    }
                                    _ => (),
                                }
                            }
                            Ok(ef)
                        })
                    })),
                    result: SubjectState::PreNetfilter,
                }]
                .into()
            }
            SubjectState::PreNetfilter => {
                let k = [FnPlan {
                    req: vec![],
                    subject: self.subject_key(),
                    tkey: (),
                    exec: Some(Box::new(move |nsp: &Self::GS| {
                        Box::pin(async move {
                            let mut ef = Remainder::default();
                            match &self.dnsproxy {
                                DNSProxyR::Disabled => (),
                                DNSProxyR::Enabled(conf) => {
                                    let p = conf.port;
                                    log::info!(
                                        "{} Apply nft rules, redirect all TCP/UDP requests to :53 to localhost:{p}",
                                        self.ns
                                    );
                                    ef.nft_merge(
                                        self.ns.as_key(),
                                        NSEffect {
                                            nft: nft::redirect_dns(p)?,
                                        },
                                    )?;
                                }
                            };
                            Ok(ef)
                        })
                    })),
                    result: SubjectState::Netfilter,
                }];
                k.into()
            }
            SubjectState::Netfilter => {
                let k = [FnPlan {
                    req: Demand!(Sub/self.ns.clone() => W),
                    subject: self.subject_key(),
                    tkey: (),
                    exec: Some(Box::new(move |nsp: &Self::GS| {
                        Box::pin(async move {
                            let mut ef = Remainder::<NSID>::default();
                            let (g, s, _): (_, _, _) = nsp.subs.get_mut(&self.ns.as_key()).await?;
                            let s = s(&mut g);
                            s.send(ToSub::Named(self.specifics.msg_run(self.clone())))
                                .await?;
                            Ok(ef)
                        })
                    })),
                    result: SubjectState::Started,
                }];
                k.into()
            }
            _ => unreachable!(),
        }
    }
    fn destroy(
        &self,
        status: Self::S,
    ) -> FnPlan<'_, Self::SK, Self::TK, Self::RKey, Self::GS, Self::E, Self::S> {
        let mut req = HashMap::default();
        req.insert(rkey!(Netns / self.ns.clone()), ReqType::W);
        req.insert(rkey!(Sub / self.ns.clone()), ReqType::W);
        for (n, c) in &self.vaddrs {
            req.insert(rkey!(Netns / n.to_owned()), ReqType::W);
            req.insert(rkey!(Sub / n.to_owned()), ReqType::W);
        }

        FnPlan {
            req,
            subject: self.subject_key(),
            tkey: (),
            exec: Some(Box::new(move |nsp: &Self::GS| {
                Box::pin(async move {
                    let mut ef = Remainder::<NSID>::default();
                    nsp.ctx
                        .pm
                        .send(PidOp::Kill(
                            ProcessGroup::Subject(self.ns.clone()),
                            KillMask::all(),
                        ))
                        .unwrap();
                    nsp.netns.subs.kill_subject(self.ns.as_key()).await?;

                    for (r, c) in &self.vaddrs {
                        let (g, mut n, _) = nsp.netns.get_mut(r).await?;
                        let n = n(&mut g);
                        let lk = c.key.link(crate::netlink::LinkAB::B);
                        if nl_ctx!(link, _conn, n.netlink, { matches!(link.g(&lk), Some(_)) }) {
                            n.netlink.remove_link(&lk).await?;
                        }
                    }
                    self.ns.remove_if_duty()?;

                    Ok(ef)
                })
            })),
            result: SubjectState::Started,
        }
    }
}

impl<K> DerivationEvent<K> for Scheduler {
    fn on_derive(&mut self, key: K) {
        
    }
}

pub trait DerivationEvent<K> {
    /// SI changed, modified or added.
    fn on_derive(&mut self, key: K);
    /// SI not changed
    fn on_visit(&mut self, key: K);
    /// SI GCed
    fn on_remove(&mut self, key: K);
}

pub struct DEHandlerEmpty;

impl<K> DerivationEvent<K> for DEHandlerEmpty {
    fn on_derive(&mut self, key: K) {}
    fn on_visit(&mut self, key: K) {}
    fn on_remove(&mut self, key: K) {}
}

pub struct NetnspState {
    // persistent
    pub derivative: Derivative,
    pub settings: Settings,
    pub paths: Arc<ConfPaths>,
    // runtime state
    pub instances: BinaryHeap<UniqueInstance>,
    pub effect: Remainder<NSID>,

    pub netfilter: NLFilter<NSWaitfree<TokioSocket, NSID>>,
    pub subs: SubHub<NSWaitfree<Sub, NSID>>,
    pub netns: NetnsMap<NSWaitfree<Netns, NSID>>,

    pub ctx: TaskCtx,
    pub sche: Scheduler,
}

pub trait NMap {
    type V: 'static;
    type K: 'static;
    type ReadGuard<'k>: 'k;
    type WriteGuard<'k>: 'k;
    async fn get<'r, 'c, Fut: Future<Output = Result<Self::V>> + 'c>(
        &'r self,
        k: &'c Self::K,
        init: impl FnOnce(&'c Self::K) -> Fut,
    ) -> Result<(
        Self::ReadGuard<'r>,
        fn(&'r Self::ReadGuard<'r>) -> &'r Self::V,
        bool,
    )>;
    async fn get_mut<'w, 'c, Fut: Future<Output = Result<Self::V>> + 'c>(
        &'w self,
        k: &'c Self::K,
        init: impl FnOnce(&'c Self::K) -> Fut,
    ) -> Result<(
        Self::WriteGuard<'w>,
        fn(&'w mut Self::WriteGuard<'w>) -> &'w mut Self::V,
        bool,
    )>;
}

#[derive(Derivative)]
#[derivative(Clone(bound = "V: Clone"), Default(bound = ""))]
/// Errors when waiting happens.
pub struct NSWaitfree<V, K: Eq + Hash + Clone> {
    map: DashMap<K, V>,
}

impl<V: 'static, K: Eq + Hash + Clone + 'static> NMap for NSWaitfree<V, K> {
    type V = V;
    type K = K;
    type ReadGuard<'k> = Ref<'k, K, V> where K: 'k;
    type WriteGuard<'k> = RefMut<'k, K, V> where K: 'k;
    async fn get<'r, 'c, Fut: Future<Output = Result<Self::V>> + 'c>(
        &'r self,
        k: &'c Self::K,
        init: impl FnOnce(&'c Self::K) -> Fut,
    ) -> Result<(
        Self::ReadGuard<'r>,
        fn(&'r Self::ReadGuard<'r>) -> &'r Self::V,
        bool,
    )> {
        match self.map.try_get(k) {
            TryResult::Locked => {
                bail!("Object for NS locked. Scheduling error")
            }
            TryResult::Present(p) => Ok((p, Ref::value, false)),
            TryResult::Absent => {
                self.map.insert(k.to_owned(), init(k).await?);
                if let TryResult::Present(p) = self.map.try_get(k) {
                    Ok((p, Ref::value, true))
                } else {
                    unreachable!()
                }
            }
        }
    }
    async fn get_mut<'w, 'c, Fut: Future<Output = Result<Self::V>> + 'c>(
        &'w self,
        k: &'c Self::K,
        init: impl FnOnce(&'c Self::K) -> Fut,
    ) -> Result<(
        Self::WriteGuard<'w>,
        fn(&'w mut Self::WriteGuard<'w>) -> &'w mut Self::V,
        bool,
    )> {
        match self.map.try_get_mut(k) {
            TryResult::Locked => {
                bail!("Object for NS locked. Scheduling error")
            }
            TryResult::Present(p) => Ok((p, RefMut::value_mut, false)),
            TryResult::Absent => {
                // bail!("Object doesn't exist for NS")
                self.map.insert(k.to_owned(), init(k).await?);
                if let TryResult::Present(p) = self.map.try_get_mut(k) {
                    Ok((p, RefMut::value_mut, true))
                } else {
                    unreachable!()
                }
            }
        }
    }
}

/// Resource per NS
pub trait NSMap {
    type V;
    type Inner: NMap<V = Self::V>;
    async fn get<'r, Fut: Future<Output = Result<Self::V>>>(
        &'r self,
        k: &<Self::Inner as NMap>::K,
    ) -> Result<(
        <Self::Inner as NMap>::ReadGuard<'r>,
        fn(&'r <Self::Inner as NMap>::ReadGuard<'r>) -> &'r Self::V,
        bool,
    )>;
    async fn get_mut<'w, Fut: Future<Output = Result<Self::V>>>(
        &'w self,
        k: &<Self::Inner as NMap>::K,
    ) -> Result<(
        <Self::Inner as NMap>::WriteGuard<'w>,
        fn(&'w mut <Self::Inner as NMap>::WriteGuard<'w>) -> &'w mut Self::V,
        bool,
    )>
    where
        Self::V: 'w;
}

pub trait Load: Sized {
    fn load_or_create(paths: &ConfPaths) -> Result<Self>;
    async fn load_or_create_async(paths: &ConfPaths) -> Result<Self>;
}

pub trait Dump {
    fn dump(&self, paths: &ConfPaths) -> Result<()>;
    async fn dump_async(&self, paths: &ConfPaths) -> Result<()>;
}

pub enum DeriveRes {
    Existent,
    New,
    NoProfile,
}

impl NetnspState {
    pub async fn dump(&self) -> Result<()> {
        self.derivative.dump_async(&self.paths).await?;
        Ok(())
    }
    pub async fn load(
        subs: SubHub<NSWaitfree<Sub, NSID>>,
        ctx: TaskCtx,
        paths: Arc<ConfPaths>,
    ) -> Result<Self> {
        Ok(Self {
            derivative: Derivative::load_or_create_async(&paths).await?,
            settings: Settings::load_or_create_async(&paths).await?,
            paths,
            netns: NetnsMap::new(paths, ctx.clone(), subs.clone())?,
            subs,
            ctx,
            instances: Default::default(),
            effect: Default::default(),
            netfilter: Default::default(),
            sche: Scheduler::default(),
        })
    }
    pub async fn post_load(&mut self) -> Result<()> {
        // No add events, therefore &mut DEHandlerEmpty to not send removal events
        self.derivative
            .clean_named(&self.settings.profiles, &self.netns, &mut DEHandlerEmpty)
            .await?;
        self.derivative
            .clean_flatpak(&self.settings.flatpak, &self.netns, &mut DEHandlerEmpty)
            .await?;
        self.flatpak_ensure()?;
        self.load_ids();
        self.derive_named_all().await?;
        self.dump().await?;
        Ok(())
    }
    /// this must be done after loading from state, before any new derivation
    pub fn load_ids(&mut self) {
        for (_, s) in &self.derivative.flatpak {
            self.instances.push(s.id.clone());
        }
        for (_, s) in &self.derivative.named_ns {
            self.instances.push(s.id.clone());
        }
    }
    /// derive for named ns that are not not yet derived
    pub async fn derive_named_all(&mut self) -> Result<()> {
        for ns in self.settings.profiles.keys() {
            self.derivative
                .named_ns
                .may_derive(
                    ns,
                    async {
                        self.instances.new_unique(ns.clone());
                        let p = self.settings.profiles.get(&ns).assume()?;
                        p.resolve_global(
                            &self,
                            self.instances.last_unique().assume()?,
                            &NamedV(ns.clone()),
                        )
                        .await?;
                    },
                    &mut self.sche,
                )
                .await?;
        }
        Ok(())
    }
    pub async fn derive_flatpak(&mut self, fv: FlatpakV) -> Result<DeriveRes> {
        let r = self.settings.flatpak.get(&fv.id).unwrap();
        match self.settings.profiles.get(&r) {
            Some(p) => {
                self.derivative
                    .flatpak
                    .may_derive(
                        &fv.pid,
                        async {
                            let n = FlatpakBaseName::new(&fv.id, fv.pid.clone());
                            self.instances.new_unique(n);

                            p.resolve_global(&self, self.instances.last_unique().assume()?, &fv)
                                .await
                        },
                        &mut self.sche,
                    )
                    .await
            }
            None => Ok(DeriveRes::NoProfile),
        }
    }

    pub fn flatpak_ensure(&self) -> Result<()> {
        let li = self.settings.flatpak.keys().collect();
        flatpak_perms_checkup(li)?;
        Ok(())
    }
    pub async fn resume(&mut self) -> Result<()> {
        log::debug!("Resume from saved state");
        self.sche.upkeep(self).await?;
        Ok(())
    }
}
