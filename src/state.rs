use anyhow::{anyhow, bail, Ok, Result};
use clap::Id;
use derivative::Derivative;
use futures::{
    future::{MaybeDone, Ready},
    Future, FutureExt, StreamExt,
};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    fmt::{format, Debug},
    hash::Hash,
    marker::PhantomData,
    mem::swap,
    pin::Pin,
};

use fixed_map::{Key, Map};
use std::collections::HashMap;

use crate::netlink::NLTracked;

// Abstract stuff

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Derivative)]
#[derivative(Debug)]
pub enum Existence<A: Trans> {
    /// Exist as confirmed by netlink communication
    Exist(A),
    /// Should exist. This has no attrs because we usually only have partial attr info atm
    ShouldExist,
    ExpectAbsent,
    // Confirmed absencce is implied in the map
}

#[derive(Derivative)]
#[derivative(Debug)]
/// Maybe Lazy
pub enum LazyVal<'f, V> {
    Todo(#[derivative(Debug = "ignore")] Pin<Box<dyn Future<Output = Result<V>> + 'f + Send>>),
    Done(V),
}

impl<'f, V> LazyVal<'f, V> {
    pub async fn eval(&mut self) -> Result<()> {
        match self {
            Self::Todo(f) => {
                let k = f.await?;
                *self = Self::Done(k);
                Ok(())
            }
            Self::Done(_) => Ok(()),
        }
    }
    pub fn unwrap(&self) -> &V {
        match self {
            Self::Todo(_) => unreachable!(),
            Self::Done(k) => k,
        }
    }
    pub fn unwrap_owned(self) -> V {
        match self {
            Self::Todo(_) => unreachable!(),
            Self::Done(k) => k,
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub enum LExistence<'f, A: Trans> {
    Exist(#[derivative(Debug = "ignore")] LazyVal<'f, A>),
    ShouldExist,
    ExpectAbsent,
}

impl<'f, A: Trans> LExistence<'f, A> {
    pub async fn eval(&mut self) -> Result<()> {
        match self {
            Self::Exist(k) => k.eval().await,
            _ => Ok(()),
        }
    }
    pub async fn eval_into(mut self) -> Result<Existence<A>> {
        self.eval().await?;
        let k = match self {
            Self::ShouldExist => Existence::ShouldExist,
            Self::Exist(p) => Existence::Exist(p.unwrap_owned()),
            Self::ExpectAbsent => Existence::ExpectAbsent,
        };
        Ok(k)
    }
}

impl<'f, A: Trans> From<Existence<A>> for LExistence<'f, A> {
    fn from(value: Existence<A>) -> Self {
        match value {
            Existence::Exist(k) => LExistence::Exist(LazyVal::Done(k)),
            Existence::ExpectAbsent => LExistence::ExpectAbsent,
            Existence::ShouldExist => LExistence::ShouldExist,
        }
    }
}

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub enum Exp<V: PartialEq> {
    Expect(V),
    Confirmed(V),
    #[default]
    Unknown,
}

impl<V: PartialEq> Exp<V> {
    pub fn get(&self) -> Option<&V> {
        match self {
            Exp::Confirmed(e) => Some(e),
            Exp::Expect(e) => {
                log::trace!("using expected data");
                Some(e)
            }
            Self::Unknown => None,
        }
    }
}

impl<V: PartialEq> Trans for Exp<V> {
    fn trans(&self, to: &Self) -> bool {
        match &self {
            Exp::Expect(ef) => match to {
                Exp::Expect(ref et) => {
                    if ef != et {
                        false
                    } else {
                        true
                    }
                }
                _ => true,
            },
            _ => true,
        }
    }
}

impl Trans for () {
    fn trans(&self, to: &Self) -> bool {
        true
    }
}

pub trait Trans: Sized {
    fn trans(&self, to: &Self) -> bool;
    fn trans_to(&mut self, to: Self) -> Result<()> {
        if self.trans(&to) {
            *self = to;
        } else {
            bail!("Invalid transition")
        }
        Ok(())
    }
}

pub trait TransMap: EMapExt<Self::K, Self::A> {
    type K: Debug + Clone;
    type A: Trans;
}

impl<M: TransMap> Trans for M {
    fn trans(&self, to: &Self) -> bool {
        let ac = true;
        for (k, v) in self.get_iter().into_iter() {}
        ac
    }
}

impl<A: Trans> Existence<A> {
    /// Errors of assumption doesn't hold
    pub fn exist(self) -> Result<A> {
        match self {
            Existence::Exist(a) => Ok(a),
            Existence::ShouldExist => bail!("Object should exist but unconfirmed"),
            Existence::ExpectAbsent => bail!("Netlink object expected to be absent"),
        }
    }
    pub fn exist_ref(&self) -> Result<&A> {
        match self {
            Existence::Exist(ref a) => Ok(a),
            Existence::ShouldExist => bail!("Object should exist but unconfirmed"),
            Existence::ExpectAbsent => bail!("Netlink object expected to be absent"),
        }
    }
    pub fn exist_mut(&mut self) -> Result<&mut A> {
        match self {
            Existence::Exist(a) => Ok(a),
            Existence::ShouldExist => bail!("Object should exist but unconfirmed"),
            Existence::ExpectAbsent => bail!("Netlink object expected to be absent"),
        }
    }
    /// Creates another Existence<_> with same variant
    pub fn to<B: Trans>(&self, b: B) -> Existence<B> {
        match self {
            Existence::Exist(a) => Existence::Exist(b),
            Existence::ShouldExist => Existence::ShouldExist,
            Existence::ExpectAbsent => Existence::ExpectAbsent,
        }
    }
    pub async fn trans_to<'f>(&mut self, mut to: LExistence<'f, A>) -> Result<Self> {
        if self.can_trans(&mut to).await? {
            let mut tmp;
            match to {
                LExistence::Exist(mut k) => {
                    k.eval().await?;
                    tmp = Existence::Exist(k.unwrap_owned());
                }
                LExistence::ExpectAbsent => {
                    tmp = Existence::ExpectAbsent;
                }
                LExistence::ShouldExist => {
                    tmp = Existence::ShouldExist;
                }
            };
            swap(self, &mut tmp);
            Ok(tmp)
        } else {
            bail!("Transition failed")
        }
    }
    pub async fn can_trans<'f>(&self, to: &mut LExistence<'f, A>) -> Result<bool> {
        let k = match self {
            Existence::ExpectAbsent => bail!("ExpectAbsent"),
            Existence::ShouldExist => match to {
                LExistence::Exist(_) => true,
                LExistence::ExpectAbsent => true,
                _ => bail!("Invalid transition from ShouldExist"),
            },
            Existence::Exist(a) => match to {
                LExistence::Exist(b) => {
                    b.eval().await?;
                    if a.trans(b.unwrap()) {
                        true
                    } else {
                        bail!("Transition from Exist to Exist fails because of the inner")
                    }
                }
                LExistence::ExpectAbsent => true,
                _ => bail!("Invalid transition from Existence::Exist"),
            },
        };

        Ok(k)
    }
    pub fn lenient(&self) -> bool {
        match self {
            Existence::Exist(_) => true,
            Existence::ShouldExist => true,
            _ => false,
        }
    }
}

/// where existence of element represents non-absent.
pub trait ExistenceMap<K: Debug + Clone> {
    type V;
    /// Some can be one of three states, None represents confirmed absent.
    fn g(&self, key: &K) -> Option<&Self::V>;
    fn g_mut(&mut self, key: &K) -> Option<&mut Self::V>;
    fn set(&mut self, key: &K, exist: Self::V) -> Option<Self::V>;
    fn not_absent(&mut self, key: &K) -> Result<&mut Self::V> {
        let p = self.g_mut(key);
        match p {
            Some(x) => Ok(x),
            // If a refresh is done this shouldn't happen
            _ => Err(anyhow!(
                "programming error: no exsitential knowledge about object"
            )),
        }
    }
    /// Assuming the object is perceived, change it, and returns the original state
    fn not_absent_then_set(&mut self, key: &K, expect: Self::V) -> Result<Self::V> {
        let p = self.set(key, expect);
        match p {
            Some(x) => Ok(x),
            // If a refresh is done this shouldn't happen
            _ => Err(anyhow!(
                "programming error: no exsitential knowledge about object"
            )),
        }
    }
    fn set_absent(&mut self, key: &K) -> Option<Self::V>;
    fn is_empty(&self) -> bool;
    type It<'it>: IntoIterator<Item = (Cow<'it, K>, &'it Self::V)>
    where
        K: 'it,
        Self::V: 'it,
        Self: 'it;
    fn get_iter<'it, 'x: 'it>(&'x self) -> Self::It<'it>;
}

impl<K: Ord + Debug + Clone, V> ExistenceMap<K> for BTreeMap<K, V> {
    type V = V;
    type It<'i>  = std::iter::Map<<&'i Self as IntoIterator>::IntoIter, impl FnMut(<&'i Self as IntoIterator>::Item) -> (Cow<'i, K>, &'i V)> where K: 'i, V: 'i, Self: 'i;
    fn set(&mut self, key: &K, exist: V) -> Option<V> {
        self.insert(key.clone(), exist)
    }
    fn g(&self, key: &K) -> Option<&V> {
        self.get(key)
    }
    fn g_mut(&mut self, key: &K) -> Option<&mut V> {
        self.get_mut(key)
    }
    /// returns None if it was considered absent already.
    fn set_absent(&mut self, key: &K) -> Option<V> {
        self.remove(key)
    }
    fn is_empty(&self) -> bool {
        self.is_empty()
    }
    fn get_iter<'i, 'x: 'i>(&'x self) -> Self::It<'i>
    where
        K: 'i,
        V: 'i,
    {
        self.into_iter().map(|(k, v)| (Cow::Borrowed(k), v))
    }
}

impl<K: Hash + Debug + Clone + Eq, V> ExistenceMap<K> for HashMap<K, V> {
    type V = V;
    type It<'i>  = std::iter::Map<<&'i Self as IntoIterator>::IntoIter, impl FnMut(<&'i Self as IntoIterator>::Item) -> (Cow<'i, K>, &'i V)> where K: 'i, V: 'i, Self: 'i;
    fn set(&mut self, key: &K, exist: V) -> Option<V> {
        self.insert(key.clone(), exist)
    }
    fn g(&self, key: &K) -> Option<&V> {
        self.get(key)
    }
    fn g_mut(&mut self, key: &K) -> Option<&mut V> {
        self.get_mut(key)
    }
    /// returns None if it was considered absent already.
    fn set_absent(&mut self, key: &K) -> Option<V> {
        self.remove(key)
    }
    fn is_empty(&self) -> bool {
        self.is_empty()
    }
    fn get_iter<'i, 'x: 'i>(&'x self) -> Self::It<'i>
    where
        K: 'i,
        V: 'i,
    {
        self.into_iter().map(|(k, v)| (Cow::Borrowed(k), v))
    }
}

impl<K: Hash + Debug + Clone + Eq + Key, V> ExistenceMap<K> for Map<K, V> {
    type V = V;
    type It<'i>  = std::iter::Map<<&'i Self as IntoIterator>::IntoIter, impl FnMut(<&'i Self as IntoIterator>::Item) -> (Cow<'i, K>, &'i V)> where K: 'i, V: 'i, Self: 'i;
    fn set(&mut self, key: &K, exist: V) -> Option<V> {
        self.insert(key.clone(), exist)
    }
    fn g(&self, key: &K) -> Option<&V> {
        self.get(key.to_owned())
    }
    fn g_mut(&mut self, key: &K) -> Option<&mut V> {
        self.get_mut(key.to_owned())
    }
    /// returns None if it was considered absent already.
    fn set_absent(&mut self, key: &K) -> Option<V> {
        self.remove(key.to_owned())
    }
    fn is_empty(&self) -> bool {
        self.is_empty()
    }
    fn get_iter<'i, 'x: 'i>(&'x self) -> Self::It<'i>
    where
        K: 'i,
        V: 'i,
    {
        self.into_iter().map(|(k, v)| (Cow::Owned(k), v))
    }
}

pub trait EMapExt<K: Debug + Clone, A: Trans>: ExistenceMap<K, V = Existence<A>> {
    /// From any to non-absent
    async fn trans_to<'f>(&mut self, key: &K, v: LExistence<'f, A>) -> Result<Option<Self::V>> {
        let p = self.g_mut(key);
        let k = if let Some(p) = p {
            Some(p.trans_to(v).await?)
        } else {
            match v {
                LExistence::ShouldExist => self.set(key, v.eval_into().await?),
                _ => bail!(
                    "Illegal ExistenceMap state transition. From absent To {:?}",
                    v
                ),
            }
        };
        Ok(k)
    }
    // From any to absent
    fn trans_to_absent(&mut self, key: &K) -> Result<Option<Self::V>> {
        let p = self.set_absent(key);
        match p {
            None => Ok(None), // Absent to absent, valid
            Some(ref k) => match k {
                Existence::Exist(_) => bail!("Unexpected transition from Exist to Absent. {key:?}"),
                Existence::ShouldExist => {
                    bail!("Unexpected transition from ShouldExist to Absent. {key:?}")
                }
                Existence::ExpectAbsent => Ok(p),
            },
        }
    }
    fn lenient(&self, key: &K) -> bool {
        if let Some(p) = self.g(key) {
            p.lenient()
        } else {
            false
        }
    }
    fn fill(&mut self, key: &K, v: Self::V) -> Result<()> {
        let k = self.set(key, v);
        if k.is_some() {
            bail!("double fill");
        }
        Ok(())
    }
}

impl<K: Debug + Clone, A: Trans, M: ExistenceMap<K, V = Existence<A>>> EMapExt<K, A> for M {}

pub trait DependentEMap<
    K: Debug + Clone + Ord,
    SK: Debug + Clone + Ord,
    M: ExistenceMap<SK> + Default,
>: ExistenceMap<K, V = M>
{
    fn set_dep(&mut self, k: &K, sk: &SK, exist: M::V) -> Option<M::V> {
        if let Some(e) = self.g_mut(k) {
            e.set(sk, exist)
        } else {
            let mut n = M::default();
            n.set(sk, exist);
            self.set(k, n);
            None
        }
    }
    fn set_absent_dep(&mut self, k: &K, sk: &SK) -> Option<M::V> {
        if let Some(e) = self.g_mut(k) {
            e.set_absent(sk)
        } else {
            None
        }
    }
}

/// Extended for Existence<A>
pub trait DepedentEMapE<
    K: Debug + Clone + Ord,
    SK: Debug + Clone + Ord,
    A: Trans,
    M: ExistenceMap<SK, V = Existence<A>> + Default,
>: DependentEMap<K, SK, M>
{
    /// From any to non-absent
    async fn trans_t<'f>(&mut self, key: &K, sk: &SK, v: LExistence<'f, A>) -> Result<()> {
        let p = self.g_mut(key);
        if let Some(p) = p {
            p.trans_to(sk, v).await?;
        } else {
            match v {
                LExistence::ShouldExist => {
                    self.set_dep(key, sk, v.eval_into().await?);
                }
                _ => bail!("Illegal ExistenceMap state transition"),
            }
        }
        Ok(())
    }
    fn trans_absent_dep(&mut self, k: &K, sk: &SK) -> Result<Option<M::V>> {
        if let Some(e) = self.g_mut(k) {
            let s = e.trans_to_absent(sk);
            if e.is_empty() {
                // Maintain the property
                self.set_absent(k);
            }
            s
        } else {
            Ok(None) // absent to absent
        }
    }
}

// impl<
//         K: Debug + Clone + Ord,
//         SK: Debug + Clone + Ord,
//         M: ExistenceMap<SK> + Debug + Clone + Default,
//         B: ExistenceMap<K, V = M>,
//     > DependentEMap<K, SK, M> for B
// {
// }

pub struct NLCtx<'m, K: Ord + Debug + Clone, M: ExistenceMap<K>, FSet: FnMut(&K, Option<&mut M::V>)>
{
    pub map: &'m mut M,
    pub set: FSet,
    pub _k: PhantomData<K>,
}

impl<'m, K: Ord + Debug + Clone, V, M: ExistenceMap<K, V = V>, F: FnMut(&K, Option<&mut M::V>)>
    ExistenceMap<K> for NLCtx<'m, K, M, F>
{
    type V = V;
    type It<'i> = M::It<'i> where K: 'i, V: 'i, M: 'i, Self: 'i;
    fn g(&self, key: &K) -> Option<&V> {
        self.map.g(key)
    }
    fn not_absent(&mut self, key: &K) -> Result<&mut V> {
        self.map.not_absent(key)
    }
    fn g_mut(&mut self, key: &K) -> Option<&mut V> {
        self.map.g_mut(key)
    }
    // All setters have the events handled
    fn set(&mut self, key: &K, mut exist: V) -> Option<V> {
        (self.set)(&key, Some(&mut exist));
        let k = self.map.set(key, exist);
        k
    }
    fn set_absent(&mut self, key: &K) -> Option<V> {
        (self.set)(&key, None);
        self.map.set_absent(key)
    }
    fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    fn get_iter<'i, 's: 'i>(&'s self) -> Self::It<'i> {
        self.map.get_iter()
    }
}

#[derive(Debug, Default)]
pub enum ExpCollection<C: Default> {
    #[default]
    Unknown,
    /// Filled where absence of an entry means confirmed absence
    Filled(C),
}

impl<C: Default> ExpCollection<C> {
    /// Mutates the state to Filled regardless you actually filled it or not.
    pub fn to_filled(&mut self) -> Result<&mut C> {
        match self {
            Self::Filled(val) => Ok(val),
            Self::Unknown => {
                *self = Self::Filled(Default::default());
                self.to_filled()
            },
        }
    }
    pub fn filled(&mut self) -> Result<&mut C> {
        match self {
            Self::Filled(val) => Ok(val),
            Self::Unknown => bail!("ExpCollection not Filled"),
        }
    }
}
