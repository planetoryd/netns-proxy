use amplify::Display;
use rangemap::RangeInclusiveSet;
use thiserror::Error;

#[derive(Default, Debug)]
/// ID allocator implemented with range set
pub struct IDAlloc(RangeInclusiveSet<ID>);

pub type ID = u32;

impl IDAlloc {
    pub fn alloc(&mut self) -> Option<ID> {
        let domain = 0..=ID::MAX;
        if let Some(ra) = self.0.gaps(&domain).next() {
            assert!(!ra.is_empty());
            let k = *ra.start();
            let id = k..=k;
            self.0.insert(id);
            Some(k)
        } else {
            None
        }
    }
    pub fn dealloc(&mut self, id: ID) {
        self.0.remove(id..=id);
    }
    pub fn alloc_or(&mut self) -> Result<ID, IDAllocError> {
        self.alloc().ok_or(IDAllocError)
    }
}

#[derive(Error, Debug)]
#[error("failed to allocate new id")]
pub struct IDAllocError;

#[test]
fn allocs() {
    let mut ida = IDAlloc::default();
    assert!(ida.0.is_empty());
    assert_eq!(ida.alloc(), Some(0));
    assert_eq!(ida.alloc(), Some(1));
    assert_eq!(ida.alloc(), Some(2));
    ida.dealloc(1);
    assert_eq!(ida.alloc(), Some(1));
    assert_eq!(ida.alloc(), Some(3));
    ida.dealloc(3);
    assert_eq!(ida.alloc(), Some(3));
    assert_eq!(ida.alloc(), Some(4));
}

#[test]
fn rset() {
    let mut rset = RangeInclusiveSet::new();
    rset.insert(0..=0);
    rset.insert(1..=1);
    rset.insert(2..=2);
    dbg!(rset.gaps(&(0..=1)).collect::<Vec<_>>());
}
