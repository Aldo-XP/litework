//! Tiny probabilistic/capped structures used by tier-0 row-group summaries.
//! All answer "may contain?" — false positives ok, false negatives never.

use ahash::RandomState;
use std::hash::Hash;

/// Fixed hasher so sketches are stable across runs (and later, across the
/// on-disk index format).
fn hasher() -> RandomState {
    RandomState::with_seeds(
        0x9e37_79b9_7f4a_7c15,
        0xbf58_476d_1ce4_e5b9,
        0x94d0_49bb_1331_11eb,
        0x2545_f491_4f6c_dd1d,
    )
}

/// Simple two-hash Bloom filter over N bytes (N*8 bits).
#[derive(Clone)]
pub struct Bloom<const N: usize> {
    bits: [u8; N],
}

impl<const N: usize> Bloom<N> {
    pub fn new() -> Self {
        Bloom { bits: [0; N] }
    }

    fn positions<T: Hash>(v: &T) -> (usize, usize) {
        let h = hasher().hash_one(v);
        let bits = N * 8;
        let h1 = (h as usize) % bits;
        let h2 = ((h >> 32) as usize) % bits;
        (h1, h2)
    }

    pub fn insert<T: Hash>(&mut self, v: &T) {
        let (a, b) = Self::positions(v);
        self.bits[a / 8] |= 1 << (a % 8);
        self.bits[b / 8] |= 1 << (b % 8);
    }

    pub fn may_contain<T: Hash>(&self, v: &T) -> bool {
        let (a, b) = Self::positions(v);
        (self.bits[a / 8] >> (a % 8)) & 1 == 1 && (self.bits[b / 8] >> (b % 8)) & 1 == 1
    }

    pub fn as_bytes(&self) -> &[u8; N] {
        &self.bits
    }

    pub fn from_bytes(bits: [u8; N]) -> Self {
        Bloom { bits }
    }
}

impl<const N: usize> Default for Bloom<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Exact set of small ints (e.g. MAC dictionary ids) capped at CAP entries;
/// past the cap it degrades to "may contain anything".
#[derive(Clone, Default)]
pub struct CappedSet {
    items: Vec<u32>,
    overflow: bool,
}

pub const CAPPED_SET_MAX: usize = 256;

impl CappedSet {
    pub fn insert(&mut self, v: u32) {
        if self.overflow {
            return;
        }
        if let Err(pos) = self.items.binary_search(&v) {
            if self.items.len() >= CAPPED_SET_MAX {
                self.overflow = true;
                self.items = Vec::new();
            } else {
                self.items.insert(pos, v);
            }
        }
    }

    pub fn may_contain(&self, v: u32) -> bool {
        self.overflow || self.items.binary_search(&v).is_ok()
    }

    pub fn is_overflowed(&self) -> bool {
        self.overflow
    }

    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.items.iter().copied()
    }

    pub fn from_parts(items: Vec<u32>, overflow: bool) -> Self {
        CappedSet { items, overflow }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// 256-bit presence set for IP protocol numbers.
#[derive(Clone, Copy, Default)]
pub struct ProtoBits(pub [u64; 4]);

impl ProtoBits {
    pub fn insert(&mut self, p: u8) {
        self.0[(p >> 6) as usize] |= 1 << (p & 63);
    }
    pub fn contains(&self, p: u8) -> bool {
        (self.0[(p >> 6) as usize] >> (p & 63)) & 1 == 1
    }
    pub fn is_empty(&self) -> bool {
        self.0 == [0; 4]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bloom_no_false_negatives() {
        let mut b: Bloom<512> = Bloom::new();
        for p in [53u16, 80, 443, 8080] {
            b.insert(&p);
        }
        for p in [53u16, 80, 443, 8080] {
            assert!(b.may_contain(&p));
        }
    }

    #[test]
    fn capped_set_overflow() {
        let mut s = CappedSet::default();
        for i in 0..300u32 {
            s.insert(i);
        }
        assert!(s.is_overflowed());
        assert!(s.may_contain(999_999)); // degraded to maybe-anything
    }

    #[test]
    fn proto_bits() {
        let mut b = ProtoBits::default();
        b.insert(6);
        b.insert(17);
        b.insert(255);
        assert!(b.contains(6) && b.contains(17) && b.contains(255));
        assert!(!b.contains(7));
    }
}
