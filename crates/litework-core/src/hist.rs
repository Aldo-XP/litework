//! Self-rescaling time histogram: fixed bucket count, bucket width doubles
//! as the observed time range grows. One pass, O(1) per packet, exact counts.

pub const HIST_BUCKETS: usize = 1024;

#[derive(Clone)]
pub struct TimeHist {
    /// Bucket width in nanoseconds (power-of-two multiple of the initial width).
    width: u64,
    /// Timestamp of the left edge of bucket 0.
    origin: u64,
    counts: Vec<u64>,
    bytes: Vec<u64>,
    initialized: bool,
}

impl TimeHist {
    pub fn new() -> Self {
        TimeHist {
            width: 1_000_000_000, // start at 1s buckets
            origin: 0,
            counts: vec![0; HIST_BUCKETS],
            bytes: vec![0; HIST_BUCKETS],
            initialized: false,
        }
    }

    pub fn add(&mut self, ts_nanos: u64, byte_len: u64) {
        if !self.initialized {
            self.origin = ts_nanos - (ts_nanos % self.width);
            self.initialized = true;
        }
        // Out-of-order early packet: shift origin down (rare; realign by rescale).
        while ts_nanos < self.origin {
            self.rescale_down();
        }
        let mut idx = (ts_nanos - self.origin) / self.width;
        while idx >= HIST_BUCKETS as u64 {
            self.rescale();
            idx = (ts_nanos - self.origin) / self.width;
        }
        self.counts[idx as usize] += 1;
        self.bytes[idx as usize] += byte_len;
    }

    /// Merge adjacent bucket pairs, doubling the width.
    fn rescale(&mut self) {
        for i in 0..HIST_BUCKETS / 2 {
            self.counts[i] = self.counts[2 * i] + self.counts[2 * i + 1];
            self.bytes[i] = self.bytes[2 * i] + self.bytes[2 * i + 1];
        }
        for i in HIST_BUCKETS / 2..HIST_BUCKETS {
            self.counts[i] = 0;
            self.bytes[i] = 0;
        }
        self.width *= 2;
    }

    /// Double the width extending the range downwards (for out-of-order data).
    fn rescale_down(&mut self) {
        for i in (0..HIST_BUCKETS / 2).rev() {
            let (c, b) = (self.counts[2 * i] + self.counts[2 * i + 1], self.bytes[2 * i] + self.bytes[2 * i + 1]);
            self.counts[HIST_BUCKETS / 2 + i] = c;
            self.bytes[HIST_BUCKETS / 2 + i] = b;
        }
        for i in 0..HIST_BUCKETS / 2 {
            self.counts[i] = 0;
            self.bytes[i] = 0;
        }
        let span = self.width * (HIST_BUCKETS as u64 / 2);
        self.origin = self.origin.saturating_sub(span);
        self.width *= 2;
    }

    /// Reconstruct from persisted parts (sidecar load).
    pub fn from_parts(width: u64, origin: u64, counts: Vec<u64>, bytes: Vec<u64>) -> Self {
        let initialized = counts.iter().any(|&c| c > 0);
        TimeHist {
            width: width.max(1),
            origin,
            counts,
            bytes,
            initialized,
        }
    }

    pub fn width_nanos(&self) -> u64 {
        self.width
    }
    pub fn origin_nanos(&self) -> u64 {
        self.origin
    }
    pub fn counts(&self) -> &[u64] {
        &self.counts
    }
    pub fn bytes(&self) -> &[u64] {
        &self.bytes
    }

    /// Non-empty span as (first_bucket, last_bucket) indices, if any data.
    pub fn span(&self) -> Option<(usize, usize)> {
        let first = self.counts.iter().position(|&c| c > 0)?;
        let last = self.counts.iter().rposition(|&c| c > 0)?;
        Some((first, last))
    }
}

impl Default for TimeHist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totals_survive_rescale() {
        let mut h = TimeHist::new();
        let base = 1_700_000_000_000_000_000u64;
        // 5000 seconds of data forces multiple rescales past 1024 x 1s
        for s in 0..5000u64 {
            h.add(base + s * 1_000_000_000, 100);
        }
        assert_eq!(h.counts().iter().sum::<u64>(), 5000);
        assert_eq!(h.bytes().iter().sum::<u64>(), 500_000);
        assert!(h.width_nanos() >= 4_000_000_000);
    }

    #[test]
    fn out_of_order_early_packet() {
        let mut h = TimeHist::new();
        let base = 1_700_000_000_000_000_000u64;
        h.add(base, 1);
        h.add(base - 3_000_000_000_000, 1); // 50 min earlier
        assert_eq!(h.counts().iter().sum::<u64>(), 2);
    }
}
