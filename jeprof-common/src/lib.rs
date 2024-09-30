#![no_std]

pub const MIN_ALLOC_INDEX: u32 = 0;
pub const MAX_ALLOC_INDEX: u32 = 1;
pub const COUNT_INDEX: u32 = 2;
pub const SAMPLE_EVERY_INDEX: u32 = 3;

const MAX_TRACKED_ALLOCATION_SIZE: usize = const {
    const GIB: usize = 1024 * 1024 * 1024;
    const MAX: usize = 16 * GIB;
    MAX.ilog2() as usize
};

#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub struct HistogramKey {
    pid_stack: u64,
    cpu: u64, // for alignment
}

impl HistogramKey {
    pub fn new(pid: u32, stack_id: u32, cpu: u32) -> Self {
        Self {
            pid_stack: ((pid as u64) << 32 | stack_id as u64),
            cpu: cpu as u64,
        }
    }

    pub fn into_parts(&self) -> UnpackedHistogramKey {
        let pid = (self.pid_stack >> 32) as u32;
        let stack_id = self.pid_stack as u32;
        UnpackedHistogramKey {
            pid,
            stack_id,
            cpu: self.cpu as u32,
        }
    }
}

#[derive(Clone, Debug, Copy, Hash, Eq, PartialEq)]
pub struct UnpackedHistogramKey {
    pub pid: u32,
    pub stack_id: u32,
    pub cpu: u32,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct ReducedEventKey {
    pub pid: u32,
    pub stack_id: u32,
}

impl UnpackedHistogramKey {
    pub fn as_reduced(&self) -> ReducedEventKey {
        ReducedEventKey {
            pid: self.pid,
            stack_id: self.stack_id,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for HistogramKey {}

#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub struct Histogram {
    pub data: [u64; MAX_TRACKED_ALLOCATION_SIZE],
    pub total: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Histogram {}

impl Histogram {
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            data: [0; MAX_TRACKED_ALLOCATION_SIZE],
            total: 0,
        }
    }

    pub fn increment(&mut self, value: u64) {
        if value == 0 {
            // log(0) is undefined
            return;
        }
        let pow2 = value.ilog2() as usize;

        if let Some(bucket) = self.data.get_mut(pow2) {
            *bucket += 1;
        }
        self.total = self.total.saturating_add(value);
    }

    pub fn merge(&mut self, other: &Histogram) {
        self.total = self.total.saturating_add(other.total);
        for (l, r) in self.data.iter_mut().zip(other.data.iter()) {
            *l = l.saturating_add(*r);
        }
    }

    pub fn total_count(&self) -> u64 {
        self.data.iter().sum()
    }
}
