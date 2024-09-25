#![no_std]

pub const MIN_ALLOC_SIZE: u32 = 0;
pub const MAX_ALLOC_INDEX: u32 = 1;

const MAX_TRACKED_ALLOCATION_SIZE: usize = const {
    const GIB: usize = 1024 * 1024 * 1024;
    const MAX: usize = 16 * GIB;
    MAX.ilog2() as usize
};

#[repr(transparent)]
#[derive(Clone, Debug, Copy)]
pub struct HistogramKey(u64);

impl HistogramKey {
    pub fn new(pid: u32, stack_id: u32) -> Self {
        Self((pid as u64) << 32 | stack_id as u64)
    }

    pub fn into_parts(&self) -> (u32, u32) {
        let pid = (self.0 >> 32) as u32;
        let stack_id = self.0 as u32;
        (pid, stack_id)
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
        self.total = self.total.wrapping_add(value);
    }
}
