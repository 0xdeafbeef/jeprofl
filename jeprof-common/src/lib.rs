#![no_std]

pub const MIN_ALLOC_SIZE: u32 = 0;
pub const MAX_ALLOC_INDEX: u32 = 1;

#[repr(C)]
pub struct Event {
    pub pid: u32,
    pub size: u64,
    pub timestamp: u64,
    pub stack_id: u32,
}
