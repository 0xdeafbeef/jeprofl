#![no_std]
#![no_main]

use aya_ebpf::bindings::BPF_F_USER_STACK;
use aya_ebpf::macros::map;
use aya_ebpf::maps::StackTrace;
use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::uprobe,
    maps::{Array, PerfEventArray},
    programs::ProbeContext,
};
use jeprof_common::{Event, MAX_ALLOC_INDEX, MIN_ALLOC_SIZE};

#[map(name = "CONFIG")]
static CONFIG: Array<u64> = Array::with_max_entries(2, 0);

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::with_max_entries(1024 * 1024, 0);

#[map(name = "STACKTRACES")]
static mut STACKTRACES: StackTrace = StackTrace::with_max_entries(1024 * 1024, 0);

#[uprobe]
pub fn malloc(ctx: ProbeContext) -> u32 {
    try_malloc(ctx).unwrap_or_else(|ret| ret)
}

fn try_malloc(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let Some(size) = ctx.arg::<u64>(0) else {
            return Err(0);
        };

        let min_size = *CONFIG.get(MIN_ALLOC_SIZE).unwrap_or(&0);
        let max_size = *CONFIG.get(MAX_ALLOC_INDEX).unwrap_or(&u64::MAX);

        if size >= min_size && size <= max_size {
            let pid = bpf_get_current_pid_tgid() as u32;
            let stack_id = match STACKTRACES.get_stackid(&ctx, BPF_F_USER_STACK.into()) {
                Ok(stack_id) => stack_id,
                Err(_) => return Err(0),
            } as _;
            let timestamp = bpf_ktime_get_ns();

            let event = Event {
                pid,
                size,
                timestamp,
                stack_id,
            };
            EVENTS.output(&ctx, &event, 0);
        }
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
