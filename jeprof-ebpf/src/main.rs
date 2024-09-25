#![no_std]
#![no_main]

use aya_ebpf::bindings::BPF_F_USER_STACK;
use aya_ebpf::macros::map;
use aya_ebpf::maps::{PerCpuHashMap, StackTrace};
use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid, macros::uprobe, maps::Array, programs::ProbeContext,
};
use jeprof_common::{Histogram, HistogramKey, MAX_ALLOC_INDEX, MIN_ALLOC_SIZE};

#[map(name = "CONFIG")]
static CONFIG: Array<u64> = Array::with_max_entries(2, 0);

#[map(name = "STACKTRACES")]
static mut STACKTRACES: StackTrace = StackTrace::with_max_entries(1024 * 1024, 0);

#[map(name = "HISTOGRAMS")]
static mut HISTOGRAMS: PerCpuHashMap<HistogramKey, Histogram> = // pid, stack_id to histogram
    PerCpuHashMap::with_max_entries(1024 * 1024, 0);

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

        if size <= min_size || size >= max_size {
            return Ok(0);
        }

        let pid = bpf_get_current_pid_tgid() as u32;
        let stack_id = match STACKTRACES.get_stackid(&ctx, BPF_F_USER_STACK.into()) {
            Ok(stack_id) => stack_id,
            Err(_) => return Err(0),
        } as u32; // userspace stacks are always 32-bit

        // update_hist(size, pid, stack_id);
    }

    Ok(0)
}

unsafe fn update_hist(size: u64, pid: u32, stack_id: u32) -> Result<u32, u32> {
    let key = HistogramKey::new(pid, stack_id);
    match HISTOGRAMS.get_ptr_mut(&key) {
        None => {
            let mut histogram = Histogram::new();
            histogram.increment(size);
            HISTOGRAMS
                .insert(&key, &histogram, 0)
                .map_err(|e| e as u32)?; //todo use lru?
        }
        Some(hist) => {
            let Some(hist) = hist.as_mut() else {
                // should be impossible
                return Err(0);
            };
            hist.increment(size);
        }
    }
    Ok(0)
}

// unsafe fn update_counter(pid: u32, stack_id: u32) -> Result<u32, u32> {
//     match HISTOGRAMS.get_ptr_mut(&(pid, stack_id)) {
//         None => {
//             let mut counter = Counter::new();
//             HISTOGRAMS
//                 .insert(&(pid, stack_id), &counter, 0)
//                 .map_err(|e| e as u32)?; //todo use lru?
//         }
//         Some(counter) => {
//             let Some(counter) = counter.as_mut() else {
//                 // should be impossible
//                 return Err(0);
//             };
//             counter.increment();
//         }
//     }
//     Ok(0)
// }

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
