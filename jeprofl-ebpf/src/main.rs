#![no_std]
#![no_main]

use aya_ebpf::bindings::BPF_F_USER_STACK;
use aya_ebpf::helpers::bpf_get_smp_processor_id;
use aya_ebpf::macros::map;
use aya_ebpf::maps::{PerCpuArray, PerCpuHashMap, StackTrace};
use aya_ebpf::{helpers::bpf_get_current_pid_tgid, macros::uprobe, programs::ProbeContext};
use jeprofl_common::{
    Histogram, HistogramKey, COUNT_INDEX, FUNCTION_INFO_INDEX, MAX_ALLOC_INDEX, MIN_ALLOC_INDEX,
    SAMPLE_EVERY_INDEX,
};

#[map(name = "CONFIG")]
static STATE: PerCpuArray<u64> = PerCpuArray::with_max_entries(5, 0);

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
        const ARG_INDEX: usize = 0;
        if !should_process() {
            return Ok(0);
        }
        // todo: somehow make solver to believe that arg lies in the range [0, 3] to allow dynamic profiling
        // let Some(arg_index) = STATE.get(FUNCTION_INFO_INDEX).copied() else {
        //     return Err(0);
        // };
        //
        // let Some(arg_index) = STATE.get(FUNCTION_INFO_INDEX).copied() else {
        //     return Err(0);
        // };
        //
        // if !check_bounds_unsigned(arg_index as _, 0, 3) {
        //     return Err(0);
        // }
        //
        // let arg_index = arg_index as usize;

        let size = match ctx.arg::<u64>(ARG_INDEX) {
            Some(s) => s,
            None => return Err(0),
        };

        let min_size = *STATE.get(MIN_ALLOC_INDEX).unwrap_or(&0);
        let max_size = *STATE.get(MAX_ALLOC_INDEX).unwrap_or(&u64::MAX);

        if size <= min_size || size >= max_size {
            return Ok(0);
        }

        let pid = bpf_get_current_pid_tgid() as u32;
        let stack_id = match STACKTRACES.get_stackid(&ctx, BPF_F_USER_STACK.into()) {
            Ok(stack_id) => stack_id,
            Err(_) => return Err(0),
        } as u32; // userspace stacks are always 32-bit

        let current_cpu = bpf_get_smp_processor_id();
        update_hist(size, pid, stack_id, current_cpu)?;
    }

    Ok(0)
}

fn should_process() -> bool {
    let sample_every = match STATE.get(SAMPLE_EVERY_INDEX) {
        None => {
            return true;
        }
        Some(v) if *v == 0 => return true,
        Some(v) => *v,
    };
    let Some(ctr) = STATE.get_ptr_mut(COUNT_INDEX) else {
        return true;
    };
    let Some(ctr) = (unsafe { ctr.as_mut() }) else {
        return true;
    };
    *ctr += 1;
    (*ctr % sample_every) == 0
}

unsafe fn update_hist(size: u64, pid: u32, stack_id: u32, current_cpu: u32) -> Result<u32, u32> {
    let key = HistogramKey::new(pid, stack_id, current_cpu as _);
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
