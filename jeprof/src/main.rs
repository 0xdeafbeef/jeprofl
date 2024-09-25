use crate::collector::spawn_collector;
use anyhow::Context;
use aya::maps::{Array, PerCpuHashMap, StackTraceMap};
use aya::programs::UProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use jeprof_common::{Histogram, HistogramKey, MIN_ALLOC_SIZE};
use log::{debug, info, warn};
use minus::Pager;
use std::fmt::Display;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tokio::signal;

mod collector;
mod resolver;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<i32>,

    #[clap(long)]
    program: PathBuf,

    #[clap(short, long, default_value = "malloc")]
    function: JemallocAllocFunctions,

    #[clap(short, long, default_value = "Size")]
    order_by: OrderBy,

    #[clap(short, long, default_value_t = u64::MAX)]
    max_alloc_size: u64,
    #[clap(short, long)]
    #[clap(default_value_t = 0)]
    min_alloc_size: u64,
}

#[derive(derive_more::Display, derive_more::FromStr, Debug, Copy, Clone)]
enum OrderBy {
    Size,
    Traffic,
}

#[derive(Debug, Clone, Copy)]
enum JemallocAllocFunctions {
    Malloc,
    Calloc,
    Realloc,
    Mallocx,
    Rallocx,
    Xallocx,
}

impl FromStr for JemallocAllocFunctions {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "malloc" => Ok(Self::Malloc),
            "calloc" => Ok(Self::Calloc),
            "realloc" => Ok(Self::Realloc),
            "mallocx" => Ok(Self::Mallocx),
            "rallocx" => Ok(Self::Rallocx),
            "xallocx" => Ok(Self::Xallocx),
            _ => Err(anyhow::anyhow!("Invalid function name {}", s)),
        }
    }
}

impl Display for JemallocAllocFunctions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malloc => write!(f, "malloc"),
            Self::Calloc => write!(f, "calloc"),
            Self::Realloc => write!(f, "realloc"),
            Self::Mallocx => write!(f, "mallocx"),
            Self::Rallocx => write!(f, "rallocx"),
            Self::Xallocx => write!(f, "xallocx"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/jeprof"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/jeprof"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    {
        let config_map = bpf.map_mut("CONFIG").expect("CONFIG not found");
        let mut config_map = Array::try_from(config_map)?;
        config_map.set(MIN_ALLOC_SIZE, opt.min_alloc_size, 0)?;
        config_map.set(1, opt.max_alloc_size, 0)?;
    }

    let program: &mut UProbe = bpf.program_mut("malloc").unwrap().try_into()?;
    program.load()?;

    let function = opt.function.to_string();
    log::info!(
        "Attaching to function: {}:{}",
        opt.program.display(),
        function
    );

    program.attach(Some(function.as_str()), 0, &opt.program, opt.pid)?;

    let canceled = tokio_util::sync::CancellationToken::new();
    let stack_traces = StackTraceMap::try_from(bpf.take_map("STACKTRACES").unwrap())?;
    let stack_traces = Arc::new(stack_traces);

    let per_cpu_map: PerCpuHashMap<_, HistogramKey, Histogram> =
        PerCpuHashMap::try_from(bpf.take_map("HISTOGRAMS").unwrap())?;

    let canceled = canceled.clone();

    //todo: config histogram
    let handle = spawn_collector(per_cpu_map, canceled.clone(), stack_traces.clone());

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");
    canceled.cancel();

    // Initialize the pager
    let pager = Pager::new();
    // Run the pager in a separate thread
    let pager2 = pager.clone();
    let t = std::thread::spawn(move || minus::dynamic_paging(pager2));

    let handle = handle
        .join()
        .expect("failed to join thread")
        .context("nothing collected")?;
    handle.print_histogram(opt.order_by, pager)?;

    t.join().unwrap()?;

    Ok(())
}
