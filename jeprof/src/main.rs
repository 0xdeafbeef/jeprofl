use crate::collector::spawn_collector;
use aya::maps::{PerCpuArray, PerCpuHashMap, PerCpuValues, StackTraceMap};
use aya::programs::UProbe;
use aya::util::nr_cpus;
use aya::{include_bytes_aligned, Ebpf};

use aya_log::EbpfLogger;
use bytesize::ByteSize;
use clap::Parser;
use jeprof_common::{
    Histogram, HistogramKey, COUNT_INDEX, FUNCTION_INFO_INDEX, MAX_ALLOC_INDEX, MIN_ALLOC_INDEX,
    SAMPLE_EVERY_INDEX,
};
use log::{debug, info, warn};
use minus::{ExitStrategy, Pager};
use std::fmt::Display;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
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

    /// Max alloc size to track
    #[clap(short, long, default_value_t = u64::MAX)]
    max_alloc_size: u64,
    /// Min allocation size to track
    #[clap(short, long)]
    #[clap(default_value_t = 0)]
    min_alloc_size: u64,

    /// Specify the sampling interval for events.
    /// For example, '1' samples every event, '1000' samples every 1000th event.
    #[clap(short, long)]
    #[clap(default_value_t = NonZeroU32::new(1).unwrap())]
    sample_every: NonZeroU32,

    /// skip allocations with total alocated < `skip_size` bytes
    #[clap(short, long, default_value_t = ByteSize(1))]
    skip_size: ByteSize,

    /// Skips stack traces with total count < `skip_count`
    #[clap(long, default_value_t = 1000)]
    skip_count: u64,

    #[clap(long("csv"))]
    csv_path: Option<PathBuf>,
}

#[derive(derive_more::Display, derive_more::FromStr, Debug, Copy, Clone)]
enum OrderBy {
    Count,
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

impl JemallocAllocFunctions {
    // void *malloc(	size_t size);
    //
    // void *calloc(	size_t number,
    // size_t size);
    //
    // void *realloc(	void *ptr,
    // size_t size);
    pub fn allocation_arg_index(&self) -> u64 {
        match self {
            Self::Malloc => 0,
            Self::Calloc => 1,
            Self::Realloc => 1,
            Self::Mallocx => 1,
            Self::Rallocx => 1,
            Self::Xallocx => 1,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    scopeguard::defer! {
          crossterm::execute!(std::io::stdout(),crossterm::cursor::Show).ok();
    };
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
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/jeprof"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/jeprof"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    {
        let config_map = bpf.map_mut("CONFIG").expect("CONFIG not found");
        let mut config_map = PerCpuArray::try_from(config_map)?;
        let num_cpus = nr_cpus()?;
        config_map.set(
            MIN_ALLOC_INDEX,
            PerCpuValues::try_from(vec![opt.min_alloc_size; num_cpus])?,
            0,
        )?;
        config_map.set(
            MAX_ALLOC_INDEX,
            PerCpuValues::try_from(vec![opt.max_alloc_size; num_cpus])?,
            0,
        )?;
        config_map.set(COUNT_INDEX, PerCpuValues::try_from(vec![0; num_cpus])?, 0)?;
        config_map.set(
            SAMPLE_EVERY_INDEX,
            PerCpuValues::try_from(vec![opt.sample_every.get() as u64; num_cpus])?,
            0,
        )?;
        config_map.set(
            FUNCTION_INFO_INDEX,
            PerCpuValues::try_from(vec![opt.function.allocation_arg_index(); num_cpus])?,
            0,
        )?;
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

    let stack_traces = StackTraceMap::try_from(bpf.take_map("STACKTRACES").unwrap())?;

    let start = std::time::Instant::now();
    let per_cpu_map: PerCpuHashMap<_, HistogramKey, Histogram> =
        PerCpuHashMap::try_from(bpf.take_map("HISTOGRAMS").unwrap())?;
    log::info!(
        "Opened per_cpu_map, took {:?}",
        start.elapsed().as_secs_f64()
    );
    log::info!(
        "Will not save stack traces which has total alocation size < {} or count < {}",
        opt.skip_count,
        opt.skip_size
    );

    let canceled = Arc::new(AtomicBool::new(false));
    let handle = spawn_collector(
        per_cpu_map,
        canceled.clone(),
        stack_traces,
        opt.skip_size.0,
        opt.skip_count,
    );

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");
    canceled.store(true, std::sync::atomic::Ordering::Release);
    // to reduce the probability of installing 2 signal handlers
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Initialize the pager
    let mut pager = Pager::new();
    pager.set_exit_strategy(ExitStrategy::PagerQuit)?;
    // Run the pager in a separate thread
    let t = {
        let pager = pager.clone();
        std::thread::spawn(move || minus::dynamic_paging(pager))
    };

    let handle = handle.join().expect("failed to join thread");

    // let mut str = String::new();
    handle.print_histogram(opt.order_by, &mut pager, opt.csv_path)?;

    t.join().unwrap()?;

    log::info!("Exited");
    Ok(())
}
