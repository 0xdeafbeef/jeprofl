use crate::resolver::{ResolvedStackTrace, Resolver};
use crate::OrderBy;
use aya::maps::perf::AsyncPerfEventArrayBuffer;
use aya::maps::{MapData, StackTraceMap};
use bytes::BytesMut;
use futures_util::future::Either;
use histogram::{Bucket, Histogram};
use jeprof_common::Event;
use rustc_hash::FxHashMap;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use std::thread::JoinHandle;
use tokio_util::sync::CancellationToken;

pub fn spawn_collector(
    mut buf: AsyncPerfEventArrayBuffer<MapData>,
    canceled: CancellationToken,
    stack_trace_map: Arc<StackTraceMap<MapData>>,
) -> JoinHandle<Option<EventProcessor>> {
    std::thread::spawn(|| {
        let fut = async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024 * 1024))
                .collect::<Vec<_>>();
            let resolver = Resolver::new();
            let mut processor = EventProcessor::new();
            loop {
                let events = {
                    let read_events = buf.read_events(&mut buffers);
                    let canceled = canceled.cancelled();

                    let read_events = std::pin::pin!(read_events);
                    let canceled = std::pin::pin!(canceled);

                    let res = futures_util::future::select(read_events, canceled).await;
                    match res {
                        Either::Left(events) => events.0.unwrap(),
                        Either::Right(_) => {
                            return Some(processor);
                        }
                    }
                };

                if events.lost != 0 {
                    log::warn!("Lost {} events", events.lost);
                }
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const Event;
                    let data = unsafe { ptr.read_unaligned() };
                    processor.process(data, &resolver, &stack_trace_map);
                }
            }
        };

        // resolver is !Send so we need to spawn the future on a local tokio runtime
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(fut)
    })
}

#[derive(Clone, Debug)]
pub struct EventProcessor {
    allocations_stats: FxHashMap<EventKey, AllocationStat>,
    resolved_traces: HashMap<u32, ResolvedStackTrace>,
}

impl EventProcessor {
    pub fn new() -> Self {
        Self {
            allocations_stats: FxHashMap::with_capacity_and_hasher(1024, Default::default()),
            resolved_traces: Default::default(),
        }
    }

    fn process(
        &mut self,
        event: Event,
        resolver: &Resolver,
        stacktrace_map: &Arc<StackTraceMap<MapData>>,
    ) {
        let key = EventKey {
            pid: event.pid,
            stack_id: event.stack_id,
        };
        let entry = self
            .allocations_stats
            .entry(key)
            .or_insert_with(AllocationStat::new);
        entry.histogram.increment(event.size).unwrap();
        entry.total_size += event.size;

        match self.resolved_traces.entry(event.stack_id) {
            Entry::Occupied(_) => {}
            Entry::Vacant(e) => {
                let Ok(trace) = stacktrace_map.get(&event.stack_id, 0) else {
                    return;
                };
                let stack_trace = resolver.resolve_stacktrace(&trace, event.pid).unwrap();
                e.insert(stack_trace);
            }
        }
    }

    pub fn merge(&self, other: Self) -> Self {
        let mut hashmap = self.allocations_stats.clone();
        for (key, hist) in other.allocations_stats {
            let entry = hashmap.entry(key).or_insert_with(AllocationStat::new);
            *entry = entry.wrapping_add(&hist).unwrap();
        }

        let mut resolved_traces = self.resolved_traces.clone();
        resolved_traces.extend(other.resolved_traces);

        Self {
            allocations_stats: hashmap,
            resolved_traces,
        }
    }

    pub(crate) fn print_histogram(
        self,
        by: OrderBy,
        mut pager: impl std::fmt::Write,
    ) -> anyhow::Result<()> {
        let mut allocations_stats = self.allocations_stats.into_iter().collect::<Vec<_>>();
        match by {
            OrderBy::Size => {
                allocations_stats.sort_by_key(|(_, stat)| {
                    stat.histogram.percentile(50.0).unwrap().map(|x| x.end())
                });
            }
            OrderBy::Traffic => {
                allocations_stats.sort_by_key(|(_, stat)| stat.total_size);
            }
        }

        for (key, hist) in allocations_stats {
            let resolved = self.resolved_traces.get(&key.stack_id);
            if let Some(resolved) = resolved {
                for symbol in &resolved.symbols {
                    writeln!(&mut pager, "{} - {}", symbol.address, symbol.symbol)?;
                }
            }

            hist.print_histogram(&mut pager)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
struct EventKey {
    pid: u32,
    stack_id: u32,
}

#[derive(Clone, Debug)]
pub struct AllocationStat {
    histogram: Histogram,
    total_size: u64,
}

impl AllocationStat {
    pub fn new() -> Self {
        Self {
            // A maximum trackable value of 2^20 - 1 = 1,048,575 bytes (just under 1MB)
            // A relative error of about 0.781% (2^-7)
            histogram: Histogram::new(7, 20).unwrap(),
            total_size: 0,
        }
    }

    pub fn wrapping_add(&self, other: &Self) -> anyhow::Result<Self> {
        let histogram = self.histogram.wrapping_add(&other.histogram)?;
        let total_size = self.total_size.wrapping_add(other.total_size);

        Ok(Self {
            histogram,
            total_size,
        })
    }

    pub fn print_histogram(self, mut lock: impl std::fmt::Write) -> anyhow::Result<()> {
        let AllocationStat {
            histogram: hist,
            total_size,
        } = self;

        let buckets: Vec<Bucket> = hist.into_iter().collect();

        let max_bar_width = 50;
        let max_count = buckets.iter().map(|b| b.count()).max().unwrap_or(0);

        let total_allocations: u64 = buckets.iter().map(|b| b.count()).sum();
        writeln!(&mut lock, "Total allocations: {total_allocations}")?;
        writeln!(
            &mut lock,
            "Total allocated: {}",
            bytesize::to_string(total_size, true)
        )?;

        writeln!(&mut lock, "Histogram:")?;
        writeln!(&mut lock, "Range                 Count  Bar")?;
        writeln!(
            &mut lock,
            "-------------------  ------  --------------------------------------------------"
        )?;

        let mut last_end: Option<u64> = None;
        let mut zero_start: Option<u64> = None;

        for bucket in buckets {
            let range = bucket.range();
            let start = *range.start();
            let end = *range.end();
            let count = bucket.count();

            // Ensure that ranges are continuous
            if let Some(last) = last_end {
                if start > last + 1 {
                    // There is a gap between last bucket and current bucket
                    writeln!(
                        &mut lock,
                        "{:>8}-{:<8}  {:>6}  ",
                        bytesize::to_string(last + 1, true),
                        bytesize::to_string(start - 1, true),
                        0
                    )?;
                }
            }

            if count == 0 {
                if zero_start.is_none() {
                    zero_start = Some(start);
                }
            } else {
                if let Some(zero_s) = zero_start {
                    // Print accumulated zero-count range before current bucket
                    writeln!(
                        &mut lock,
                        "{:>8}-{:<8}  {:>6}  ",
                        bytesize::to_string(zero_s, true),
                        bytesize::to_string(start - 1, true),
                        0
                    )?;
                    zero_start = None;
                }

                // Calculate bar width using logarithmic scale
                let bar_width = if max_count > 1 {
                    ((count as f64).ln() / (max_count as f64).ln() * max_bar_width as f64).round()
                        as usize
                } else {
                    count as usize
                };
                let bar = "#".repeat(bar_width);

                // Print the row with logarithmic range display
                writeln!(
                    &mut lock,
                    "{:>8}-{:<8}  {:>6}  {}",
                    bytesize::to_string(start, true),
                    bytesize::to_string(end, true),
                    count,
                    bar
                )?;
            }

            last_end = Some(end);
        }

        // Print any remaining zero-count range at the end
        if let Some(zero_s) = zero_start {
            let last = last_end.unwrap_or(zero_s - 1);
            writeln!(
                &mut lock,
                "{:>8}-{:<8}  {:>6}  ",
                bytesize::to_string(zero_s, true),
                bytesize::to_string(last + 1, true),
                0
            )?;
        }

        Ok(())
    }
}
