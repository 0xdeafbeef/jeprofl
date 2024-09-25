use crate::resolver::{ResolvedStackTrace, Resolver};
use crate::OrderBy;
use aya::maps::{MapData, PerCpuHashMap, StackTraceMap};
use futures_util::future::Either;
use jeprof_common::{Histogram, HistogramKey};
use rustc_hash::FxHashMap;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use std::thread::JoinHandle;
use tokio_util::sync::CancellationToken;

pub fn spawn_collector(
    buf: PerCpuHashMap<MapData, HistogramKey, Histogram>,
    canceled: CancellationToken,
    stack_trace_map: Arc<StackTraceMap<MapData>>,
) -> JoinHandle<Option<EventProcessor>> {
    std::thread::spawn(move || {
        let fut = async move {
            let resolver = Resolver::new();
            let mut processor = EventProcessor::new();
            loop {
                {
                    let elapsed = tokio::time::sleep(std::time::Duration::from_secs(10));
                    let canceled = canceled.cancelled();

                    let read_events = std::pin::pin!(elapsed);
                    let canceled = std::pin::pin!(canceled);

                    let res = futures_util::future::select(read_events, canceled).await;
                    match res {
                        Either::Left(_) => {}
                        Either::Right(_) => {
                            return Some(processor);
                        }
                    }
                };

                for cpu in buf.iter() {
                    let (key, stacktrace) = cpu.unwrap();
                    let (pid, stack_id) = key.into_parts();
                    for hist in stacktrace.iter() {
                        processor.process(pid, stack_id, hist, &resolver, &stack_trace_map);
                    }
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
    allocations_stats: FxHashMap<EventKey, Histogram>,
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
        pid: u32,
        stack_id: u32,
        event: &Histogram,
        resolver: &Resolver,
        stacktrace_map: &Arc<StackTraceMap<MapData>>,
    ) {
        let key = EventKey { pid, stack_id };
        self.allocations_stats.insert(key, *event); // just update with latest snapshot TODO: merge somehow

        match self.resolved_traces.entry(stack_id) {
            Entry::Occupied(_) => {}
            Entry::Vacant(e) => {
                let Ok(trace) = stacktrace_map.get(&stack_id, 0) else {
                    return;
                };
                let stack_trace = resolver.resolve_stacktrace(&trace, pid).unwrap();
                e.insert(stack_trace);
            }
        }
    }

    pub fn print_histogram(
        &self,
        order_by: OrderBy,
        mut pager: impl std::fmt::Write,
    ) -> anyhow::Result<()> {
        let mut entries: Vec<(_, _)> = self
            .allocations_stats
            .iter()
            .filter(|(_, hist)| hist.total > 0)
            .collect();

        match order_by {
            OrderBy::Size => {
                entries.sort_by_key(|(_, hist)| hist.data.iter().sum::<u64>());
            }
            OrderBy::Traffic => {
                entries.sort_by_key(|(_, hist)| hist.total);
            }
        }
        for (key, hist) in entries {
            let resolved_trace = self.resolved_traces.get(&key.stack_id).unwrap();
            for fun in resolved_trace.symbols.iter() {
                writeln!(pager, "{} - {}", fun.address, fun.symbol)?;
            }
            print_histogram(hist, &mut pager)?;
        }

        Ok(())
    }
}

pub(crate) fn print_histogram(
    hist: &Histogram,
    mut pager: impl std::fmt::Write,
) -> anyhow::Result<()> {
    let mut entries: Vec<(usize, u64)> = hist
        .data
        .iter()
        .enumerate()
        .filter(|(_, &count)| count > 0)
        .map(|(size, &count)| (size, count))
        .collect();

    entries.sort_by_key(|&(size, _)| size);

    let max_count = entries.iter().map(|&(_, count)| count).max().unwrap_or(1);
    let bar_width = 50; // Maximum width of the bar

    writeln!(pager, "Size      | Count     | Percentage | Distribution")?;
    writeln!(
        pager,
        "----------+-----------+------------+{}",
        "-".repeat(bar_width)
    )?;

    let total_count: u64 = entries.iter().map(|&(_, count)| count).sum();

    for (size, count) in entries {
        let size_bytes = size_bytes(size);
        let percentage = (count as f64 / total_count as f64) * 100.0;
        let bar_length = ((count as f64 / max_count as f64) * bar_width as f64).round() as usize;

        writeln!(
            pager,
            "{:10} | {:9} | {:9.2}% | {}",
            bytesize::to_string(size_bytes, true),
            count,
            percentage,
            "#".repeat(bar_length)
        )?;
    }

    writeln!(
        pager,
        "Total allocations: {} in {} allocations",
        bytesize::to_string(hist.total, true),
        total_count
    )?;

    Ok(())
}
fn size_bytes(size: usize) -> u64 {
    1u64 << size
}
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
struct EventKey {
    pid: u32,
    stack_id: u32,
}

#[cfg(test)]
mod test {
    use crate::collector::print_histogram;
    use jeprof_common::Histogram;

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn print_histogram_empty() {
            let histogram = Histogram::new();
            let mut buf = String::new();
            print_histogram(&histogram, &mut buf).unwrap();
            insta::assert_snapshot!(buf);
        }

        #[test]
        fn print_histogram_single_allocation() {
            let mut histogram = Histogram::new();
            histogram.increment(1023);
            let mut buf = String::new();
            print_histogram(&histogram, &mut buf).unwrap();
            insta::assert_snapshot!(buf);
        }

        #[test]
        fn print_histogram_multiple_sizes() {
            let mut histogram = Histogram::new();
            histogram.increment(1); // 1 B
            histogram.increment(512); // 512 B
            histogram.increment(1026); // 2 KB
            let mut buf = String::new();
            print_histogram(&histogram, &mut buf).unwrap();
            insta::assert_snapshot!(buf);
        }

        #[test]
        fn print_histogram_large_allocations() {
            let mut histogram = Histogram::new();
            histogram.increment(1 << 20); // 1 MB
            histogram.increment(1u64 << 30); // 1 GB
            let mut buf = String::new();
            print_histogram(&histogram, &mut buf).unwrap();
            insta::assert_snapshot!(buf);
        }

        #[test]
        fn print_histogram_many_small_allocations() {
            let mut histogram = Histogram::new();
            for _ in 0..1000 {
                histogram.increment(1); // 1 B
            }
            histogram.increment(1023); // 1 KB
            let mut buf = String::new();
            print_histogram(&histogram, &mut buf).unwrap();
            insta::assert_snapshot!(buf);
        }
    }
}
