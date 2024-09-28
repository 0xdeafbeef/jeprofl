use crate::resolver::{ResolvedStackTrace, Resolver};
use crate::OrderBy;
use aya::maps::{MapData, PerCpuHashMap, StackTraceMap};

use jeprof_common::{Histogram, HistogramKey, ReducedEventKey, UnpackedHistogramKey};
use rustc_hash::FxHashMap;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

pub fn spawn_collector(
    buf: PerCpuHashMap<MapData, HistogramKey, Histogram>,
    canceled: Arc<AtomicBool>,
    stack_trace_map: Arc<StackTraceMap<MapData>>,
    skip_total_alloc_size_lower_than: u64,
) -> JoinHandle<EventProcessor> {
    thread::spawn(move || {
        let resolver = Resolver::new();
        let mut processor = EventProcessor::new();

        loop {
            thread::sleep(Duration::from_secs(1));
            if canceled.load(Ordering::Acquire) {
                return processor;
            }

            for cpu in buf.iter() {
                let (key, per_cpu_histograms) = cpu.unwrap();
                let key = key.into_parts();
                for hist in per_cpu_histograms.iter() {
                    if hist.total < skip_total_alloc_size_lower_than {
                        continue;
                    }
                    if canceled.load(Ordering::Acquire) {
                        return processor;
                    }
                    processor.process(key, hist, &resolver, &stack_trace_map);
                }
            }
        }
    })
}

#[derive(Clone, Debug)]
pub struct EventProcessor {
    allocations_stats: FxHashMap<UnpackedHistogramKey, Histogram>,
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
        key: UnpackedHistogramKey,
        event: &Histogram,
        resolver: &Resolver,
        stacktrace_map: &Arc<StackTraceMap<MapData>>,
    ) {
        self.allocations_stats.insert(key, *event); // just update with latest snapshot TODO: merge somehow

        match self.resolved_traces.entry(key.stack_id) {
            Entry::Occupied(_) => {}
            Entry::Vacant(e) => {
                let Ok(trace) = stacktrace_map.get(&key.stack_id, 0) else {
                    return;
                };
                let stack_trace = match resolver.resolve_stacktrace(&trace, key.pid) {
                    Ok(stacktrace) => stacktrace,
                    Err(e) => {
                        log::debug!("Failed to resolve {e}");
                        return;
                    }
                };
                e.insert(stack_trace);
            }
        }
    }

    fn merge(&self) -> FxHashMap<ReducedEventKey, Histogram> {
        let mut allocations_stats: FxHashMap<ReducedEventKey, Histogram> =
            FxHashMap::with_capacity_and_hasher(self.allocations_stats.len(), Default::default());

        for (key, stat) in &self.allocations_stats {
            match allocations_stats.entry(key.as_reduced()) {
                Entry::Occupied(mut e) => e.get_mut().merge(stat),
                Entry::Vacant(e) => {
                    e.insert(*stat);
                }
            }
        }
        allocations_stats
    }

    pub fn print_histogram(
        &self,
        order_by: OrderBy,
        mut pager: impl std::fmt::Write,
    ) -> anyhow::Result<()> {
        let stats = self.merge();
        writeln!(pager, "total stack traces: {}\n", stats.len())?;

        let mut entries: Vec<(_, _)> = stats.iter().filter(|(_, hist)| hist.total > 0).collect();

        match order_by {
            OrderBy::Count => {
                entries.sort_by_key(|(_, hist)| hist.data.iter().sum::<u64>());
            }
            OrderBy::Traffic => {
                entries.sort_by_key(|(_, hist)| hist.total);
            }
        }
        for (key, hist) in entries {
            print_section(&mut pager, '*')?;

            if let Some(resolved_trace) = self.resolved_traces.get(&key.stack_id) {
                for fun in resolved_trace.symbols.iter() {
                    writeln!(pager, "{} - {}", fun.address, fun.symbol)?;
                }
            } else {
                writeln!(pager, "No resolved stacktrace")?;
            }

            print_section(&mut pager, '-')?;

            print_histogram(hist, &mut pager)?;
            writeln!(&mut pager, "\n")?;
        }

        Ok(())
    }
}

fn print_section(mut pager: impl std::fmt::Write, char: char) -> anyhow::Result<()> {
    let string = (0..80).map(|_| char).collect::<String>();
    pager.write_str(&string)?;
    pager.write_char('\n')?;
    Ok(())
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
