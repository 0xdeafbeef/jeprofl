use anyhow::Result;
use std::num::NonZeroU32;

use aya::maps::stack_trace::StackTrace;
use blazesym::symbolize::{Input, Process, Source, Symbolized};
use blazesym::Pid;
use itertools::Itertools;

pub struct Resolver {
    symbolizer: blazesym::symbolize::Symbolizer,
}

impl Resolver {
    pub fn new() -> Resolver {
        let symbolizer = blazesym::symbolize::Symbolizer::new();
        Resolver { symbolizer }
    }

    pub fn resolve_stacktrace(
        &self,
        stacktrace: &StackTrace,
        pid: u32,
    ) -> Result<ResolvedStackTrace> {
        let pid = Pid::Pid(NonZeroU32::new(pid).unwrap());
        let stacktrace: Vec<_> = stacktrace.frames().iter().map(|x| x.ip).collect();
        let stacktrace = Input::AbsAddr(stacktrace.as_slice());
        let res = self
            .symbolizer
            .symbolize(&Source::Process(Process::new(pid)), stacktrace)?
            .into_iter()
            .map(|x| match x {
                Symbolized::Sym(s) => OwnedSymbol {
                    address: s.addr,
                    symbol: s.name.to_string(),
                },
                Symbolized::Unknown(reason) => OwnedSymbol {
                    address: 0,
                    symbol: reason.to_string(),
                },
            })
            .collect();

        Ok(ResolvedStackTrace { symbols: res })
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedStackTrace {
    pub symbols: Vec<OwnedSymbol>,
}

impl ResolvedStackTrace {
    pub fn as_inferno(&self, calculation: u64) -> String {
        let mut symbols: String = self.symbols.iter().map(|x| x.symbol.clone()).join(";");
        symbols.push(' ');
        symbols.push_str(&calculation.to_string());
        symbols
    }
}

#[derive(Debug, Clone)]
pub struct OwnedSymbol {
    pub address: u64,
    pub symbol: String,
}
