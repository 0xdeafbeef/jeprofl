# jeprof

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Build eBPF and Userspace

```bash
cargo xtask build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```

# Todo

- [x] aggregate histogram in kernelspace. For now, we 're just dumping all the
  data to userspace, which gives 1us overhead per call which is unacceptable.
  Pure uprobe uses 20ns per call.
- [ ] find which malloc is used (now we assume that target is statically linked)
- [ ] add ratatui based tui
- [ ] produce flamegraphs