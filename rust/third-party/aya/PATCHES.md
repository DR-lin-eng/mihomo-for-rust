# Local Aya patch

Source: Aya 0.13.1 from crates.io, https://github.com/aya-rs/aya.
License: MIT OR Apache-2.0; both upstream license texts are retained.

The only runtime change is an additive `EbpfLoader::new_without_btf()` constructor in `src/bpf.rs`. The original `new()` still reads kernel BTF and otherwise behaves identically. The new constructor initializes the same fields with `btf: None`, so UAPI-only TC programs avoid reading and parsing `/sys/kernel/btf/vmlinux` before disabling CO-RE. No private field layout assumptions or unsafe constructor tricks are used.

The workspace uses this pinned package through `[patch.crates-io]`. Replace this local copy with an upstream equivalent once Aya exposes a constructor that skips the initial BTF read. Other upstream runtime code is unchanged. `Cargo.toml` is the published normalized manifest; this copy is excluded from workspace test discovery and remains an ordinary dependency.
