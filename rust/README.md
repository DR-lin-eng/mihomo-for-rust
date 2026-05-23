# Rust Rewrite Workspace

This workspace is the starting point for a full Rust rewrite of the Go core.

It is intentionally additive:

- the existing Go implementation remains the reference runtime
- the Rust tree codifies compatibility boundaries before behavior is replaced
- subsystem crates mirror the current core layout instead of only targeting one hot path

## Docker Build

If the local machine has no Rust toolchain, validate with Docker from the `rust/` directory:

```bash
docker run --rm -v "$PWD:/work" -w /work rust:1.78 cargo test --workspace
```
