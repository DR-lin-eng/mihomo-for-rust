# Rust Rewrite Workspace

This workspace is the primary implementation track for mihomo.

The Go tree remains in the repository for compatibility comparison, legacy release coverage, and unresolved cutover work, but it should no longer be treated as the default runtime target.

## Docker Build

Current dependencies require a newer stable Rust than the original scaffold documentation assumed.

If the local machine has no Rust toolchain, validate from the `rust/` directory with a Rust 1.88 image or newer:

```bash
docker run --rm -v "$PWD:/work" -w /work rust:1.88 cargo test --workspace
```

The pinned toolchain uses the minimal profile, and from the repository root the default `make build` and `make test` targets already fall back to this Docker-based Rust toolchain path when `cargo` is unavailable locally. The Docker fallback uses isolated target directories for build, test, and release flows so it does not block on a local or concurrent Rust build that is using `rust/target`.

To keep the default Rust mainline build lighter and avoid pulling vendored OpenSSL into every release build, SSH transport support is gated out of the default Rust feature set for now. The same opt-in applies to SSH-specific end-to-end tests in `mihomo-app`. Re-enable it explicitly when the cutover is ready to carry that native dependency in the mainline.
