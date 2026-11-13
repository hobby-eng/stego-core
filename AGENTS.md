# stego-core

The core library of StegoCode. Workspace rules: `AGENTS.md` in the workspace root.

Toolchain: Rust 1.99.1 (`rust-toolchain.toml`). On the development machine set `CARGO_HOME` and `RUSTUP_HOME` as the workspace rules say, and run heavy commands under the CORE-53 thermal limits.

Fast gates (CORE-43):

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`

Layout: `src/algorithm/` holds the cost models and syndrome codes (no file I/O); `src/jpeg*` the baseline JPEG coefficient codec; `src/sites.rs` the site rules; `src/coding.rs` the three layers; `src/record.rs`, `src/keys.rs` the records and keys; `src/parts.rs`, `src/threshold.rs` sets of several photos; `src/hide.rs`, `src/reveal.rs` the public jobs. `tests/reference/` keeps the Python oracle of the J-CRFW tests.
