## 1. Remove unused dependencies

- [x] 1.1 Remove minus = "5.3.1" from root Cargo.toml
- [x] 1.2 Remove serde from root Cargo.toml
- [x] 1.3 Move terminal_size to [dev-dependencies] in root Cargo.toml
- [x] 1.4 Check if colored is used directly in src/ — remove from root Cargo.toml if only transitively needed
- [x] 1.5 Run cargo build && cargo test to verify

## 2. Delete dead test code

- [x] 2.1 Delete tests/archive/ directory entirely
- [x] 2.2 Verify cargo test still passes

## 3. Remove dead re-exports

- [x] 3.1 Remove unused DEFAULT_RECURSION_LIMIT re-export from crates/engine/src/eval/mod.rs
- [x] 3.2 Verify cargo build --workspace

## 4. Clippy cleanup

- [x] 4.1 Run cargo clippy --fix --workspace --all-targets
- [x] 4.2 Verify cargo test still passes
