## 1. Remove unused dependencies

- [ ] 1.1 Remove minus = "5.3.1" from root Cargo.toml
- [ ] 1.2 Remove serde from root Cargo.toml
- [ ] 1.3 Move terminal_size to [dev-dependencies] in root Cargo.toml
- [ ] 1.4 Check if colored is used directly in src/ — remove from root Cargo.toml if only transitively needed
- [ ] 1.5 Run cargo build && cargo test to verify

## 2. Delete dead test code

- [ ] 2.1 Delete tests/archive/ directory entirely
- [ ] 2.2 Verify cargo test still passes

## 3. Remove dead re-exports

- [ ] 3.1 Remove unused DEFAULT_RECURSION_LIMIT re-export from crates/engine/src/eval/mod.rs
- [ ] 3.2 Verify cargo build --workspace

## 4. Clippy cleanup

- [ ] 4.1 Run cargo clippy --fix --workspace --all-targets
- [ ] 4.2 Verify cargo test still passes
