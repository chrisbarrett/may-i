## 1. Rename crate on disk

- [ ] 1.1 `git mv crates/layout crates/may-i-output`
- [ ] 1.2 Edit `crates/may-i-output/Cargo.toml`: set `name = "may-i-output"`

## 2. Update workspace manifest

- [ ] 2.1 In root `Cargo.toml`, replace the
  `may-i-layout = { path = "crates/layout" }` dependency line with
  `may-i-output = { path = "crates/may-i-output" }`
- [ ] 2.2 Run `cargo metadata --no-deps --format-version 1 | jq '.packages[].name'`
  and confirm `may-i-output` is present and `may-i-layout` is absent

## 3. Rewrite Rust imports

- [ ] 3.1 `fastmod 'may_i_layout' 'may_i_output' src/ crates/` (the
  Rust extern identifier — underscores, not dashes)
- [ ] 3.2 `rg 'may_i_layout' src/ crates/` returns zero hits
- [ ] 3.3 `rg 'may-i-layout' src/ crates/ Cargo.toml` returns zero
  hits (the dashed Cargo-package form)
- [ ] 3.4 Run `cargo fmt`

## 4. Build, test, validate

- [ ] 4.1 `cargo build` succeeds
- [ ] 4.2 `cargo test` passes (insta snapshots under
  `crates/may-i-output/src/snapshots/` move with the crate; verify
  they still resolve)
- [ ] 4.3 `openspec validate rename-layout-to-output` passes

## 5. Stage and verify

- [ ] 5.1 `git status` shows the rename as a directory move plus the
  import edits, with no stray files
- [ ] 5.2 `Cargo.lock` regenerated and staged
