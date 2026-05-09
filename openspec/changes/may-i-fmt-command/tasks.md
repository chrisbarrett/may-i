## 1. Canonicaliser pass

- [x] 1.1 Implement CST sort for parser body: `(style …)` first, `(flag …)` block alphabetised, `(parameter …)` block alphabetised, `(tail …)` last.
- [x] 1.2 Implement CST sort for `(define-arg-style …)` body: attributes alphabetised by head atom.
- [x] 1.3 Implement CST sort for `(check …)` body: cases alphabetised by command string.
- [x] 1.4 Implement vector sort for `(flag VEC)` and `(parameter VEC …)` name positions; leave other vectors untouched.
- [x] 1.5 Implement canonical-name extraction for vector-named declarations (key on first element after vector sort).
- [x] 1.6 Public entry point `canonicalise_forms(Vec<CstNode>) -> Vec<CstNode>` (or equivalent), callable from `cmd_fmt` and from tests.
- [x] 1.7 Property test: idempotence — `canonicalise(canonicalise(x)) ≡ canonicalise(x)`.
- [x] 1.8 Property test: equivalent configs differing only in declaration order produce identical canonical form (closes dsl-coherence §15.5).
- [x] 1.9 Unit test: vector-name sort key derives correctly when input vector is unsorted.
- [x] 1.10 Unit test: separator vector and other sequence-typed vectors are NOT sorted.

## 2. Trivia attachment under sort

- [x] 2.1 Verify trivia model: leading trivia moves with form when sorted (no special handling needed if data model is correct).
- [x] 2.2 Snapshot test: comment between forms travels with the next form on sort.
- [x] 2.3 Snapshot test: trailing comment on last child of a list travels with that child when sorted.
- [x] 2.4 Snapshot test: section-header comment behaviour documented in test fixture.

## 3. `fmt` subcommand — file mode

- [x] 3.1 Add `Fmt` variant to `Command` enum in `src/main.rs` with `files: Vec<String>` and `check: bool`.
- [x] 3.2 Create `src/cmd_fmt.rs`; mirror `cmd_migrate.rs` structure.
- [x] 3.3 In file mode: parse → canonicalise → pretty_serialize → `std::fs::write`.
- [x] 3.4 Detect read-only files; emit stderr warning, skip, continue with remaining files.
- [x] 3.5 Multi-file processing: collect per-file results; final exit code is the highest severity (`2 > 1 > 0`).
- [x] 3.6 Integration test: single file formatted in place rewrites file with canonical output.
- [x] 3.7 Integration test: multi-file run with one parse error processes other files and exits `2`.
- [x] 3.8 Integration test: read-only file emits warning, skipped, other files processed.

## 4. `fmt` subcommand — load-graph walk

- [x] 4.1 When no positional args and stdin is a terminal, invoke `walk_load_graph(primary_config)`.
- [x] 4.2 Format each file in the graph in place; reuse the file-mode pipeline from §3.
- [x] 4.3 Integration test: bare invocation formats primary config + transitively-loaded files.

## 5. `fmt` subcommand — stdin filter mode

- [x] 5.1 Detect piped stdin (no positional args, `!stdin.is_terminal()`).
- [x] 5.2 Detect explicit `-` argument (sole positional).
- [x] 5.3 Reject mixed `-` + file args at argv parse with stderr error and exit `2`.
- [x] 5.4 In stdin mode: read stdin → parse → canonicalise → pretty_serialize → stdout.
- [x] 5.5 Preserve trailing newline iff input had one.
- [x] 5.6 Integration test: piped stdin produces canonical stdout, no file modified.
- [x] 5.7 Integration test: explicit `-` reads stdin.
- [x] 5.8 Integration test: mixed mode rejected.

## 6. `fmt` subcommand — `--check` flag

- [x] 6.1 Parse `--check` boolean flag on `Fmt`.
- [x] 6.2 In `--check` mode: skip writes; compare `canonical_output == source` per input.
- [x] 6.3 Final exit code: `0` if all match, `1` if any would change, `2` if any error.
- [x] 6.4 Suppress stdout in `--check` mode (file mode and stdin mode).
- [x] 6.5 Integration test: clean files exit `0`.
- [x] 6.6 Integration test: would-change exits `1`.
- [x] 6.7 Integration test: parse error exits `2`.
- [x] 6.8 Integration test: stdin in `--check` mode exits `1` if input would change.
- [x] 6.9 Integration test: multi-file `--check` returns highest severity exit code.

## 7. Legacy syntax handling

- [x] 7.1 After canonicalise + render, attempt strict-canonical re-parse to detect legacy forms.
- [x] 7.2 If legacy detected: emit stderr warning naming source and suggesting `may-i migrate`.
- [x] 7.3 Format-and-write proceeds unchanged (no rewrites).
- [x] 7.4 In `--check` mode: legacy syntax with non-canonical whitespace exits `1` with warning; legacy syntax already in canonical whitespace exits `0` with warning.
- [x] 7.5 Integration test: file with `(effect :allow)` formatted in place with stderr warning, exit `0`.
- [x] 7.6 Integration test: stdin with legacy syntax produces stdout output and stderr warning citing `<stdin>`.
- [x] 7.7 Integration test: `--check` against legacy file with non-canonical whitespace exits `1` with warning.

## 8. Deferred dsl-coherence test backfill

- [x] 8.1 Property test: form-list parser body roundtrips through parse + canonicalise (closes dsl-coherence §1.4).
- [x] 8.2 Property test: decision verbs roundtrip through canonical form (closes dsl-coherence §4.4).
- [x] 8.3 Update `openspec/changes/dsl-coherence/tasks.md`: mark §1.4, §4.4, §15.1, §15.2, §15.3, §15.5 as complete with cross-reference to this change.

## 9. Docs and examples

- [x] 9.1 Re-format `examples/*.lisp` under new canonical sort; commit alongside.
- [x] 9.2 Add `may-i fmt` section to `REFERENCE.md` covering file mode, stdin, `--check`, legacy warning.
- [x] 9.3 Update `CONTEXT.md` if new domain vocabulary introduced (likely not — "canonical form" already exists).
- [x] 9.4 Update `CLAUDE.md` to mention `may-i fmt` as the analog to `cargo fmt` for `examples/`.

## 10. Release

- [x] 10.1 Bump `Cargo.toml` version per CLAUDE.md release process. [skipped — 0.3.0 is still unreleased; this change merges into the existing 0.3.0]
- [x] 10.2 `cargo fmt`; ensure clean.
- [x] 10.3 `cargo tarpaulin`; inspect coverage; fill gaps with proptest or surgical unit tests. [workspace 85.44% (above 85% threshold); `crates/config/src/canonicalise.rs` 133/134 = 99.25%]
- [ ] 10.4 Cut release tag matching new Cargo version. [user-side step]
