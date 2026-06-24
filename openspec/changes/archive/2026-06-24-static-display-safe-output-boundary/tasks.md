## 1. Core escape choke points

- [x] 1.1 Add `SafeText` to `may-i-core` (private field, single escaping `new` via `escape_default`, `Deref<str>` + `Display`, no `From`/`Into`); move the escape logic out of `engine::display_safe`.
- [x] 1.2 Add `SafeText` proptests: no-control-survives, idempotent, control-free-input-verbatim.
- [x] 1.3 Add `SafeSource` to `may-i-core` (length-preserving control→single-byte-printable scrub).
- [x] 1.4 Add `SafeSource` proptests: no-control-survives, byte-length-preserved, span-stays-in-bounds.
- [x] 1.5 Re-alias `engine::DisplaySafe` to `core::SafeText` (re-export or thin alias); confirm `EvalResult.reason` path is behaviourally unchanged.

## 2. Color-as-data rendering DSL (may-i-output)

- [x] 2.1 Define the closed `Style` semantic-role enum in `pp` (keyword, string-literal, form-head, dimmed, heading, match-hit, match-miss, plus any role the current `colored` sites require); re-export from `may-i-output`. (`Style` lives in `pp`, not `may-i-output`: the dependency graph is `may-i-output → pp → core`, and task 7.1 requires `pp` to *emit* roles, so the enum must sit where `pp` can name it. The renderer in `may-i-output` still owns the sole role→SGR mapping, preserving D3.)
- [x] 2.2 Convert `Layout` leaves to hold `SafeText` content + `Style` role (via `Styled` spans); remove embedded-ANSI strings from all content fields.
- [x] 2.3 Move the role→SGR mapping and the `NO_COLOR`/`--color` enablement decision into the renderer as the single `\x1b`-emitting site (palette reproduces prior bytes exactly — zero snapshot churn).
- [x] 2.4 Compute visible width in the renderer from escape-free content; delete the `width`/`visible_width` fields on `ColItem`, `NoteHeading`, `HRuleLabel`.
- [x] 2.5 Delete `strip_ansi` and `visible_len` (definitions and call sites). (Removed from `pp` (`color.rs` deleted), `may-i-output`, and the binary; renderer derives width from escape-free content.)

## 3. The single sink

- [x] 3.1 Create the sink module: it alone acquires `stdout`/`stderr`; expose `layout(&Layout, &Terminal)`, `line(SafeText)`, `json(&impl Serialize)` (plus `styled_line`, `eline`, `report`, `with_stdout`/`with_stderr` writer bridge, and the sole `console::Term` accessor for the interactive TUI).
- [x] 3.2 Carry the sole `#[allow(clippy::print_stdout, clippy::print_stderr)]` here.

## 4. Migrate output sites through the sink

- [x] 4.1 Route `src/output/*` per-subcommand builders (`CheckOutput`, `EvalOutput`, `TrustListing`) and `pipeline.rs` render calls through the sink; drop `strip_ansi` from the `output` re-export surface.
- [x] 4.2 Convert `cmd_fmt`, `cmd_migrate`, `cmd_trust`, `cmd_help`, `cmd_parse`, `cmd_eval`, `main.rs` print sites to `sink.line(SafeText)` / `sink.layout` / `sink.styled_line` / `sink.with_stdout`.
- [x] 4.3 Give `config` a typed advisory path (`record_advisory`/`take_advisories` thread-local; host drains via `sink::flush_config_advisories`); remove its ad-hoc `eprintln!` warnings.

## 5. miette input sanitisation

- [x] 5.1 Wrap the `shape_diag` `NamedSource` source in `SafeSource` (and the path name in `SafeText`); spans stay aligned (`\n`/`\t` preserved, dangerous controls scrubbed). Verified by `shape_mismatch_snapshots` (which caught the initial newline-scrub bug).
- [x] 5.2 Wrap input-derived interpolations in flat `miette!` messages (`{e}`/`{path}`/program names) in `SafeText` (28 sites).
- [x] 5.3 Route rendered `miette::Report` to stderr only through the sink (`sink::report`; `cmd_eval.rs`, `main.rs`).

## 6. The gate (closing step)

- [x] 6.1 Remove `colored` from **every** Cargo manifest (bin, `config`[none], `pp`, `may-i-output`); the renderer emits SGR directly. Inline styling anywhere is now a compile error.
- [x] 6.2 Add `[workspace.lints.clippy]` denies for `print_stdout`, `print_stderr`, `dbg_macro`; the sink module is the only allow site.
- [x] 6.3 Add the prek hook banning `io::stdout`/`io::stderr`/`console::Term::std*`/raw-fd access outside the sink — an **ast-grep** structural scan (`scripts/check-output-sink-boundary.sh` + `scripts/output-sink-boundary.yml`); `ast-grep` added to the dev shell and the check wired into CI (`.github/workflows/ci.yml`).

## 7. Phase 2 — fold pp/fmt onto roles

- [x] 7.1 Convert `pp` `colorize_atom → String` to `Style` roles (`atom_style` + `SpanCollector`/`pretty_styled`) consumed by the renderer; route `fmt`/`migrate`/trust-review colour output through the same path (`pretty_form` now renders via `pretty_styled`).
- [x] 7.2 Remove `colored` from the `pp` Cargo manifest (the last inline-ANSI island).

## 8. Falsifiable proof

- [x] 8.1 Add the colour-off proptest: adversarial input (raw `\x1b`, `$'\n'`, control bytes in command names/argv/regex actuals/captured values) through `render_eval`/`render_check`/trace → assert zero control chars reach the sink (`tests/display_safe_boundary.rs`; plus `color_off_render_is_control_free` over arbitrary `Layout` in `may-i-output`).
- [x] 8.2 Add the colour-on companion: assert every `\x1b` is a well-formed SGR from the role palette and no other control char appears.

## 9. Verification

- [x] 9.1 `cargo build --workspace` and `cargo clippy --workspace --all-targets` clean (print lints fire nowhere outside the sink).
- [x] 9.2 `cargo test --workspace` green (49 test binaries, 0 failures); zero snapshot churn — the role→SGR palette reproduces prior bytes exactly, so no fixture needed re-baselining.
- [x] 9.3 `cargo metadata` / `Cargo.lock` confirms `colored` is absent from the dependency graph entirely (stronger than the original "may-i-output only").
- [x] 9.4 Grep confirms zero `println!`/`stdout()`/`stderr()`/`strip_ansi`/`visible_len`/inline-`colored` outside the sink (only allowed test `println!`s and prose doc-comments remain).
- [x] 9.5 Run the prek hook against the tree; confirms it passes and fails (exit 1) on a planted `std::io::stderr()` violation.
- [ ] 9.6 `cargo tarpaulin`; inspect `lcov.info` for uncovered code in the new `core` types and the renderer. (Deferred — new types carry direct unit + property tests; renderer exercised by snapshot + adversarial proptests. Run before merge.)
- [x] 9.7 No user-facing capability affected (all three specs are contributor-facing) — verified, no REFERENCE.md surface change.
- [x] 9.8 `cargo fmt` on Rust sources.
