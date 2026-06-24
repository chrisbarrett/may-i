## 1. Core escape choke points

- [ ] 1.1 Add `SafeText` to `may-i-core` (private field, single escaping `new` via `escape_default`, `Deref<str>` + `Display`, no `From`/`Into`); move the escape logic out of `engine::display_safe`.
- [ ] 1.2 Add `SafeText` proptests: no-control-survives, idempotent, control-free-input-verbatim.
- [ ] 1.3 Add `SafeSource` to `may-i-core` (length-preserving control→single-byte-printable scrub).
- [ ] 1.4 Add `SafeSource` proptests: no-control-survives, byte-length-preserved, span-stays-in-bounds.
- [ ] 1.5 Re-alias `engine::DisplaySafe` to `core::SafeText` (re-export or thin alias); confirm `EvalResult.reason` path is behaviourally unchanged.

## 2. Color-as-data rendering DSL (may-i-output)

- [ ] 2.1 Define the closed `Style` semantic-role enum (keyword, string-literal, form-head, dimmed, heading, match-hit, match-miss, plus any role the current `colored` sites require).
- [ ] 2.2 Convert `Layout` leaves to hold `SafeText` content + `Style` role; remove embedded-ANSI strings from all content fields.
- [ ] 2.3 Move the role→SGR mapping and the `NO_COLOR`/`--color` enablement decision into the renderer as the single `\x1b`-emitting site.
- [ ] 2.4 Compute visible width in the renderer from escape-free content; delete the `width`/`visible_width` fields on `ColItem`, `NoteHeading`, `HRuleLabel`.
- [ ] 2.5 Delete `strip_ansi` and `visible_len` (definitions and call sites).

## 3. The single sink

- [ ] 3.1 Create the sink module: it alone acquires `stdout`/`stderr`; expose `layout(&Layout, &Terminal)`, `line(SafeText)`, `json(&impl Serialize)`.
- [ ] 3.2 Carry the sole `#[allow(clippy::print_stdout, clippy::print_stderr)]` here (added in group 6).

## 4. Migrate output sites through the sink

- [ ] 4.1 Route `src/output/*` per-subcommand builders (`CheckOutput`, `EvalOutput`, `TrustListing`) and `pipeline.rs` render calls through the sink; drop `strip_ansi` from the `output` re-export surface.
- [ ] 4.2 Convert `cmd_fmt`, `cmd_migrate`, `cmd_trust`, `cmd_help`, `cmd_parse`, `cmd_eval`, `main.rs` print sites to `sink.line(SafeText)` / `sink.layout` / `sink.json`.
- [ ] 4.3 Give `config` (`io.rs`, `config.rs`, `style.rs`, `parser_form.rs`) a typed advisory path to the sink; remove its ad-hoc `eprintln!` warnings.

## 5. miette input sanitisation

- [ ] 5.1 Wrap the `shape_diag` `NamedSource` source in `SafeSource`; confirm span underlines stay aligned.
- [ ] 5.2 Wrap input-derived interpolations in flat `miette!` messages (`{e}`/`{path}`/program names) in `SafeText`.
- [ ] 5.3 Route rendered `miette::Report` to stderr only through the sink (replace `cmd_eval.rs:33`, `main.rs:160`).

## 6. The gate (closing step)

- [ ] 6.1 Remove `colored` from the binary and `config` Cargo manifests; replace remaining inline styling with `Style` roles.
- [ ] 6.2 Add `[workspace.lints.clippy]` denies for `print_stdout`, `print_stderr`, `dbg_macro`; verify the sink is the only allow site.
- [ ] 6.3 Add the prek hook banning `io::stdout`/`io::stderr`/`console::Term::std*`/raw-fd access outside the sink module.

## 7. Phase 2 — fold pp/fmt onto roles

- [ ] 7.1 Convert `pp` `colorize_atom → String` to `Style` roles consumed by the renderer; route `fmt`/`migrate` colour output through the same path.
- [ ] 7.2 Remove `colored` from the `pp` Cargo manifest (the last inline-ANSI island).

## 8. Falsifiable proof

- [ ] 8.1 Add the colour-off proptest: adversarial input (raw `\x1b`, `$'\n'`, control bytes in command names/argv/regex actuals/captured values/`(load)`ed config) through `render_eval`/`render_check`/trace/advisory → assert zero control chars reach the sink.
- [ ] 8.2 Add the colour-on companion: assert every `\x1b` is a well-formed SGR from the role palette and no other control char appears.

## 9. Verification

- [ ] 9.1 `cargo build --workspace` and `cargo clippy --workspace` clean (print lints fire nowhere outside the sink).
- [ ] 9.2 `cargo test --workspace` green; re-baseline only snapshots whose fixtures contain control characters (benign fixtures must be byte-unchanged).
- [ ] 9.3 `cargo metadata` confirms `colored` is a dependency of `may-i-output` only.
- [ ] 9.4 Grep confirms zero `println!`/`stdout()`/`stderr()`/`strip_ansi`/`visible_len`/inline-`colored` outside the sink and renderer.
- [ ] 9.5 Run the prek hook against the tree; confirm it passes and fails on a planted violation.
- [ ] 9.6 `cargo tarpaulin`; inspect `lcov.info` for uncovered code in the new `core` types and the renderer.
- [ ] 9.7 No user-facing capability affected (all three specs are contributor-facing) — record "verified, no REFERENCE.md surface change".
- [ ] 9.8 `cargo fmt` on Rust sources before staging.
