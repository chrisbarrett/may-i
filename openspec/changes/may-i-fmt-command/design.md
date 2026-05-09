## Context

The pretty-printer is in shape after `pretty-printer-indentation`: indent contract is written, cascade discipline is fixed, snapshot suite is comprehensive. `migrate` already chains `parse_cst → migrate_forms → pretty_serialize → write`, so the formatter primitives all exist. dsl-coherence §15 wrote the canonical-order rules but deferred implementation pending a consumer.

This change is that consumer. It adds the `fmt` subcommand and the canonical-order pass that §15 specified.

## Goals / Non-Goals

**Goals:**

- One canonical formatter usable from CLI, editors, and CI.
- Idempotent canonical form: running `fmt` on already-formatted output produces byte-identical output.
- `--check` exit code suitable for CI gates and editor pre-commit hooks.
- Stdin → stdout filter mode for editor "format buffer" features.
- No semantic rewrites — `fmt` and `migrate` remain disjoint commands with disjoint capabilities.
- Closes dsl-coherence's deferred §15 work and the canonicaliser-dependent property tests (§1.4, §4.4, §15.5).

**Non-Goals:**

- Diff output in `--check` mode. `migrate --dry-run` already emits diffs; users wanting visual review run that.
- `--width N` flag. `detect_column_width` is the existing heuristic; reuse it. Add `--width` only if a user asks.
- Format-region (partial-buffer formatting). Editors integrate via stdin filter; whole-buffer is the contract.
- Sorting rule bodies. Rule order is semantic.

## Decisions

### Walk `(load …)` graph by default

Bare `may-i fmt` (no args, tty stdin) walks the load graph from the primary config (or `--config` override) and formats every reachable file in place. Mirrors `migrate`'s default. Read-only files are skipped with a stderr warning.

**Alternative considered:** require explicit path. Rejected — misses the multi-file workflow already established for `migrate`; users with split configs would have to enumerate each file.

### `--check` is exit-code-only

`--check` writes nothing — neither to disk nor to stdout — and signals state via exit code:

- `0` — every input is canonically formatted
- `1` — at least one input would change
- `2` — parse error, IO error, or other blocking failure

Stderr remains free for warnings and error pointers.

**Alternative considered:** rustfmt-style diff to stdout in `--check`. Rejected — overlaps with `migrate --dry-run` for visual review; the primary `--check` consumer is automated tooling that wants a clean exit signal.

### Stdin via `-` or implicit pipe

Editor integrations need a filter mode: input on stdin, formatted output on stdout. Two ergonomic spellings:

- `cat foo.lisp | may-i fmt` — implicit, when no positional args and stdin is a non-terminal source
- `may-i fmt -` — explicit; useful in scripts where `cat | may-i fmt` is awkward

Mixed mode (`may-i fmt - other.lisp`) is rejected at argv parse — single mode per invocation.

**Alternative considered:** stdin-only via explicit `-`, no implicit pipe detection. Rejected — implicit detection matches `may-i eval`'s existing behaviour (see `main.rs:115–130`); consistency wins.

### Legacy syntax: format + warn, never rewrite

When `fmt` parses input that contains forms the strict canonical loader rejects (e.g. `(effect :allow)`, `(may-i *)`, plist-form `define-arg-style`), it:

1. Pretty-prints the CST as-is — whitespace canonicalised, legacy forms preserved.
2. Emits a stderr warning naming the file (or `<stdin>`) and suggesting `may-i migrate`.
3. Returns the same exit code it would for canonical input.

The pretty-printer operates at CST level and is structurally agnostic to canonical-vs-legacy. The warning-without-rewrite rule keeps `fmt` and `migrate` disjoint: each command does one thing.

**Alternative considered:** silent migrate-and-format. Rejected — re-introduces "what does this command actually do" ambiguity; trust hash rehash and Class B warnings belong to `migrate`, not `fmt`.

**Alternative considered:** error and exit on legacy syntax. Rejected — editors and CI need formatted output even from in-progress legacy files; the warning is the migration nudge.

### Canonical sort: head-anchored, set-semantics for name vectors

**Parser body order:**

```
(parser PROG
  (style …)              ← always first
  (flag …)               ← alphabetised by canonical name
  (flag …)
  …
  (parameter …)          ← alphabetised by canonical name
  (parameter …)
  …
  (tail …))              ← always last
```

**`define-arg-style` body order:** attribute forms alphabetised by name (`(combined-shorts …)`, `(first-token-bundle …)`, `(long-prefix …)`, `(overrides …)`, `(pun …)`, `(separators …)`, `(short-prefix …)`).

**`check` body order:** cases alphabetised by command string.

**Rule body order:** preserved. Rule body forms are evaluated short-circuit; order is semantic.

**Canonical name extraction:**

| Form                              | Sort key                                    |
| --------------------------------- | ------------------------------------------- |
| `(flag "X")`                      | `"X"`                                       |
| `(parameter "X" …)`               | `"X"`                                       |
| `(flag [STR…])`                   | first element of vector after vector sort   |
| `(parameter [STR…] …)`            | first element of vector after vector sort   |

**Vector canonicalisation:** when a vector appears as the name set of `(flag …)` or `(parameter …)`, vector contents are sorted lexicographically. `(flag ["r" "0"])` → `(flag ["0" "r"])`. Vectors elsewhere (`(separators "=" " ")`, etc.) are order-significant and **untouched** — the tokeniser may use separator order for priority.

**Alternative considered:** sort all vectors. Rejected — separator vectors and prefix vectors are positional. Spec must distinguish set-vectors (flag/parameter names) from sequence-vectors (everything else).

**Alternative considered:** interleave flag and parameter declarations alphabetically. Rejected — dsl-coherence §15 specified flag-block-then-parameter-block; preserve that.

### Sort moves comments with their form

CST trivia model attaches comments and whitespace as `leading` trivia on the next form (parser code: `crates/sexpr/src/cst.rs:454–504`). Sort relocates the form; its leading trivia rides along. The data model makes this automatic — no special handling needed.

**Implication for users:** a "section header" comment placed between two forms migrates with whichever form follows it. Documented in REFERENCE.md and pinned via snapshot test.

**Edge case:** a trailing comment at the end of a list (no following sibling) attaches as `trailing` of the last child. Sort moves the last child elsewhere, so the trailing comment goes with it. Snapshot-tested; rare in practice.

**Alternative considered:** detect blank-line "fences" between forms and refuse to sort across them. Rejected — heuristic is fuzzy; ship the simple structural rule and revisit if real-world complaints emerge.

### Trust hash unaffected

Per dsl-coherence §15 deferral notes: parser bodies and checks are not trust-hashed; only rules are. Rule body order is preserved. So `fmt` cannot change any trust hash. No rehash logic, no migration story for the trust store.

If a future change starts hashing parser bodies or checks, the canonical form here becomes the input to that hash — by construction, formatted-then-hashed produces a deterministic key.

### Idempotence

Running `fmt` on output of `fmt` produces byte-identical output. Property-tested. Failure modes:

- Sort instability (e.g., non-total ordering on duplicate keys) → property test will catch.
- Vector sort interaction with sort key derivation (sort key depends on already-sorted vector) → unit-tested.
- Pretty-printer non-idempotence on canonical input → existing `pretty_print_is_idempotent` proptest in `crates/pp/src/tests/properties.rs` covers this region.

### `migrate` may opt into the canonicaliser

`migrate` currently calls `pretty_serialize` directly. After this change, `migrate` could prepend the canonicaliser pass — producing fully-canonical output (sort + whitespace + form rewrites in one shot). This is a follow-up consideration, not a blocker; out of scope for this change.

## Risks / Trade-offs

**[Hand-tuned ordering loss]** Users who deliberately ordered flags by importance see them re-sorted. → Trade-off: deterministic canonical form is the explicit promise of `fmt`. Users who don't want that don't run `fmt`. The `--check` exit code lets CI catch unsanctioned reformats.

**[Comment relocation surprises]** Section-header comments move with the next form. → Documented. Rare in real configs (verified against `examples/`). If reports surface, revisit with a fence heuristic.

**[Examples diff churn]** Re-formatting `examples/*.lisp` produces a one-shot diff. → One-shot is cheap; commit alongside the change.

**[Diff with `migrate`'s output]** Configs that have been through `migrate` may not match `fmt`'s output if `migrate` doesn't run the canonicaliser. → Document: post-migrate, run `fmt` to get fully-canonical form. Or in a follow-up, have `migrate` invoke the canonicaliser too.

**[Stdin error path obscurity]** Errors against stdin can't reference a file path. → Use `<stdin>` consistently in error messages. Editor integrations expect this.

## Migration Plan

1. Land canonicaliser pass over CST (parser/define-arg-style/check sort + vector canonicalisation).
2. Wire canonicaliser into a public entry point (`canonicalise_forms` or similar) callable from `cmd_fmt`.
3. Add `cmd_fmt.rs` mirroring `cmd_migrate.rs` structure: file walk, stdin detection, `--check` branch, write or compare.
4. Add `Fmt` subcommand to `main.rs`.
5. Re-format `examples/*.lisp` under new canonical sort.
6. Update REFERENCE.md and CONTEXT.md (mention `may-i fmt` analog to `cargo fmt`).
7. Backfill deferred dsl-coherence property tests (§1.4, §4.4, §15.5) using the canonicaliser as the round-trip target. Update dsl-coherence/tasks.md to mark these as completed-in-this-change.
8. Bump `Cargo.toml`, run `cargo tarpaulin`, cut release.

## Open Questions

- **Crate ownership of the canonicaliser pass.** `crates/sexpr/` is DSL-agnostic; the sort discipline is DSL-aware (knows the head atoms `parser`/`define-arg-style`/`check` and their body shapes). Belongs in `crates/config/`. Confirm during implementation.
- **`--write` flag for stdin mode?** No. Stdin mode is filter-only; if a user wants to write back to a file from stdin, they redirect (`may-i fmt < foo.lisp > foo.lisp.tmp && mv …`).
- **Atomicity of in-place writes.** `migrate` uses direct `std::fs::write`. Same here. Editor integrations don't depend on temp-file-rename semantics. Revisit if a real concurrent-write scenario appears.
- **Should `migrate` invoke the canonicaliser?** Out of scope here, but worth a follow-up: post-migrate output that isn't canonical means users running `fmt` after `migrate` see a non-trivial diff.
