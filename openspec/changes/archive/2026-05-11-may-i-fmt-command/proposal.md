## Why

Three multi-declaration bodies in the DSL — parser body, `define-arg-style`, and `check` — have set-like semantics: the order users type their declarations in is irrelevant to behaviour. As configs grow and edits accumulate, these bodies drift out of any visual order, making diffs noisy and review harder. dsl-coherence §15 specified a canonical order but deferred implementation, because the canonicaliser only matters in the presence of a formatter — and there is no formatter.

Independently: `may-i migrate` already reformats whitespace as a side effect of pretty-printing migrated forms, conflating semantic rewrite (legacy → canonical) with whitespace normalisation. Editors hooking the tool need a no-rewrite formatter; CI needs a `--check` mode. Without one, every contributor's editor reformats by feel and PR diffs accumulate cosmetic churn.

`may-i fmt` is the missing piece. It also unblocks the deferred dsl-coherence canonicaliser tests (§1.4, §4.4, §15.1–§15.3, §15.5), which were waiting for an in-tree consumer of the canonical form.

## What Changes

- **NEW** `may-i fmt` subcommand. Format-in-place by default. Walks the `(load …)` graph from the primary config when invoked with no args. Accepts multiple file paths. Reads stdin → writes stdout when stdin is piped or `-` is the sole argument.
- **NEW** `--check` flag: exit-code-only signal. `0` clean, `1` would-change, `2` parse/IO error. No diff output. No writes. Stdout stays empty for editor pre-commit hooks.
- **NEW** Canonical body-form ordering pass over the CST before pretty-printing:
  - Parser body: `(style …)` first, `(flag …)` declarations alphabetised, `(parameter …)` declarations alphabetised, `(tail …)` last.
  - `(define-arg-style …)` body: attribute forms alphabetised by name.
  - `(check …)` body: cases alphabetised by command string.
  - Rule body order preserved (semantic — short-circuit evaluation).
- **NEW** Vector canonicalisation in `(flag VEC)` and `(parameter VEC …)` name positions. `(flag ["r" "0"])` → `(flag ["0" "r"])`. Vectors elsewhere (separators, prefixes) are order-significant and untouched.
- **NEW** Legacy-syntax handling: `fmt` formats the CST as-is (whitespace canonicalised, legacy forms preserved) and emits a stderr warning naming the source and suggesting `may-i migrate`. Same behaviour in file and stdin modes. No silent rewrites — `migrate` remains the explicit semantic-rewrite path.
- **MODIFIED** Pretty-printing capability gains the canonical-ordering requirement. Comments travel with their owning form under sort (CST trivia model already attaches comments as leading trivia on the next form, so this is a structural property — documented and snapshot-tested).
- **CLOSES** dsl-coherence deferred tasks: §15.1, §15.2, §15.3, §15.5, §1.4, §4.4.

## Capabilities

### New Capabilities

- **`fmt-command`** — the `may-i fmt` subcommand surface, including file mode, stdin filter mode, `--check`, and legacy-syntax warning.

### Modified Capabilities

- **`pretty-printing`** — adds canonical body-form ordering as a pre-render pass; specifies sort key derivation, vector canonicalisation, and trivia attachment under sort.

## Impact

- **`src/main.rs`** — add `Fmt { files, check, … }` subcommand variant; dispatch.
- **`src/cmd_fmt.rs`** — new file; mirrors `cmd_migrate.rs` structure (parse → canonicalise → pretty-print → write or compare).
- **`crates/sexpr/src/cst.rs`** or **`crates/config/src/canonicalise.rs`** — CST sort pass. Open: which crate owns it. Probably `config` since the sort discipline is DSL-aware (knows about `parser`/`define-arg-style`/`check` head atoms).
- **`crates/pp/`** — no changes. Existing `pretty_serialize` stays whitespace-only.
- **`tests/fmt_*.rs`** — new integration suite covering file mode, stdin, `--check`, legacy warning.
- **`examples/*.lisp`** — re-formatted under new canonical order; committed alongside.
- **`REFERENCE.md`** — new `may-i fmt` reference section.
- **No evaluation behaviour change.** Trust hashes unaffected — parser bodies and checks aren't trust-hashed; rule body order is preserved.
- **No breaking change to existing commands.** `migrate` continues as-is. `fmt` is purely additive.
