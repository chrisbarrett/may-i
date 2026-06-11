## Context

`may-i` evaluates a bash command by parsing it (`crates/shell-parser`),
decomposing the AST into evaluation units, and running rules over each
(`crates/engine/src/eval`). Three friction points, all surfaced by the
`harden-shell-parse-fidelity` change:

- **Duplicated pipeline.** `evaluate_command_inner` (`command.rs:97`) and
  `evaluate_authorised_string` (`command.rs:240`) both implement *parse →
  decompose → loop units → aggregate strictest (`:allow < :ask < :deny`) →
  floor at `:ask` on an Error-severity diagnostic*. They differ only in: (a)
  per-unit rule-eval depth — top-level uses `evaluate_with_fold` (depth 0),
  authorise uses `evaluate_at_depth(depth)`; (b) `:via` injection; (c)
  segment/offset tracking + embedded-reason annotation. The
  `may-i-recurse-compound-inner` design already chose one shared evaluator and
  rejected duplication; `engine-segment-decisions` then scoped segment
  *population* to `evaluate_command_inner` ("opt-in by virtue of going through
  `evaluate_command_inner`"), which is the only reason the second copy
  persists.

- **Leaked span contract.** `decompose` calls `Word::extract_embedded_with_spans`
  to get substitution bodies, then correlates each body span against the flat
  `ParseDiagnostic` list to decide whether the substitution is unterminated
  (`substitution_is_unterminated`, `decompose.rs:162`). The required knowledge
  — an `UnterminatedCommandSubstitution`/`UnterminatedBacktick` diagnostic span
  *covers* the body span (diagnostic starts at the sigil, body starts after it,
  shared end) — is documented only in the lexer and the engine helper, never at
  the parser's interface. The parser already knows termination at lex time
  (`word_parts.rs:282`, `:57`).

- **Duplicated tokeniser.** `entry::parser_positional_args` (`-> Vec<&str>`,
  `entry.rs:250`) and `bindings::positional_args_owned` (`-> Vec<String>`,
  `bindings.rs:538`) are identical except `.as_str()` vs `.clone()`;
  `first_positional_index` is copied verbatim into both; `bindings::split_after_*`
  re-implements `entry::split_outer_tail`. The owned copy exists only because
  `parse_argv` stores results in the `Bindings` map, which cannot hold borrows
  of the transient `args`.

## Goals / Non-Goals

**Goals:**

- One command-evaluation core; the two entry points become thin adapters.
- Substitution termination reported by the parser; the engine stops doing
  byte-offset diagnostic correlation.
- One parser-aware positional/tail tokenisation implementation.
- Groups 1 (parser termination) and 2 (tokeniser) are behaviour-neutral. The
  pipeline collapse (group 3) is *unify-and-improve*: the authorise recursion
  path gains the richness the top-level path already had (embedded-reason
  annotation, `fold.embedded_command`/`fold.default_ask` events, populated
  `parse_diagnostics`, and uniform depth threading). Decisions are unchanged;
  trace/audit output for an `(authorise …)` carrier over a substitution or
  dynamic inner becomes richer and any affected snapshot/audit tests are
  re-blessed.

**Non-Goals:**

- Folding `evaluate_authorise_tokens` into the core — it is tokeniser-then-
  single-eval, not a decompose→loop pipeline; its `len == 1` arm already
  delegates to the shared string path.
- Any DSL, config, trust-hash, or migration change.
- Reworking the `EvalFold` trait or segment semantics (segments stay
  EvalUnit-granular per `engine-segment-decisions`).

## Decisions

### D1 — One `eval_units` core; segments are an injected optional sink

Extract a private core in `command.rs` that parses and decomposes `input`
itself (so embedded recursion can re-enter it directly):

```rust
fn eval_units<F: EvalFold>(
    input: &str,
    config: &Config,
    facts: &ContextFacts,
    fold: &mut F,
    depth: usize,
    via: Option<&str>,
    segments: Option<usize>,
) -> Result<EvalResult, EvalError>
```

It owns parse + decompose + the unit loop, the strictest-wins lattice,
embedded-reason annotation, fold events, and the parse-error floor (aggregate
always; per-segment only when collecting). Embedded recursion re-enters
`eval_units` with `via = None` and the offset re-based to the substitution.
The segment sink is `segments: Option<usize>` — `Some(outer_offset)` collects
`SegmentDecision`s in outermost coordinates (top-level, for display), `None`
skips collection (the authorise path, which has no display surface). A dedicated
`SegmentSink` struct proved unnecessary: the byte-offset base is the only state
to thread, and the accumulator lives as a local `Vec` in the core.

- `evaluate_command_inner` → `eval_units(.., via = None, segments = Some(sink @ outer_offset))`.
- `evaluate_authorised_string` → `eval_units(.., via, segments = None)`, keeping
  its `:via` push (now expressed via the `via` parameter, performed inside the
  core — matching `may-i-recurse-compound-inner` Decision 2).

*Why not extract only a shared aggregate-and-floor helper:* that leaves the
decompose→loop skeleton — the part that forced two-call-site edits in
`harden-shell-parse-fidelity` — duplicated.

### D2 — Uniform depth threading and uniform richness (unify-and-improve)

The core always evaluates a `SimpleCommand` unit via
`evaluate_at_depth(.., depth)`, always annotates embedded reasons, always emits
`fold.embedded_command`/`fold.default_ask` events, and always populates
`parse_diagnostics`. Top-level enters at `depth = 0`; the authorise path threads
its `depth`. Versus today this changes the authorise path in four ways — it
gains annotation, fold events, populated diagnostics, and (for deeply embedded
substitutions) rule-eval depth that matches recursion depth instead of resetting
to 0. **Decisions are unchanged**; only trace/audit richness and niche
substitution reasons change. The rich-vs-lean split that previously justified
two functions is dissolved: the lean authorise path was an omission, not a
contract. Fenced by `recursion_depth_limit`, `prop_authorised_matches_top_level`
(decisions still agree), and the line-continuation span proptest; affected
audit/trace snapshots are re-blessed.

### D3 — Parser reports `terminated`; engine reads the flag

`Word`'s embedded extraction returns, per substitution, a record carrying
`source`, `span`, `form`, and a new `terminated: bool`. The lexer sets
`terminated = false` exactly where it pushes the `UnterminatedCommandSubstitution`
/ `UnterminatedBacktick` / unterminated-process-substitution diagnostic. The
shape:

```rust
pub struct Embedded<'a> {
    pub source: &'a str,
    pub span: Span,
    pub form: SubstitutionForm,
    pub terminated: bool,
}
```

`decompose` skips a unit when `!terminated`; `substitution_is_unterminated` and
the diagnostic-span correlation are deleted. The AST node itself is unchanged
(spec D3 of `harden-shell-parse-fidelity`: AST output stays byte-identical),
and the diagnostics list is unchanged — only an extra bool rides along the
extraction result.

*Why not drop the substitution from extraction when unterminated:* other
consumers and the AST-stability requirement depend on the node existing;
flagging keeps the AST stable while moving the recurse/skip decision to where
the knowledge lives.

### D4 — One borrowed tokeniser; clone at the call site

Keep `entry::parser_positional_args<'a>(..) -> Vec<&'a str>` and
`entry::first_positional_index(..) -> usize` as the single source. `parse_argv`
adapts ownership inline:

```rust
let positionals: Vec<String> =
    parser_positional_args(args, parser).iter().map(|s| s.to_string()).collect();
```

Delete `bindings::positional_args_owned`, `bindings::first_positional_index`,
`bindings::split_after_flags`, and `bindings::split_after_token`; route the
split through `entry::split_outer_tail`. Make the kept functions `pub(crate)` if
not already.

## Risks / Trade-offs

- **Depth-threading change (D2).** The only semantic shift. Mitigation: assert
  `evaluate_command` and `evaluate_authorised_string` agree on decisions for
  arbitrary input (the existing `prop_authorised_matches_top_level` becomes
  near-tautological), and keep `recursion_depth_limit` +
  `prop_line_continuation_preserves_span_bounds` green.
- **`SegmentSink` offset bookkeeping.** Mis-rebasing the sink on embedded
  recursion would shift segment ranges. Mitigation: the existing
  segment-decision unit tests and `prop_top_level_segments_disjoint` /
  `unclosed_process_substitution_segments_nest` pin the offsets.
- **Parser API ripple (D3).** Renaming/extending `extract_embedded_with_spans`
  touches its current callers. Mitigation: keep a single extraction method;
  update `decompose` and any `wordpart-source-span` consumers in the same
  change; the engine's `substitution` tests fence behaviour.
- **Low blast radius for D4** — pure deletion of a duplicate; behaviour is
  identical by construction and `prop_tokens_match_string_when_metafree`
  guards it.
