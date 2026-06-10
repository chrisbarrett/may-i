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
- No user-facing behaviour change; all existing tests stay green.

**Non-Goals:**

- Folding `evaluate_authorise_tokens` into the core — it is tokeniser-then-
  single-eval, not a decompose→loop pipeline; its `len == 1` arm already
  delegates to the shared string path.
- Any DSL, config, trust-hash, or migration change.
- Reworking the `EvalFold` trait or segment semantics (segments stay
  EvalUnit-granular per `engine-segment-decisions`).

## Decisions

### D1 — One `eval_units` core; segments are an injected optional sink

Extract a private core in `command.rs`:

```rust
fn eval_units<F: EvalFold>(
    units: &[EvalUnit],
    diagnostics: &[ParseDiagnostic],
    input: &str,
    config: &Config,
    facts: &ContextFacts,
    fold: &mut F,
    depth: usize,
    via: Option<&str>,
    segments: Option<SegmentSink>,
) -> Result<EvalResult, EvalError>
```

It owns the unit loop, the strictest-wins lattice, embedded-reason annotation,
and the parse-error floor (aggregate always; per-segment only when `segments`
is `Some`). Embedded recursion re-enters `eval_units` with `via = None` and the
sink re-based to the substitution offset. `SegmentSink` carries the byte-offset
base and accumulates `SegmentDecision`s; `None` means "do not collect" (the
authorise path).

- `evaluate_command_inner` → `eval_units(.., via = None, segments = Some(sink @ outer_offset))`.
- `evaluate_authorised_string` → `eval_units(.., via, segments = None)`, keeping
  its `:via` push (now expressed via the `via` parameter, performed inside the
  core — matching `may-i-recurse-compound-inner` Decision 2).

*Why not extract only a shared aggregate-and-floor helper:* that leaves the
decompose→loop skeleton — the part that forced two-call-site edits in
`harden-shell-parse-fidelity` — duplicated.

### D2 — Uniform depth threading

The core always evaluates a `SimpleCommand` unit via
`evaluate_at_depth(.., depth)`. Top-level enters at `depth = 0`, so its units
are evaluated identically to today's `evaluate_with_fold` (which is
`evaluate_at_depth(.., 0)`). The difference appears only for *deeply embedded*
substitutions, where the rule-eval depth now matches the recursion depth
instead of resetting to 0 — feeding the recursion-limit guard and any
parser-level `(parameter (authorise))` recursion. This is the single
behavioural reconciliation point and is fenced by the existing
`recursion_depth_limit` test and the line-continuation span proptest.

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
