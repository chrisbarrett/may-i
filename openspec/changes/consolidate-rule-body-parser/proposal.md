## Why

The config crate's rule-body parsing is split across five modules —
`pattern.rs` (1234 LOC), `predicate.rs` (659), `effect.rs` (711),
`parser_form.rs` (800), `rule.rs` (340) — each `pub`-exporting its own
entry point: `parse_arg_pattern`, `parse_positional_arg`,
`parse_predicate`, `parse_effect`, `parse_parser_form`. The split mirrors
the **contributor-only** `ArgPattern` / `Expr<T>` / `Predicate` / `Effect`
divide that CONTEXT.md explicitly warns against surfacing:

> The internal representation is richer than the surface syntax — argv-shaped
> matchers are an `ArgPattern` enum, single-token matchers are `Expr<T>`,
> and tests in conditional position go through a `Predicate` enum. Resist
> the urge to surface this split in user docs, error messages, or DSL forms;
> users see one kind of thing.

The split is currently leaking past the config crate's `pub` surface even
though, in practice, no caller outside the crate uses any of the
sub-parsers — every external consumer enters through `parse_config` or
imports the core AST types (`may_i_core::ast::{Effect, Predicate}`,
`may_i_core::pattern::ArgPattern`) directly. The four `pub` sub-parsers
are dead public surface that invites future drift.

Tightening the seam removes the invitation: one public entry point for
rule bodies (`parse_rule_body`), the sub-parsers become `pub(crate)`
implementation detail, and renaming or restructuring any of the four
internal modules becomes a single-crate change. The Pattern-internals
divide stops being a published contract.

## What Changes

- **Add** `parse_rule_body(sexpr: &Sexpr) -> Result<Spanned<Effect>, RawError>`
  to `crates/config/src/lib.rs` as the single public entry point for
  parsing the body of a rule (everything after the command-pattern
  position). The function delegates to the existing internal parsers
  (`effect::parse_effect`, which in turn calls `predicate::parse_predicate`
  and `pattern::parse_arg_pattern`).
- **Downgrade** four public re-exports in `crates/config/src/lib.rs` to
  `pub(crate)`:
  - `parse_effect`
  - `parse_predicate`
  - `parse_arg_pattern`
  - `parse_positional_arg`

  `parse_rule`, `parse_define`, `parse_parser_form`, `parse_style_definition`,
  and `parse_command_pattern` remain `pub`: they parse top-level forms
  (rules, defines, parser declarations, style declarations, command-dispatch
  position) and are conceptually distinct from rule-body parsing.
- **Confirm zero external callers** of the downgraded functions before
  the visibility flip; the change is purely a surface-area tightening.
- **Confirm trust-hash invariance**: canonical-form serialisation lives in
  `crates/engine/src/trust.rs` and consumes core AST types
  (`may_i_core::ast::{Effect, Predicate}`,
  `may_i_core::pattern::ArgPattern`) directly. This change does not touch
  those types, the parsers' output, or the canonicalisation path. A
  snapshot of canonical-form output for the prelude SHALL be unchanged
  byte-for-byte across the change.
- **No DSL surface change.** No user-visible behaviour change. No parse
  error message changes. No spec changes to user-facing specs
  (`patterns`, `rule-decisions`, `parser-bindings`).

## Capabilities

### New Capabilities

_None._

### Modified Capabilities

- `code-quality`: adds a contributor-internals requirement that the
  config crate exposes exactly one public entry point for rule-body
  parsing (`parse_rule_body`), and that the four sub-parsers
  (`parse_effect`, `parse_predicate`, `parse_arg_pattern`,
  `parse_positional_arg`) are `pub(crate)`. This pins the new seam so
  a future readability sweep cannot quietly re-widen the surface, and
  gives the consolidation a testable acceptance scenario.

The user-facing specs (`patterns`, `rule-decisions`, `parser-bindings`)
describe the DSL surface and decision semantics; none names the internal
sub-parser functions. They are unaffected by this change.

The contributor spec `parser-engine-invariants` constrains AST shape and
span coherence; it does not name the config crate's parser entry points.
Unaffected.

## Impact

- **Code:**
  - `crates/config/src/lib.rs` — add `parse_rule_body`; flip four
    `pub use` to `pub(crate) use` (or drop the re-export and keep
    callers internal).
  - `crates/config/src/rule.rs` — `parse_rule` continues to call
    `parse_effect` internally; no change to its body, only to imports
    if needed.
  - `crates/config/src/parser_properties.rs` — the existing proptests
    that call `crate::parse_effect` / `crate::parse_predicate` continue
    to compile because they reach in via `crate::`, not via the public
    re-export.
- **Public-API consumers:** none affected. A workspace grep for
  `may_i_config::parse_effect`, `may_i_config::parse_predicate`,
  `may_i_config::parse_arg_pattern`, and `may_i_config::parse_positional_arg`
  returns zero hits before this change.
- **Trust hashing:** unchanged. Canonical-form output for the prelude is
  byte-identical pre/post.
- **Tests:** existing `cargo test` and `cargo tarpaulin` runs pass
  without modification. The new `parse_rule_body` gets at least one unit
  test demonstrating it routes to the same result as the existing call
  path.
- **DSL:** unchanged.
- **Migrations:** none needed (no config format change, no trust-hash
  change).
