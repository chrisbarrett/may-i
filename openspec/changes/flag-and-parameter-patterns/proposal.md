## Why

Today, rules express flag-related concerns through string-literal matchers
(`(anywhere "-x")`, `(forbidden "--force")`, `(positional "-c" . (may-i
*))`). This forces users to:

- enumerate every spelling of a flag they care about (`-r`, `-rf`, `-fr`,
  `-rfv`, `--recursive`),
- rely on accidental cross-talk with `expand_combined_flags` for combined
  shorts to match,
- reverse-engineer how `positional_args` strips/keeps tokens just to write
  a working `(positional "-c" …)` rule.

This is brittle. The classic example is `(rule "bash" (positional "-c" .
(may-i *)))` — broken because `positional_args` strips `-c` from the
positional stream, so the value of `-c` is matched against the literal
pattern `"-c"` and fails. The intent — "recurse on the value of the `-c`
flag" — has no clean expression in the grammar today.

This change adds two new pattern forms that make flag handling
first-class:

- `(flag X)` — boolean: is the flag present (in any tokeniser-recognised
  form)?
- `(parameter X FORM)` — extract the value of the flag and route it to
  `FORM` for further matching (`regex`, `may-i`, fact-bind, etc.).

Composes with the `(parser …)` / `(define …)` parsing DSL from
`per-command-arg-style`, which is a prerequisite for this change. Where
parser-level `(flag …)` / `(parameter …)` declarations cover *what is a
flag and what consumes a value*, the rule-level forms in this change
cover *what to do when a given flag or value is present*.

## What Changes

- **New pattern: `(flag X)`** — true if the named flag appears in the
  tokenised arg stream. `X` may be a string (length-1 ⇒ short, longer ⇒
  long) or a vector of two strings `[short long]` to match either form.
- **New pattern: `(parameter X FORM)`** — matches the flag's value against
  `FORM`. Supports the same naming convention as `(flag …)`. Implicitly
  registers `X` as a value-bearing flag for the tokeniser even if not
  declared in `args-style :flags-with-values`.
- **No `(no-flag …)`** — negation uses the existing `(not …)` combinator:
  `(not (flag X))`. Keeps the surface area minimal.
- **Match semantics** — `(flag X)` returns Allow if present, Nil
  otherwise. `(parameter X FORM)` returns Nil if the flag is absent;
  otherwise the result of `FORM` evaluated against the flag's value.
- **Consumption** — `(parameter X FORM)` consumes both the flag token and
  its value from the stream visible to subsequent positional matchers in
  the same rule, the same way `(positional …)` consumes its matches.
- **Tokeniser feedback** — flags named in any rule-level `(parameter …)`
  form are added to that rule's effective value-bearing list during
  evaluation, so the tokeniser correctly groups flag-value pairs even
  when no parser-level declaration covers them. This rule-level implicit
  registration is a transitional convenience; the canonical way to make a
  parameter value-bearing is a parser-level `(parameter X)` declaration
  (see `per-command-arg-style`).
- **Migration rewrites** — automatic migration converts:
  - `(anywhere "-x")` ⇒ `(flag "x")`
  - `(forbidden "-x")` ⇒ `(not (flag "x"))`
  - `(positional "-c" . FORM)` ⇒ `(parameter "c" FORM)`
- **`bash -c` rule unblocked** — `(rule "bash" (parameter "c" (may-i *)))`
  now works correctly.

## Capabilities

### New Capabilities

- None — extends existing `pattern-expressions`.

### Modified Capabilities

- `pattern-expressions` — gains `flag` and `parameter` forms.

## Impact

- `crates/core/src/ast.rs` — new `ArgPattern::Flag { name }` and
  `ArgPattern::Parameter { name, form }` (or equivalent enum variants).
- `crates/core/src/pattern.rs` — `is_match` / serialisation extensions.
- `crates/config/src/...` — parser support for `(flag …)` and `(parameter
  … FORM)`.
- `crates/engine/src/eval/effects.rs` — new branches in
  `evaluate_arg_pattern_effect_fold` for the new patterns.
- `crates/engine/src/eval/entry.rs` — tokeniser collects implicit
  value-bearing flags from `(parameter …)` patterns in matching rules.
- `src/cmd_migrate.rs` (or rewrite-rule registry) — migration rewrites for
  the three deprecated shapes.
- `tests/` — integration tests covering each new form, combined-shorts
  interaction, `(may-i)` integration, and migration.
- `openspec/specs/pattern-expressions/spec.md` — modified to document the
  new forms.

## Dependencies

- Depends on `per-command-arg-style` (the `(parser …)` / `(define …)`
  parsing DSL and parser-aware tokeniser). Land that first or alongside.
