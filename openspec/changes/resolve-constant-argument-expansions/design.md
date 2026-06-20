## Context

The `resolve-constant-command-names` change (archived 2026-06-17) added
`constant_env` — a structural analysis returning the variables whose value is
provably constant for a command — and wired it into `decompose` so a dynamic
**command-name** word (`$BIN`) resolves to its literal before being declared
dynamic. That change explicitly listed "resolving variable *arguments*" as a
Non-Goal.

The remaining gap is the link from argument words to that env. In
`decompose_simple_command` (`crates/engine/src/eval/decompose.rs:644-648`),
arguments are produced by `w.to_str()` (raw, unresolved) and each
expansion-bearing word is recorded in `arg_expansions`. When an `:allow` match
rests on an expansion-bearing argument and the matcher constrains the value,
`anywhere_match`/the matchers record it as unresolved and the rule evaluator
floors the `:allow` to `:ask` (`unresolved_expansion_reason`). The motivating
case — `BUCKET=…; KEY=…; aws s3 cp "s3://$BUCKET/$KEY" …` — is provably constant
yet asks.

`Word::resolve(const_env)` already resolves a mixed word against the env (it is
how the command-name path works), so the machinery exists; only argument words
are untouched.

A second, latent issue surfaces here. The command-name requirement already
states the constant assignment must "execute unconditionally **before the use**",
but `constant_env` records assignments without inspecting use position
(`crates/shell-parser/src/const_env.rs::collect` walks assignment-like nodes
only). So `$X foo; X=lit` resolves `$X` to `lit` even though `X` is the inherited
environment at the use site — `may-i` then evaluates the wrong command. The gap
is narrow for command names but becomes sound-critical once arguments resolve,
so this change closes it.

## Goals / Non-Goals

**Goals:**

- Resolve an argument word against the command's provably-constant env so an
  argument built from local literals matches rules on its real value and no
  longer floors an `:allow` as an unresolved expansion.
- Make the provably-constant analysis use-order-aware: a variable used before
  its sole assignment is not resolved, for both the command-name and argument
  paths.
- Never change a decision except to turn an unresolved-expansion ask into
  evaluation of the real, proven value.

**Non-Goals:**

- Transitive resolution (`DIR=/o; KEY=$DIR/x`) — RHS must be a pure literal, as
  in the command-name change.
- Resolving any value requiring runtime knowledge: `$(…)`, conditionally-set,
  reassigned, loop/function-scoped, environment-inherited.
- Suppressing secret-read taint for const-resolved names (see Risks). Out of
  scope; taint behaviour is unchanged.
- Partial-word resolution feeding a partially-substituted string to matchers —
  resolution is all-or-nothing per word.

## Decisions

### D1 — Resolve argument words in `decompose_simple_command`, all-or-nothing

Where `args`/`arg_expansions` are built (`decompose.rs:644-648`), resolve each
argument word against the existing `const_env`:

- If `!word.resolve(const_env).is_expansion_bearing()` → push the resolved value
  into `args` and set that word's `arg_expansions` entry to `None` (provable).
- Otherwise → keep `w.to_str()` and the existing
  `is_expansion_bearing().then(display_source)` entry (unchanged behaviour).

The guard is `!is_expansion_bearing()`, **not** `is_literal()`: `is_literal()`
returns true for an unquoted glob/brace word (`/tmp/a*`, `{a,b}`), which is
expansion-bearing and must stay flagged — clearing it would let a glob word
satisfy an `:allow`, which D3 forbids. The expansion-bearing check is the honest
"every part is proven" test (it also keeps a leading-tilde word flagged).

Symmetrically, `const_env` resolution itself must not launder an expandable
value into a literal: `resolve_param_op` resolves a `${VAR…}` operator form only
when **all** its operands are inert (no nested `$`/backtick, and — for operands
that become part of the produced word — no glob metachar or leading tilde). An
operator word with an expandable operand (`${A:+/tmp/*}`, `${Y#$X}`,
`${Y/cat/$R}`) stays expansion-bearing and floors. This guard lives in
`crates/shell-parser/src/resolve.rs` (`op_operands_are_inert`) and is newly
load-bearing because arguments resolve operator forms that the command-name path
(lone-variable-only) never reached.

All-or-nothing per word mirrors the command-name precedent and keeps the
`arg_expansions` flag honest: a word is cleared only when *every* part is proven.
A partially-resolved word (`s3://$BUCKET/$UNKNOWN`) stays flagged and floors as
today. `args.len() == arg_expansions.len()` is preserved (the
`debug_assert_eq!` in `anywhere_match`).

Mixed words are the common argument shape (URLs, paths), unlike command names
where a lone-variable word was required; `Word::resolve` already handles mixed
words part-by-part, so no new resolution logic is needed.

### D2 — Make `constant_env` use-order-aware

Extend the analysis so a use of a name that lexically precedes its sole
qualifying assignment on the straight-line spine disqualifies that name. The
analysis already disqualifies names assigned in nested/conditional/loop/function
contexts; this adds the one remaining ordering case on the spine. Implementation
walks in source order and records a name as "used" when it appears as an
expansion in any word; an assignment seen *after* a prior use of the same name
does not establish a constant for that name.

This is a single shared change in `constant_env`, so both the command-name path
(D2 of the prior change) and the new argument path inherit it. Straight-line
assign-then-use — the overwhelmingly common case, including the motivating
command — is unchanged.

### D3 — Conservative by construction; resolution only narrows asks

If a name is not in the (now use-order-aware) `const_env`, behaviour is
byte-for-byte unchanged: the argument keeps its raw form and its
expansion-bearing flag. The change can never introduce a wrong `:allow` because
an unproven value is never resolved, and the proven value is exactly what the
shell will pass. A resolved argument flows through normal matching as a literal
argument would — so a `:deny`/`:ask` rule keyed on the real value now fires where
the raw `$VAR` text would have hidden it (tightening, also sound).

## Risks / Trade-offs

- **Mis-resolution → wrong rule match.** Mitigated by the single-static-assignment,
  straight-line, no-reassignment, use-order bar; any ambiguity falls back to the
  unresolved-expansion floor. The all-or-nothing rule prevents a half-resolved
  string from matching a rule it shouldn't.
- **Use-before-assignment was a latent command-name gap.** D2 closes it. Risk is
  that some currently-resolved command name becomes dynamic again — but only in
  the `$X; X=lit` shape, which mis-resolves today and *should* be dynamic. Net
  effect is more-correct, never less-safe. A failing test (red) confirms the gap
  exists before the fix lands; if it already passes, D2 narrows to a
  regression-guard.
- **Secret-read taint interaction.** A const-resolved name (`P=lit; cat "$P"`) is
  a locally-assigned literal, not an inherited secret, yet `collect_parameter_names`
  still flags `$P` for `(env NAME (deny))` taint. Leaving taint unchanged is the
  safe default (taint only tightens). Refining it to exempt const-resolved names
  is deliberately out of scope.
- **Straight-line precedence vs true execution order.** As with command names,
  assignments in branches stay excluded; we do not prove a conditional always
  runs. Cost: some safe cases stay flagged. Acceptable — the change only adds
  coverage.
