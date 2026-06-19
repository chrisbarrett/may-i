## Context

`annotate_embedded_reason` (`crates/engine/src/eval/command.rs`) wraps a
bubbled-up substitution reason with an origin clause (`($(...) substitution in
\`grep\`)`). Substitutions nest, so the same reason can pass through several
embedding layers; the function must wrap exactly once. Today it detects
"already wrapped" by sniffing the reason text:

```rust
if inner.contains(" substitution in ") || inner.ends_with(" (embedded substitution)") {
    return inner.to_string();
}
```

The inner reason embeds an attacker-influenced command name — `No rule for
command \`{escape_for_reason(name)}\`` — and `escape_for_reason` does not escape
spaces. A command name such as `"x substitution in y"` (reachable via quoting)
makes the inner text contain the guard's sentinel, so the **enclosing**
substitution's legitimate origin clause is suppressed. The decision is
unaffected and the command name is still printed, but the origin attribution —
the entire point of `fix-substitution-origin-attribution` — disappears on
exactly the adversary input where the operator most needs it.

Separately, `prop_reason_is_single_line` is meant to guarantee no reason ever
carries a raw control character (which would corrupt the single-JSON-string hook
surface). Its generator's character class excludes control characters, so the
property passes vacuously for the reason-interpolated-name path; the
`escape_for_reason` call that actually prevents corruption is never exercised by
it.

## Goals / Non-Goals

**Goals:**

- The presence and form of the origin annotation depend only on evaluation
  structure (which syntactic position owns the substitution, how deep the
  recursion is) — never on the textual content of an input-derived reason.
- Removing the substring guard preserves every current annotation output
  byte-for-byte (single-wrap, no double-wrap, idempotent across nesting).
- The control-escaping invariant on reason-interpolated names is enforced by a
  test that actually drives a control character through that path.

**Non-Goals:**

- Changing any decision, classification, segment range, fold event, or
  trust-hash. This is diagnostic-string integrity only.
- Re-escaping spaces or otherwise altering `escape_for_reason`'s character
  policy — the fix removes the *reliance* on reason text, it does not change what
  the text contains.
- Reworking how origin is computed (that is `fix-substitution-origin-attribution`,
  which this builds on).

## Decisions

### D1 — Carry "already origin-annotated" as evaluation state, not reason text

`eval_units` returns, alongside its `EvalResult`, a boolean that means *the
aggregate reason being returned already carries a substitution-origin clause*.
The `EmbeddedCommand` arm consumes this flag from its recursive call: it applies
`annotate_embedded_reason` only when the inner flag is `false`, and reports
`true` for its own result whenever it produced (or passed through) an annotated
reason. Every non-embedded unit (simple command, dynamic command, floors, parse
error) reports `false` — none of them annotate. The aggregate adopts the flag of
whichever unit's reason wins the strictest-wins meet.

`annotate_embedded_reason` then drops both substring checks entirely: callers
guarantee it is invoked at most once per reason, so it unconditionally wraps
(still falling back to the generic clause for a process substitution or an
unnameable owner). The sentinel an attacker could forge no longer exists in the
control path.

**Mechanism.** Thread the flag through `eval_units`' internal return rather than
adding a field to the public `EvalResult`. `eval_units` and its recursion are
internal; the three call sites that discard the flag (`evaluate_command_with_fold`,
`evaluate_authorised_string`, the token path) are trivial, and the
`EmbeddedCommand` recursion is the only consumer. This keeps the public result
type unchanged.

**Alternative rejected — keep substring sniffing, just harden the sentinel.**
Any in-band marker placed in user-visible text is reconstructible by an attacker
who controls part of that text (command names, and tomorrow perhaps assignment
targets if the grammar loosens). Out-of-band state is the only construction that
removes input influence rather than narrowing it.

**Alternative rejected — a `pub(crate)` flag field on `EvalResult`.** Lower
churn, but it pollutes the public result type with a transient internal concern
and leaks an annotation bookkeeping bit to every consumer of `evaluate_command`.

### D2 — Make the escaping invariant load-bearing

Extend the input generator behind the reason-invariant property
(`prop_reason_is_single_line`) so it can emit control-character vectors —
ANSI-C `$'\n'`/`$'\t'` command-name forms and raw control bytes — guaranteeing a
control character reaches a reason-interpolated name. The property then fails if
`escape_for_reason` is ever bypassed on that path, turning a today-vacuous check
into a real guard. A focused regression test pins one explicit
control-char-in-command-name case alongside the property.

## Risks / Trade-offs

- **Signature churn on `eval_units`.** → Only three internal call sites discard
  the new flag; the public API is untouched. Covered by the full engine suite.
- **Behavioural drift in the annotation string.** → The existing tests
  (`nested_embedded_substitution_does_not_double_wrap`,
  `embedded_*_substitution_names_outer_command`, the per-origin unit test) lock
  the current output; they must pass unchanged, which is the acceptance bar.
- **A broadened generator could surface unrelated reason-corruption paths.** →
  Desirable if so — that is the property's job; any failure is a real bug to fix,
  not a reason to narrow the generator.

## Migration

None. Internal diagnostic-string mechanism only; no config, DSL, or trust-hash
surface, and no user-config change.

## Open Questions

<!-- none -->
