## Why

The security review of `fix-substitution-origin-attribution` confirmed the
substitution-origin annotation is diagnostic-only (no decision impact), but
deferred two findings — both of which let **adversary-controlled input** degrade
the very diagnostic an operator or agent relies on to understand a blocked
command:

1. **Annotation presence is attacker-controllable.** Whether a bubbled-up reason
   is "already annotated" is decided by sniffing its text for the literal
   `" substitution in "`. A command name carrying that phrase — reachable through
   quoting or ANSI-C `$'…'` — trips the guard and **suppresses** the legitimate
   origin clause on the substitution that encloses it. The decision is unchanged
   and the dangerous command name is still shown, but the origin attribution the
   change exists to provide silently vanishes on attacker command, which is
   exactly where input should have no influence.
2. **The reason-corruption escaping invariant is not load-bearing under test.**
   The reason is consumed as a single JSON string by the Claude Code hook
   surface; an embedded control character corrupts it. `escape_for_reason` guards
   this, but the property that pins it (`prop_reason_is_single_line`) uses a
   generator whose character class excludes control characters — so no test
   actually drives a control char (e.g. a newline from `$'\n'` in a command name)
   into a reason-interpolated name. The guard is correct today only by the
   parser's grammar restrictions holding forever; the test does not enforce it.

## What Changes

- Determine origin-annotation presence from **evaluation structure** rather than
  reason-string content: track whether a bubbled-up reason is already
  origin-annotated as evaluation state carried out of band, so a command name's
  text can never suppress (or spoof) the annotation.
- Remove the substring idempotency guard (`contains(" substitution in ")` and the
  `ends_with(" (embedded substitution)")` band-aid that compensated for the
  generic double-wrap) — both become unnecessary once presence is structural.
- Make the escaping invariant load-bearing: extend the reason-invariant property
  test (or add a focused one) so a control character provably flows through a
  reason-interpolated name (command name), exercising `escape_for_reason`.
- Enforce display-safety in the type system rather than by per-site discipline:
  introduce a `DisplaySafe` newtype with a single escaping smart constructor and make
  `EvalResult.reason` an `Option<DisplaySafe>`, so no reason-building site can ever
  emit an unescaped reason (the post-review `DynamicCommand` leak proved per-site
  escaping is whack-a-mole). The scattered `escape_for_reason` calls are deleted;
  the newtype's constructor is the single choke point.
- No change to any decision, classification, segment, or trust-hash behaviour —
  purely the integrity of the diagnostic string, its type, and its test coverage.

## Capabilities

### New Capabilities

<!-- none -->

### Modified Capabilities

- `shell-command-security-model`: add a requirement that the substitution-origin
  annotation's presence and form are determined by the command's syntactic
  structure, never by the textual content of an attacker-influenced reason, and
  that every interpolated, input-derived name in a reason is control-escaped.

## Impact

- Builds on `fix-substitution-origin-attribution` (same capability, same
  `annotate_embedded_reason` code path); land that change first.
- `crates/engine/src/eval/command.rs` — `annotate_embedded_reason` drops the
  substring guard; `eval_units` carries "reason already origin-annotated" as
  state (a flag propagated with the bubbled `EvalResult`) so the
  `EmbeddedCommand` arm decides re-annotation structurally.
- `crates/engine/src/eval/` tests — extend the reason-invariant property's input
  generator to include control-character vectors so `escape_for_reason` is
  exercised on the reason-interpolated-name path.
- No DSL, config, or trust-hash surface change; no migration.
