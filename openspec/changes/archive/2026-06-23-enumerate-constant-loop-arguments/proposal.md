## Why

A `for` loop over a statically-known literal list binds its variable to a finite,
provable set of values:

```sh
for k in domains/api/zone domains/web/zone domains/dev/zone; do
  aws s3 cp "s3://bucket/$k/terraform.tfstate" /tmp/x
done
```

Every iteration runs, so the value of `$k` at the use site is provably one of
three literals — yet today the body's `$k` is an unresolved expansion and floors
the `:allow` to `:ask` (`constant_env` deliberately disqualifies loop variables,
`crates/shell-parser/src/const_env.rs:55`). This `for x in <literal list>` shape
is ubiquitous in ops scripts; the spurious ask trains reflex-approval.

## What Changes

- When a `for` loop's list is **statically enumerable** (every list word a static
  literal — no command substitution, glob, `$@`/`$*`, or unresolved variable),
  treat the loop variable as bound to that finite value set within the loop body.
- Resolve the body by **unrolling**: emit the body's evaluation units once per
  list value, each with the loop variable bound to that single literal, then
  combine with the existing strictest-wins meet across units. All iterations run,
  so strictest-wins is the sound combination — if any value fails an allow
  pattern, that unit floors and the meet asks.
- Reuse single-value resolution from `resolve-constant-argument-expansions`: each
  unrolled body sees the loop variable as one more provably-constant scalar. No
  matcher change.
- Bound the unrolling by a **total-unit budget**; nested loops multiply, so over
  budget the loop variable falls back to its current unresolved (flagged)
  behaviour. The cap only costs precision, never soundness.

## Capabilities

Bucket: `parsing` (how argv words resolve before rules see them).

### New Capabilities

<!-- none -->

### Modified Capabilities

- `shell-command-security-model`: enumerate a statically-known `for` list as the
  loop variable's provable value set and evaluate the body once per value
  (bounded), so a body argument built from the loop variable is classified as it
  would be for each concrete value, combined strictest-wins.

## Impact

- `crates/shell-parser/src/const_env.rs` — stop unconditionally disqualifying a
  `for` variable; expose the enumerable list (or keep the disqualification when
  the list is not statically literal, the variable is reassigned/`unset` in the
  body before use, or the body is otherwise non-enumerable).
- `crates/engine/src/eval/decompose.rs` — when a `for` loop is enumerable, unroll
  its body per list value into the existing `EvalUnit` stream with the loop
  variable seeded into each copy's constant env; enforce the total-unit budget
  and fall back to the single non-unrolled walk when exceeded.
- Tests: `crates/engine` — unroll-and-meet for all-match (allow) and
  some-match (ask); nested-loop product; budget fallback; non-literal list stays
  flagged. Metamorphic: per-value classification equals the bare command with
  that literal.
- No DSL, config, or trust-hash surface change; no migration. **Depends on**
  `resolve-constant-argument-expansions` (single-value argument resolution).
  Independent of the array changes.
