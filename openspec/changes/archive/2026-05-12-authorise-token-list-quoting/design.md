## Context

`BindingValue` already distinguishes the two shapes the recursion needs to
treat differently:

```rust
pub enum BindingValue {
    Token(String),         // single-string capture (parameter "c" #cmd, single positional)
    Tokens(Vec<String>),   // token-list capture (rest, positional *+, many-till)
    Unbound,
}
```

But the only consumer that matters for recursion — `Effect::Authorise` —
collapses both via `BindingValue::as_joined()`, which calls
`Tokens(v).join(" ")`. The structural information that the outer shell already
established is discarded right before it would be useful.

The downstream `evaluate_authorised_string` then sees a string and must guess
where the OUTER shell put boundaries. For tokens containing shell
metacharacters (`&&`, `;`, `|`, parens, spaces, quotes), the guess is wrong.

Concrete:

```
input:       sudo bash -c "echo a && rm /"
sudo argv:   [bash, -c, echo a && rm /]              ← 3 tokens, third has metas
#cmd bound:  Tokens([bash, -c, echo a && rm /])      ← shape preserved
as_joined:   "bash -c echo a && rm /"                ← shape lost
parse:       ["bash -c echo a", "rm /"]              ← two top-level commands
```

The third token (which is `bash -c`'s `-c` argument) is split at the unquoted
`&&`. The recursion that follows operates on the wrong frame: the `rm` unit is
a sibling of `bash`, not a child.

The recursion side already knows the shape — it just throws it away.

## Goals / Non-Goals

**Goals:**
- Token-list `(authorise …)` recursion preserves token boundaries end-to-end.
  Tokens containing shell metacharacters arrive at the inner parser intact.
- Wrapper-chains like `sudo → bash -c` reach the same decision as the
  equivalent direct invocation `bash -c …` (modulo the extra `:via "sudo"`).
- Equivalence: for any token list with no metacharacters in any token, the new
  behaviour agrees with the old (regression-safe).
- The fix is a strict tightening of the existing policy contract. No rule that
  correctly authorised under the old behaviour starts failing.

**Non-Goals:**
- Changing the surface DSL.
- Changing single-string capture behaviour (`(parameter "c" #cmd)`).
- Changing `(many-till …)` semantics. The captured fragment is authored by the
  user as a space-separated sequence, not delivered by the outer shell; the
  current join-and-parse behaviour is correct for it.
- Re-doing the recursion contract from scratch. The fix is an additive
  dispatch on the binding kind, not a rewrite of `evaluate_authorised_string`.

## Decisions

### 1. Add `evaluate_authorised_tokens` alongside `evaluate_authorised_string`

```rust
pub(crate) fn evaluate_authorised_tokens<F: EvalFold>(
    tokens: &[String],
    config: Option<&Config>,
    facts: &ContextFacts,
    fold: &mut F,
    depth: usize,
    via_program: Option<&str>,
) -> Result<EvalResult, EvalError>
```

Same depth-limit guard, same `:via` push, same return shape as the existing
helper. Body:

- If `tokens` is empty → empty-command short-circuit (matches existing
  no-match semantics for empty bindings).
- Let `command = tokens[0]`, `args = tokens[1..]`.
- If `command` itself contains shell metacharacters or is empty → return
  `:ask` with a dynamic-command-name reason. This mirrors how
  `evaluate_authorised_string` surfaces `EvalUnit::DynamicCommand`. Tokens are
  not expected to be dynamic (the outer parse already resolved them), but the
  guard preserves the "I don't know what this is" invariant rather than
  silently mis-recursing.
- Otherwise call `evaluate_at_depth(command, args, config, facts_with_via,
  fold, depth)`. Single inner unit — no aggregation needed.

The helper has NO `decompose` step. That's the entire point: the outer shell
already decomposed; we trust its work.

**Alternative**: have `evaluate_authorised_string` take `Either<&str,
&[String]>`. Rejected — two helpers with clear names are easier to read and
test than one helper with a discriminant.

### 2. Dispatch at the `Effect::Authorise` call site

```rust
Effect::Authorise { binding } => {
    let value = ctx.parser_bindings.get(binding);
    if value.is_empty() {
        return Ok(fold.effect_nil(effect));
    }
    recurse_into_bound_command(fold, effect, value, ctx, rules)?
}
```

`recurse_into_bound_command` consults the kind:

```rust
match value {
    BindingValue::Token(s) =>
        evaluate_authorised_string(&s, ..., Some(ctx.command)),
    BindingValue::Tokens(v) =>
        evaluate_authorised_tokens(&v, ..., Some(ctx.command)),
    BindingValue::Unbound => unreachable!(),  // guarded above
}
```

Both branches share the surrounding `fold.begin_recursive_eval()` and outer
`effect_terminal` wrapper, so the trace shape is identical.

### 3. `ArgPattern::Tail` is a token-list path

The `(tail (authorise))` form (legacy) resolves a tail slice as `&[String]`
and currently joins it before recursing. Route it through
`evaluate_authorised_tokens` directly — no join, no quote-loss. Trace
surface stays the same because the existing site already wraps with
`effect_arg_continuation`.

### 4. `ParameterForm::Authorise` and parser-level
       `ParameterTreatment::Authorise` are string paths — unchanged

Both capture a single shell arg as one string. The outer shell preserved
that string as a single token; there's no token-list to dispatch on.
They continue calling `evaluate_authorised_string`.

### 5. `(many-till …)` continues to join-with-spaces

The captured fragment is authored by the user as a space-separated command
inside e.g. `-exec rm /tmp/x \;`. The user wrote the spaces; there's no
quoted-arg envelope that the shell stripped. The current behaviour
(`as_joined()` → string-parse) is correct. The spec gets a sentence
clarifying that the asymmetry with `(rest)` is deliberate, not a missed
case.

### 6. `BindingValue::as_joined` retains its current meaning

`as_joined` is used elsewhere — `(matches? #var PAT)`,
`(with-facts [[:k #var]] …)` — where the join-into-one-string semantics is
correct (these are predicate / fact-promotion contexts, not recursion).
Don't touch it. The fix lives entirely at the recursion dispatch.

### 7. Equivalence guarantee

For any token list `tokens` where every element matches the regex
`[^ \t\n;|&()<>"'$\\`]+`, `evaluate_authorised_tokens(tokens)` produces the
same decision as `evaluate_authorised_string(tokens.join(" "))`. This is the
regression-safety property — anything that worked under the old join-and-parse
keeps working. Encode as a proptest.

## Risks / Trade-offs

- **Behaviour change visible to users.** A rule set that *accidentally* relied
  on the old bypass (e.g., a `sudo` rule that allowed everything because
  inner `rm` evaluated at the wrong layer and matched a permissive `rm` rule)
  will now correctly invoke the stricter inner rule. Mitigation: this is the
  fix. Frame in release notes as a security fix; recommend users re-review
  wrapper rule sets.
- **Trace verbosity.** Token-list recursion now resolves a single inner
  simple-command instead of "splitting" into multiple units. Less verbose, not
  more. No mitigation needed.
- **Dynamic command in argv[0].** If a binding produces `[$X, args…]` (e.g.
  via a not-yet-resolved variable that survived earlier passes), the new
  helper returns `:ask`. The old behaviour would have parsed-joined and gone
  somewhere arbitrary. Surfacing `:ask` is correct.
- **`(many-till …)` asymmetry.** Many-till still joins-and-parses for the
  semantic reason above. A user might reasonably ask "why is this case
  different?" Mitigation: spec sentence explaining the outer-shell-envelope
  distinction.

## Migration Plan

- No config migration needed. The behavioural shift only affects evaluations
  that were already producing a *wrong* decision under the old code path.
- Trust hashes unchanged: no rule grammar changes, no canonical-form changes.
- Release as a patch on the next version after `0.3.0-pre5`. Suggest CVE-style
  note: "policy bypass for `(authorise #var)` over `(rest)`-style bindings
  when inner argv contains shell metacharacters."

## Open Questions

- Should the `command-contains-metacharacters` guard in
  `evaluate_authorised_tokens` reject `command` containing `=` as well?
  (Shell assignment-prefix syntax.) The outer parse wouldn't have produced
  such a token as argv[0] normally, but be conservative — return `:ask` with
  a "command name contains assignment syntax" reason. Defer to implementation
  review.
- For `(positional #foo *)` bindings, do we want to preserve the existing
  no-match semantics when the list is empty, or treat them as "no inner
  command" with an explanatory reason? The helper short-circuits to `:ask`
  with "empty command" today; integration tests will tell us if this surfaces
  oddly. Leaning ask-with-reason for visibility.
