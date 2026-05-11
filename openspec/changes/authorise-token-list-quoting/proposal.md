## Why

`(authorise #var)` recursion over a token-list binding (`(rest …)`,
multi-quantifier `(positional … *)` / `… +`, `(parameter NAME (many-till PAT) #var)`)
joins the tokens with single spaces and re-parses the result. The join is lossy:
any token whose content contains shell metacharacters (`&&`, `;`, `|`, `(…)`,
spaces, quotes) loses its boundary. The inner parser then sees those
metacharacters as **structure** rather than as content of a single quoted
argument.

The practical effect is a **policy bypass**. Concrete reproducer:

```
sudo bash -c "echo a && rm -rf /tmp/x"
```

with policy

```
(rule "sudo" (authorise #cmd))
(rule "bash" (authorise #cmd))
(rule "rm"   (deny "no rm"))
```

- sudo's `(rest #cmd)` binds `[bash, -c, echo a && rm -rf /tmp/x]`.
- `(authorise #cmd)` joins → `"bash -c echo a && rm -rf /tmp/x"`.
- Inner shell parse splits at the unquoted `&&`: command 1 is `bash -c echo a`,
  command 2 is `rm -rf /tmp/x`.
- For command 1, bash's `(parameter "c" #cmd)` binds `#cmd = "echo"`. The `a`
  becomes a positional arg to bash. The `rm …` we expected to be inner-of-bash
  is now a sibling at sudo's recursion level.
- Whether the bypass surfaces as `:allow`, `:ask`, or `:deny` depends on the
  exact rule set, but the rule the user wrote — "deny rm inside bash inside
  sudo" — does not fire under its intended semantics. With the rules above the
  decision happens to be `:deny` (the `rm` rule still fires at the wrong layer),
  but with `(rule "rm" (when (fact? [:via "bash"]) (deny)))` the deny silently
  vanishes because the `rm` unit is never under bash's `:via`.

The deeper issue is that the join discards the boundary information the OUTER
shell already established. Wrappers using `(rest …)` to hand off to a `-c`-style
inner program (sudo, ssh, xargs, nix-shell, watchexec, mise, …) are common; the
class of bypass is broad.

This is a **trust-relevant** problem: a user-authored rule that the user
believed they had reviewed does not protect what they think it protects.

## What Changes

- **`(authorise #var)` recursion preserves token boundaries when `#var` is bound
  to a token list.** Instead of joining tokens and re-parsing, the recursion
  takes the first token as the inner command name and the remaining tokens as
  inner argv directly. The inner program's own parser then handles the rest —
  in particular, `(parameter "c" #cmd)` sees its arg as one preserved string,
  exactly as the outer shell delivered it.
- **String bindings continue to parse-as-command-line.** When `#var` is bound
  to a single string (e.g., `(parameter "c" #cmd)` capturing one shell arg),
  the existing `evaluate_authorised_string` path is unchanged. The fix
  introduces a sibling helper for the token-list case.
- **`(many-till …)` captures keep current behaviour.** Many-till joins with
  single spaces by design (the terminator pattern makes the boundary
  unambiguous within the parser's view, but the captured tokens are
  semantically a command-line fragment that the user wrote separated by spaces
  — there's no outer-shell quote envelope to preserve). Document this
  explicitly so the asymmetry isn't a bug.
- **Trace surface unchanged for the common case.** Token-list recursion
  produces a single inner simple-command (or, if argv[0] itself contains shell
  metas, a `DynamicCommand` ask). No quote-wrapping appears in the trace.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `parser-bindings`: the `(authorise #var) recurses on a bound name`
  requirement is split into "string-bound" and "token-list-bound" cases with
  distinct contracts. The current "join with single spaces and parse" clause
  for token-list bindings is replaced by "treat as `(command, args)` directly,
  preserve each arg as a single token".
- `parameter-many-till`: clarify that `(authorise #var)` on a many-till capture
  joins with single spaces (current behaviour) because the captured fragment is
  authored that way by the user, not delivered by the outer shell.

## Impact

- `crates/engine/src/eval/command.rs` — add `evaluate_authorised_tokens` helper
  alongside the existing `evaluate_authorised_string`. Same depth/`:via`/limit
  semantics; takes `&[String]` instead of `&str`.
- `crates/engine/src/eval/effects.rs` —
  - `recurse_into_bound_command` (`Effect::Authorise`): consult the binding's
    kind (`BindingValue::Single` vs `BindingValue::List`) and dispatch to the
    correct helper.
  - `recurse_into_inner_command` (`ParameterForm::Authorise` single-token):
    unchanged — captured value is always a single string.
  - `evaluate_tail_authorise_fold` (`ArgPattern::Tail`): unchanged behavioural
    surface — tail is a token slice that the deprecated form already exposes
    via the slice; route through `evaluate_authorised_tokens`.
- `crates/engine/src/eval/entry.rs` — `ParameterTreatment::Authorise`
  parser-level pre-rule recursion: unchanged (parameter capture is a single
  string).
- `crates/engine/src/eval/bindings.rs` — confirm `BindingValue::List(Vec<String>)`
  vs `BindingValue::Single(String)` are distinguishable at the recursion site.
  If not yet, surface the distinction.
- `openspec/specs/parser-bindings/spec.md` — MODIFY the
  `(authorise #var) recurses on a bound name` requirement: split into
  string-bound / token-list-bound subclauses with separate scenarios.
- `openspec/specs/parameter-many-till/spec.md` — MODIFY the rule-side
  `(authorise #var)` clause: note explicitly that many-till uses
  join-with-spaces because the user authored the fragment that way.
- `tests/binding_recursion.rs` — new integration tests covering the bypass
  reproducer and per-wrapper variants (sudo/bash, ssh/bash, xargs/sh).
- Property test: for any token list `[cmd, arg1, …, argn]` where every `argi`
  is a single bash word (no spaces or metas), token-list authorise and
  string-join authorise SHALL agree. (Documents the equivalence the old
  spec relied on.)
- Migration: none. Behavioural change is a strict tightening — anything that
  worked correctly before (no metacharacters in tokens) keeps working; cases
  that previously silently bypassed now correctly recurse into the inner
  parser's frame.
