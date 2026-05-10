## Context

The config DSL accreted: parser body mixes plist (`:style S`) and form-list (`(flag X)`, `(parameter Y)`); `define-arg-style` body is a flat plist; `check` body is interleaved keyword/value; rule bodies use the only improper-list syntax in the DSL (`(positional X . CONT)`); the recursion verb is named after the binary (`(may-i *)`); decisions are spelled `(effect :decision REASON)` despite user docs saying "the rule allows / asks / denies". Across these is a shared smell: multiple conventions for "list of declarations".

Independently, wrappers without `--` silently bypass authorisation. `parser_positional_args` walks the entire argv with the outer style, so `sudo rm -rf /tmp/x` lets sudo's GNU tokeniser eat `-rf` as combined-shorts before the recursive `(may-i *)` ever sees the inner command. Verified: with `(rule "rm" (forbidden "-rf") …)`, the oracle returns `:allow` for `sudo rm -rf /tmp/x`. The `(anywhere …)` and `(forbidden …)` matchers also fail to honour `--`, so they leak across wrapper boundaries even on parsers where the tokeniser does respect `--`.

The DSL is pre-1.0 (CLAUDE.md: "back-compatibility not required"). One coherent change replacing all of the above is cheaper than several incremental migrations against one another's intermediate forms.

## Goals / Non-Goals

**Goals:**

- Single convention for body shape: every multi-declaration body is a form-list of `(KIND ARGS…)` declarations.
- Single user-facing spelling for decisions: `(allow|ask|deny REASON?)`. Drop `(effect …)` from surface syntax.
- Single recursion verb: `(authorise)`. Drop `(may-i *)` and the dotted-tail continuation form.
- Declarative wrapper-boundary mechanism that fixes the silent-bypass for sudo/xargs/env/timeout/nice/time/watch/su/ionice/chrt/mise.
- A capture-shape primitive that handles `find -exec … \;` and `find -exec … +`.
- One migration window: every existing config rewrites once; trust hashes auto-update for syntactic rewrites.

**Non-Goals:**

- find's predicate algebra (`-and`, `-or`, `\(`, `\)`). Defer to a future change.
- xargs/parallel stdin-injected tokens. Document the blindspot; don't try to model what we can't see.
- Per-subcommand parsers (e.g. `kubectl exec` uses `--` but `kubectl get` doesn't). Defer.
- Sub-second performance optimisation work. Existing perf budgets stay.

## Decisions

### Form-list everywhere, plist nowhere

Every multi-declaration body is a list of `(KIND ARGS…)` forms.

Bodies affected:

- `(parser PROG (style S) (flag F)… (parameter P …)… (tail …)?)`
- `(define-arg-style NAME (overrides …) (separators … …) (long-prefix …) …)`
- `(check (allow CMD R?) (ask CMD R?) (deny CMD R?) …)`

Keywords retain two honest roles only:

- Fact keys (`:via`, `:ssh/host`, user-defined).
- Enum values inside forms (`(pun :allow)`, `(after :flags)`).

Both are existing conventions for tag-style identifiers, not key-value pairs.

**Alternative considered:** keep plist where the body is a flat attribute bag (define-arg-style). Rejected — two conventions cost more than the modest verbosity of the form-list version, and a single rule ("body is a list of declarations") is easier to teach than a discriminator ("plist when flat, form-list when nested").

### `(allow|ask|deny REASON?)` replace `(effect :decision REASON?)`

Three direct verbs at rule body. Reason string optional.

`(effect …)` retires from surface syntax. CONTEXT.md already flags it as contributor jargon ("In user docs say allows / asks / denies"); the surface form should match the documented vocabulary.

**Alternative considered:** keep `(effect :decision REASON?)` as-is. Rejected — leaks contributor noun "effect" into user-facing syntax and forces an extra layer of nesting for the most common forms.

### `(authorise)` is the sole recursion verb

`(may-i *)` retires. `(authorise)` takes no arguments. It only appears nested in a host context that provides a string operand:

- `(parameter NAME (authorise))` — parameter value
- `(tail (authorise))` — tail slice
- `(positional X (authorise) Y)` — single positional element (rare; bare `(authorise)` as leaf consumes one positional and parses its value as a command)

Bare `(authorise)` at rule body root is a config-load error. The host context always disambiguates which span gets recursed.

**Alternative considered:** keep `(may-i *)`. Rejected — naming a DSL form after the binary is a smell, and the `*` placeholder was vestigial since the only matcher used was always `*`.

**Alternative considered:** verb-first form `(authorise (tail))` / `(authorise (parameter "c"))`. Rejected — breaks consistency with `(parameter NAME PATTERN)`'s matcher role, where the body slot can be a constraint rather than an action. Slot-first composition keeps one grammar for parameter regardless of body kind.

### `(tail (after VALUE))` parser-side, `(tail (authorise))` rule-side

The parser declares a tail slice; the rule operates on it.

`VALUE` is either:

- A keyword tag for built-in named positions: `:flags` ("after outer flags consumed").
- A string literal for explicit token boundaries: `"--"`.

Type asymmetry is honest — keyword-as-enum-value is the same Category 2 convention as `(pun :error)`. Future tags can be added (`:first-positional`, …) without grammar change.

Rule-side `(tail X)` body is restricted to `(authorise)` only. There is no use case for "match tail-as-string against regex" that isn't better served by recursing into the inner ruleset.

When a parser declares `(tail …)`, all argv matchers (`(flag …)`, `(parameter …)`, `(positional …)`, `(anywhere …)`, `(forbidden …)`) scope to the outer slice. The tail is exclusively addressable via `(tail (authorise))`.

When a parser does not declare `(tail …)`, `(tail (authorise))` in a rule operates on the residual positional stream after preceding `(positional …)` matches consumed their prefix — the reader-monad context resolves to the only available "rest".

**Alternative considered:** `(tail TOKEN-OR-:after-flags)` with a heterogeneous string-or-keyword value. Rejected — same value-space smell as the plist `:passthrough` we started with.

**Alternative considered:** `(tail-after-flags)` and `(tail-after "--")` as two distinct forms. Rejected — proliferates form names for one concept.

**Alternative considered:** rule-side bare `(tail)` as shorthand for `(tail (authorise))`. Rejected — explicit verb is clearer; shorthand re-introduces "what does bare X do" confusion the user explicitly flagged.

### `(parameter NAME (many-till PAT))` for multi-token capture

Third capture-shape for `(parameter NAME …)`, alongside the existing single-token presence (no body) and constraint-matcher (`"literal"`, `(regex …)`, etc.) cases:

- `(parameter NAME)` — value-bearing, single-token capture.
- `(parameter NAME PATTERN)` — matcher: constrain the captured value.
- `(parameter NAME (many-till PAT))` — capture tokens after NAME until PAT matches one.
- `(parameter NAME (authorise))` — action: authorise the captured value as a command.

`(many-till …)` only appears in a parser declaration body, not a rule. It shapes the capture; the rule then references the shaped value with `(parameter NAME (authorise))` or a constraint matcher.

Multi-occurrence: when a parameter is declared `(many-till …)` and the argv contains multiple occurrences (e.g. `find … -exec foo \; -exec bar \;`), the rule body fires once per occurrence. The strictest decision across occurrences wins, consistent with the existing combiner.

If `(many-till PAT)` reaches end-of-argv without PAT matching, that is a tokenisation error. Per the existing invariant ("when the shell parser emits an error-severity diagnostic, the decision floors to `:ask`"), the rule is treated as :ask, not :deny.

**Alternative considered:** generalising to `(many-till PAT START-PAT)` with explicit start. Rejected — start is always the parameter token by definition; redundant.

**Alternative considered:** modelling find's predicate algebra (`-and`/`-or`/`\(`/`\)`). Rejected as out of scope. `(many-till …)` covers `-exec`/`-execdir`/`-ok`, which is the dominant authorisation-relevant case.

### Tokeniser splits outer/tail when parser declares `(tail …)`

Today `parser_positional_args` walks the whole argv. After this change, when the resolved parser carries a tail declaration, the tokeniser produces two slices:

- **outer**: tokens up to the boundary, parsed under the style (flags, parameters, positionals).
- **tail**: tokens after the boundary, untouched (no flag interpretation).

`(after :flags)` boundary: the outer slice ends after the last flag/parameter consumed; the first non-flag token starts the tail. `(after "--")` boundary: the outer slice ends before the literal `--`; tail starts at the next token. The boundary token (or the absence of one) is recorded for trace rendering.

All argv matchers operate on the outer slice. `(tail (authorise))` reads the tail slice (joined into a command line via the existing `extract_inner_command` join-and-reparse).

**Alternative considered:** make the split implicit — every parser splits at first non-flag positional. Rejected — git, ls, cp, etc. don't have a wrapper boundary; treating their first positional as a tail break would lose match semantics for the common case.

### `(anywhere …)` and `(forbidden …)` honour `--` (Lever A)

`flag_present_in_with_parser` (`crates/engine/src/eval/effects.rs:402-422`) already stops at `--`. `find_parameter_value_with_parser` does too. `(anywhere …)` and `(forbidden …)` (effects.rs:313-346) do not — they scan the full argv. They will, after this change.

Independent of the wrapper-tail mechanism: this fix applies even to parsers without `(tail …)` declared (git, ls, …) where `--` is the path-disambiguator, because tokens after `--` are not flag-shaped tokens for the outer command.

**Alternative considered:** subsume Lever A under the wrapper-tail mechanism. Rejected — `--` as flag-stop is a universal lexical convention for any GNU-shaped tool, not a wrapper-only concern.

### Canonical-form alphabetises parser/style/check bodies

For trust-hash stability under user reformatting, the canonical form sorts:

- Parser body: `(style …)` first, then `(flag …)` declarations alphabetically by canonical name, then `(parameter …)` alphabetically by canonical name, then `(tail …)` last.
- `define-arg-style` body: attributes sorted alphabetically by name.
- `check` body: cases sorted alphabetically by command string.

Rule order remains preserved (rule order is semantic — short-circuit evaluation).

The pretty-printer respects canonical order on output. User-typed orderings are reformatted at format time. CLAUDE.md mandates `cargo fmt` before staging; an analogous `may-i fmt`-style pass on configs is implied (not in scope here, but the canonicaliser is the foundation).

### Migration walks `(load …)` graph transitively

`may-i migrate` rewrites primary config + every transitively-loaded file in one pass. Glob loads (`(load "rules/*.lisp")`) expand at migration time. Cycles are dedupped (existing loader behaviour). Read-only files emit "skipped, not writable" with a clear message.

The migration distinguishes two rewrite classes:

- **Class A (syntactic, semantics-preserving)**: `(effect :allow)` → `(allow)`, `:style S` → `(style S)`, `(positional . CONT)` → `(positional)` `(tail CONT)`, `(may-i *)` → `(authorise)`, `define-arg-style` plist → form-list, `check` plist → form-list. Trust hashes auto-update under the same approval. User is notified, no prompt.

- **Class B (semantic shift)**: the wrapper-boundary fix changes evaluation behaviour for sudo/xargs/etc. — rules don't textually change but their effect on a given command may. Migration emits a prominent warning: "wrapper-boundary fix may change behaviour for rules covering: [sudo, xargs, env, …]. Run `may-i check` to verify your test cases still pass." No automatic action; the user owns verification.

`--dry-run` flag for `may-i migrate` shows the planned rewrites without touching files. CLAUDE.md mandates that auto-migration apply only to the primary config — `may-i migrate` is the explicit, user-invoked path that may write further.

### Prelude ships wrapper parsers

The prelude declares parsers for the common wrapper tools so users don't each rediscover the trick:

```lisp
(parser "sudo"    (style gnu) (tail (after :flags)))
(parser "xargs"   (style gnu) (parameter ["n" "I" "L" "P" "d"]) (flag ["0" "r"]) (tail (after :flags)))
(parser "env"     (style gnu) (tail (after :flags)))
(parser "timeout" (style gnu) (tail (after :flags)))
(parser "nice"    (style gnu) (parameter ["n"]) (tail (after :flags)))
(parser "time"    (style gnu) (tail (after :flags)))
(parser "watch"   (style gnu) (parameter ["n" "interval"]) (tail (after :flags)))
(parser "su"      (style gnu) (tail (after :flags)))
(parser "ionice"  (style gnu) (tail (after :flags)))
(parser "chrt"    (style gnu) (tail (after :flags)))
(parser "mise"    (style gnu) (tail (after "--")))
(parser "find"    (style single-dash-long)
                  (parameter "exec"    (many-till (or ";" "+")))
                  (parameter "execdir" (many-till (or ";" "+")))
                  (parameter "ok"      (many-till (or ";" "+")))
                  (parameter ["name" "iname" "type" "mtime" "size" "regex" "path"]))
```

Users `(overrides …)`-style or shadow as needed. `kubectl exec` is intentionally absent — its `--` is per-subcommand and the per-subcommand parser model is out of scope.

## Risks / Trade-offs

**[Trust-store invalidation]** Every existing user's loaded rules canonical form changes. → Class A rewrites auto-rehash trust under the same approval; user sees a notice but doesn't re-approve. Class B emits a warning but trust still carries (the rule text didn't change).

**[Migration scope explosion]** A user with many `(load …)`'d files sees a pile of file rewrites. → `may-i migrate --dry-run` lists the planned changes; summary output groups by file with rewrite counts; the rewrites themselves are mechanical.

**[Wrapper-bypass fix changes existing rule behaviour]** Some users may have rules that *passed* because of the bypass (e.g. they assumed `sudo rm -rf` was already blocked elsewhere and wrote a permissive sudo allow rule). → Migration's Class B warning + the existing `(check …)` testing framework. This is the bug we are fixing; observable behaviour change is the point.

**[Reader-monad context for `(tail …)` is implicit]** `(tail (authorise))` resolves to either the parser-declared slice or residual positionals depending on context. → Trace renderer surfaces which source the tail came from (outer/tail split rendered explicitly). Error messages name the source: "(tail) on `<cmd>`: parser declares no tail; using residual positionals after positional matches".

**[Multi-occurrence parameter semantics is new]** Today's parameter eval handles single-occurrence; multi-occurrence `(many-till …)` is a new dimension. → Implementation extends the parameter eval to iterate occurrences; existing single-occurrence cases remain unchanged. Property tests cover both.

**[find still incomplete]** `(many-till …)` handles `-exec`/`-execdir`/`-ok` but not `-and`/`-or`/`\(`/`\)`. → Documented limitation; future change adds predicate algebra if real demand emerges. Conservative users can `(rule "find" (anywhere "-and") (ask …))` etc. as guards.

**[xargs/parallel stdin invisibility]** Stdin contents are unknowable to static analysis. → Documented. Inner rules check `(fact? :via "xargs")` and tighten. This is a property of the world, not something the DSL can fix.

**[Canonicalisation reformats source]** A `may-i fmt` pass reorders parser body declarations. Users who depended on visual ordering see their source rewritten. → No actual semantic change; alphabetisation is consistent and predictable. Canonical order is documented.

## Migration Plan

1. Implement the new grammar (parser, define-arg-style, check, decision verbs, recursion verb, tail mechanism, many-till) behind feature parity with the old. Both grammars accepted at parse time during the transition.
2. Implement the tokeniser outer/tail split and matcher scoping.
3. Implement the `(anywhere)`/`(forbidden)` `--` boundary fix.
4. Add the canonical-form sorter.
5. Add the migration rewrites for every Class A transformation.
6. Implement the `(load …)` graph walker for `may-i migrate`.
7. Add the Class B warning.
8. Ship the prelude parsers.
9. Update REFERENCE.md, CONTEXT.md, examples.
10. Run the migration on the user's own config (`~/.config/may-i/config.lisp`); manually verify with `may-i check` and trace inspection.
11. Cut a release. The transition window is short — pre-1.0; no graceful coexistence period.

## Open Questions

- **Class A coverage completeness**: have I enumerated every syntactic rewrite needed? The proposal scope is the canonical list, but a careful audit during implementation may surface edge cases (nested `(may-i *)` inside `cond`, decision keywords inside `(when …)` etc.). Acceptable to discover and add.
- **Multi-occurrence `(many-till …)` evaluation order**: deterministic source-order? Reverse? CLI flag? Default to source order (matches user mental model); revisit if a real case wants otherwise.
- **`may-i fmt`**: a formatter that applies the canonical form is the natural follow-up. Not in scope here; the canonicaliser used for hashing is the seed.
