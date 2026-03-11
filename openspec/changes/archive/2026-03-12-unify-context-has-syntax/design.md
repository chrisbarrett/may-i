## Context

Context expressions currently expose three different query forms for the same underlying fact model: `(has :key)` for presence, `(= :key "value")` for exact scalar matches, and `(matches :key "regex")` for regex scalar matches. The evaluator already stores facts as entries keyed by namespaced fact names, and `with-facts` already teaches users to think in terms of fact-entry vectors such as `[[:opencode/agent "build"]]`.

The current split leaks into traces. Human-readable output has to invent placeholder strings such as `"<absent>"` for missing scalar values and repeats keys in both columns even though the source query is already shown on the left. This change spans parsing, evaluation, human trace rendering, JSON trace serialization, docs, and tests, so it benefits from an explicit design before implementation.

## Goals / Non-Goals

**Goals:**
- Replace context-level `=` and `matches` with a single `has`-based surface syntax that matches the existing fact-vector model.
- Support a restricted value-pattern grammar for scalar fact queries: bare strings, `*`, `(regex ...)`, `(and ...)`, `(or ...)`, and `(not ...)`.
- Preserve short-circuit evaluation semantics and make unevaluated branches visible in both human and machine traces.
- Simplify human trace output so the right column focuses on observed evidence while JSON trace remains richly structured.
- Preserve source-form choices that matter to readers, especially `(has :foo)` versus `(has [:foo])`.

**Non-Goals:**
- Introduce non-string fact value types such as numbers, booleans, or keywords.
- Reuse the full argument-matcher grammar for fact values.
- Add compatibility shims for the legacy context `=` and `matches` forms.
- Change how runtime facts are produced by integrations or wrappers.

## Decisions

### 1. Unify context fact queries under `has`
Context expressions will continue to support alias references and outer boolean composition, but the primitive fact query surface becomes:

- `(has :key)` or `(has [:key])` for presence
- `(has [:key "value"])` for exact scalar matching
- `(has [:key PATTERN])` for restricted value-pattern matching

This aligns the query syntax with `with-facts` literals and removes the misleading appearance of a generic equality operator comparing a keyword to a string.

Alternatives considered:
- Keep `=` and `matches` and only improve traces: rejected because it leaves the DSL conceptually split.
- Add `has` forms as aliases while retaining legacy syntax: rejected because the user is the only consumer today and prefers a clean break.

### 2. Use a dedicated fact-value pattern grammar
Scalar `has` queries will parse a separate value-pattern AST instead of reusing argument matcher nodes directly. The grammar supports:

- exact string literals
- wildcard `*` meaning "some scalar value exists"
- `(regex "...")`
- `(and ...)`, `(or ...)`, `(not ...)`

Mixed matcher kinds are allowed inside boolean composition, and `not` applies only after a scalar value exists. Presence-only queries remain separate via `(has :key)` / `(has [:key])`.

Alternatives considered:
- Reuse the full arg matcher grammar: rejected because it would drag in unrelated constructs and blur the distinction between argument matching and fact-value matching.
- Keep only exact and regex patterns: rejected because the restricted grammar wants first-class boolean composition and wildcard support.

### 3. Keep internal trace kinds explicit while simplifying the surface syntax
Even though the user-facing syntax becomes uniformly `has`, machine-readable trace data will keep explicit top-level variants:

- `context_has_presence`
- `context_has_exact`
- `context_has_pattern`

`context_has_pattern` will include a structured pattern AST, canonicalized source strings, top-level failure reasons, and a nested evaluation tree with unevaluated children marked explicitly.

Alternatives considered:
- Collapse everything into a single generic `context_has` record: rejected because explicit variants keep tests and renderers simpler.
- Split every pattern shape into its own top-level trace kind: rejected because it would overfit the trace schema to individual matcher forms.

### 4. Optimize human traces for evidence, not restatement
The human-readable trace will preserve the written query on the left and use the right column only for the smallest useful piece of evidence.

- Presence queries render `yes` / `no`.
- Exact scalar queries render `yes` on success, `"actual" -> no` on mismatch, and plain `no` when no scalar value exists.
- Pattern queries render `"actual" -> yes|no` whenever a scalar value exists, and plain `no` when no scalar value exists.

Observed values stay quoted, escaped in JSON-string style, and may be truncated for display. This keeps the human trace compact while leaving JSON output fully explicit.

Alternatives considered:
- Repeat keys or operators in the right column (`"plan" = "build" -> no`): rejected as redundant because the left column already shows the query.
- Distinguish `unset` versus mismatch in human output: rejected because it adds noise; the JSON trace keeps that detail.

### 5. Attach human evidence to the decisive leaf and preserve short-circuit behavior
Value-pattern evaluation will short-circuit consistently with existing trace behavior. Unevaluated branches remain dimmed in the rendered left column and appear in JSON with `evaluated: false`.

For wrapped/composed patterns, the single right-column annotation attaches to the decisive leaf that finalized the result, not to the enclosing `has` form. When no scalar value exists, the plain `no` attaches near the key/value part of the query rather than the closing delimiter.

Alternatives considered:
- Evaluate all pattern children for trace completeness: rejected because existing trace semantics already model short-circuit evaluation and dim unevaluated expressions.
- Attach evidence to the closing line of the whole `has` form: rejected because it delays the most useful evidence when short-circuiting decides early.

## Risks / Trade-offs

- [Breaking DSL change] → Update starter config, docs, and tests together so all examples move in one pass.
- [Pattern grammar grows beyond the current simple fact model] → Keep the value-pattern grammar intentionally restricted and string-only.
- [Trace rendering becomes harder to place correctly on wrapped forms] → Reuse existing annotation placement machinery, but add explicit handling for decisive leaves and missing-scalar cases.
- [Human trace hides why a scalar query failed when the value is absent] → Preserve explicit machine-readable failure reasons such as `absent` and `present_without_scalar`.
- [Canonicalized JSON source diverges from user-authored formatting] → Preserve user-facing sugar choices while canonicalizing only layout/whitespace for stable machine output.

## Migration Plan

- Rewrite local config rules and examples from `(= :key "value")` to `(has [:key "value"])` and from `(matches :key "regex")` to `(has [:key (regex "regex")])`.
- Update docs and starter config in the same change so new syntax is the only documented form.
- Update parser, evaluator, human trace renderer, JSON trace schema, and tests together to keep behavior coherent.

## Open Questions

- None at proposal time; the syntax, trace strategy, and failure-reporting behavior have been explored and decided.
