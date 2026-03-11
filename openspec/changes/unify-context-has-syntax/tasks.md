## 1. Context Query Syntax

- [ ] 1.1 Replace context-parser support for `=` and `matches` with unified `has` query parsing for bare-key, vector-presence, exact-scalar, and pattern-based forms.
- [ ] 1.2 Introduce a dedicated fact-value pattern AST and parser for string literals, `*`, `(regex ...)`, `(and ...)`, `(or ...)`, and `(not ...)`.
- [ ] 1.3 Update context-expression pretty-printing and source serialization so traces preserve sugar choices like `(has :foo)` versus `(has [:foo])`.

## 2. Evaluation And Trace Data

- [ ] 2.1 Implement evaluation for unified `has` queries, including scalar-only wildcard behavior, mixed pattern composition, and short-circuit semantics.
- [ ] 2.2 Add explicit machine-trace annotations for `context_has_presence`, `context_has_exact`, and `context_has_pattern`, including failure reasons and canonical source strings.
- [ ] 2.3 Record nested pattern-evaluation trees with unevaluated children marked explicitly for short-circuited pattern queries.

## 3. Human Trace Rendering

- [ ] 3.1 Update human-readable trace formatting so presence queries render `yes`/`no`, exact mismatches render the observed value, and pattern queries render the observed value whenever a scalar exists.
- [ ] 3.2 Place right-column evidence on the decisive leaf line for wrapped/composed `has` queries, and attach plain `no` near the key/value portion when no scalar value exists.
- [ ] 3.3 Quote, escape, and truncate observed scalar values consistently in human trace output while keeping JSON output fully explicit.

## 4. Documentation And Verification

- [ ] 4.1 Update README, starter config, and related docs/examples to use only unified `has` syntax for context fact queries.
- [ ] 4.2 Refresh parser, engine, and trace tests to cover the new syntax, failure-reason distinctions, and decisive-leaf rendering behavior.
- [ ] 4.3 Run the relevant test suite and fix any regressions introduced by the syntax and trace changes.
