## 1. Fold absorbed pattern specs into `pattern-expressions`

For each move, copy the `### Requirement: NAME` block — body and
`#### Scenario:` children — verbatim from the source file. Append in
source order.

### 1a. From `expr-combinator-matching` → `pattern-expressions`

- [x] 1a.1 *Expr::Or matches if any sub-expression matches* — copy
  verbatim. Title may be rephrased to user vocabulary at apply time.

### 1b. From `partial-pattern-matching` → `pattern-expressions`

- [x] 1b.1 *Fewer args than required patterns returns no match*.
- [x] 1b.2 *Optional quantifier matches with or without arg*.
- [x] 1b.3 *OneOrMore quantifier requires at least one match*.
- [x] 1b.4 *ZeroOrMore quantifier matches any count*.

### 1c. From `v2-expr-fact-binding` → `pattern-expressions`

- [x] 1c.1 *Bind is valid in positional, exact, and anywhere but not
  forbidden* — copy verbatim. Title may be rephrased to user vocabulary
  at apply time.

## 2. Fold parameter capture and prelude into `parser-bindings`

- [x] 2.1 Rewrite `parser-bindings` Purpose to cover the full per-program
  parser-declaration surface: style, flag-scanning mode, parameters
  (single and `(many-till …)`), positionals, `(rest …)`, fact bindings,
  shadowing, prelude defaults.

### 2a. From `parameter-many-till` → `parser-bindings`

- [x] 2a.1 *`(many-till PAT)` declares multi-token parameter capture*.
- [x] 2a.2 *Rules access `(many-till …)`-captured value via the bound
  `#var`*.
- [x] 2a.3 *Multi-occurrence parameters fire rule body per occurrence*.

### 2b. From `prelude-wrapper-parsers` → `parser-bindings`

- [x] 2b.1 *Prelude ships parsers for common wrapper tools*.
- [x] 2b.2 *Prelude ships `find` parser with `(many-till …)` and named
  bindings*.

## 3. Fold span-coalescing into wordpart-source-spans

- [x] 3.1 *Adjacent ignore spans SHALL be coalesced* — copy verbatim
  from `span-coalescing/spec.md`.

## 4. Remove absorbed spec directories

- [x] 4.1 `rm -rf openspec/specs/expr-combinator-matching/`
- [x] 4.2 `rm -rf openspec/specs/partial-pattern-matching/`
- [x] 4.3 `rm -rf openspec/specs/v2-expr-fact-binding/`
- [x] 4.4 `rm -rf openspec/specs/parameter-many-till/`
- [x] 4.5 `rm -rf openspec/specs/prelude-wrapper-parsers/`
- [x] 4.6 `rm -rf openspec/specs/span-coalescing/`

## 5. Update cross-references

- [x] 5.1 `grep -rln 'expr-combinator-matching\|partial-pattern-matching\|v2-expr-fact-binding\|parameter-many-till\|prelude-wrapper-parsers\|span-coalescing' openspec/specs/ .claude/ CONTEXT.md CLAUDE.md README.md`
  — repoint each hit.

## 6. Verify

- [x] 6.1 Each absorbed requirement appears once and only once in its
  new home.
- [x] 6.2 `wordpart-source-spans` retains its contributor-only
  declaration.
- [x] 6.3 `openspec validate consolidate-parsing-specs --strict` passes.

## 7. Note: rename deferred

- [x] 7.1 The rename `pattern-expressions` → `patterns` (vocab alignment
  per `spec-conventions`) is deferred to the `rename-specs-to-vocab`
  change.
