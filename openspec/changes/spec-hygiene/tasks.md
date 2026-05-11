## 1. Add new requirement to `spec-conventions`

- [x] 1.1 Add `### Requirement: Spec names use user vocabulary` to
  `openspec/specs/spec-conventions/spec.md`, after the existing audience
  requirement (Requirement 3). Wording must explicitly exempt (a) the meta-
  spec `spec-conventions` itself and (b) contributor-only specs (audience
  declared in Purpose) from the user-vocabulary constraint.
- [x] 1.2 Add `#### Scenario:` blocks covering: a user-facing spec named
  with contributor vocabulary (FAILS), a contributor spec named with
  contributor vocabulary (OK because audience declared), the meta-spec named
  `spec-conventions` (OK by exemption).
- [x] 1.3 Update `.claude/rules/openspec-specs.md` checklist to add a bullet
  referencing the new requirement.

## 2. Restructure `trust-hashing` to canonical headings

- [x] 2.1 Replace the leading `## ADDED Requirements` line with the canonical
  scaffold: `# Trust-Hashing Specification`, `## Purpose` (write Purpose;
  declare `Trust-relevant: yes` and cross-ref `trust-store`, `trust-command`,
  `trust-provenance`), `## Requirements`.
- [x] 2.2 Verify all 8 `### Requirement: ...` blocks survive verbatim and
  retain their `#### Scenario:` children.

## 3. Insert canonical `# X Specification` title in 18 specs

For each spec below, insert a new line 1 reading
`# <Spec-Name> Specification` (capital initials, hyphens preserved); push
existing content down. Do not touch any `## Purpose` or `## Requirements`
content.

- [x] 3.1 `code-quality` → `# Code-Quality Specification`
- [x] 3.2 `fact-system` → `# Fact-System Specification`
- [x] 3.3 `human-evaluation-trace` → `# Human-Evaluation-Trace Specification`
- [x] 3.4 `interactive-trust-review` → `# Interactive-Trust-Review Specification`
- [x] 3.5 `migration-system` → `# Migration-System Specification`
- [x] 3.6 `migration-testing` → `# Migration-Testing Specification`
- [x] 3.7 `parser-engine-invariants` → `# Parser-Engine-Invariants Specification`
- [x] 3.8 `pattern-expressions` → `# Pattern-Expressions Specification`
- [x] 3.9 `per-rule-trust` → `# Per-Rule-Trust Specification`
- [x] 3.10 `pretty-printing` → `# Pretty-Printing Specification`
- [x] 3.11 `shell-command-security-model` → `# Shell-Command-Security-Model Specification`
- [x] 3.12 `testing-strategy` → `# Testing-Strategy Specification`
- [x] 3.13 `trace-system` → `# Trace-System Specification`
- [x] 3.14 `trust-advisory-boxes` → `# Trust-Advisory-Boxes Specification`
- [x] 3.15 `trust-block-context` → `# Trust-Block-Context Specification`
- [x] 3.16 `trust-provenance` → `# Trust-Provenance Specification`
- [x] 3.17 `trust-ui-listing` → `# Trust-UI-Listing Specification`
- [x] 3.18 `trust-hashing` covered by §2 above.

## 4. Add `Contributor-only.` lead to contributor-spec Purposes

For each spec, prepend `Contributor-only. ` to the existing Purpose-section
prose. Do not change any other wording.

- [x] 4.1 `code-quality`
- [x] 4.2 `parser-engine-invariants`
- [x] 4.3 `testing-strategy`
- [x] 4.4 `test-infrastructure`
- [x] 4.5 `integration-test-coverage`
- [x] 4.6 `oracle-trace-testing`
- [x] 4.7 `migration-testing`
- [x] 4.8 `parser-bindings` (parser internals — uses `Expr<T>`/binding semantics in detail)
- [x] 4.9 `wordpart-source-spans`
- [x] 4.10 `span-coalescing`
- [x] 4.11 `expr-combinator-matching`
- [x] 4.12 `evaluator-error-handling`
- [x] 4.13 `v2-expr-fact-binding`
- [x] 4.14 `unified-renderer`
- [x] 4.15 `prelude-wrapper-parsers`
- [x] 4.16 `parameter-many-till`
- [x] 4.17 `var-trace-breakout`

(Some of these specs will be folded by the consolidation changes; the
hygiene pass still applies to them in the meantime so that intervening
edits and reviews see consistent declarations. Folded contents inherit the
declaration via the parent spec.)

## 5. Add `Trust-relevant: yes` to trust-affecting Purposes

For each spec, append a line `Trust-relevant: yes — see <ref>.` to the
existing Purpose-section prose. References named below.

- [x] 5.1 `per-rule-trust` — see `trust-store`, `trust-hashing`.
- [x] 5.2 `trust-hashing` — handled by §2 (Purpose written from scratch).
- [x] 5.3 `trust-provenance` — see `trust-store`, `trust-gate`.
- [x] 5.4 `trust-advisory-boxes` — see `trust-gate`, `trust-store`.
- [x] 5.5 `trust-ui-listing` — see `trust-command`, `trust-store`.
- [x] 5.6 `trust-block-context` — see `trust-gate`, `trust-store`.
- [x] 5.7 `interactive-trust-review` — see `trust-command`, `trust-hashing`.

## 6. Verify

- [x] 6.1 `for d in openspec/specs/*/; do head -1 "$d/spec.md"; done` —
  every line ends with `Specification`.
- [x] 6.2 `grep -rln '^## ADDED Requirements' openspec/specs/` returns
  empty.
- [x] 6.3 `openspec validate spec-hygiene --strict` (if available) passes.
- [x] 6.4 Every spec listed in §4 has the literal `Contributor-only.` token
  in its first 200 characters of `## Purpose`.
- [x] 6.5 Every spec listed in §5 has the literal `Trust-relevant: yes`
  token in its `## Purpose`.
