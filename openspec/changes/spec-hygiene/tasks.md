## 1. Add new requirement to `spec-conventions`

- [ ] 1.1 Add `### Requirement: Spec names use user vocabulary` to
  `openspec/specs/spec-conventions/spec.md`, after the existing audience
  requirement (Requirement 3). Wording must explicitly exempt (a) the meta-
  spec `spec-conventions` itself and (b) contributor-only specs (audience
  declared in Purpose) from the user-vocabulary constraint.
- [ ] 1.2 Add `#### Scenario:` blocks covering: a user-facing spec named
  with contributor vocabulary (FAILS), a contributor spec named with
  contributor vocabulary (OK because audience declared), the meta-spec named
  `spec-conventions` (OK by exemption).
- [ ] 1.3 Update `.claude/rules/openspec-specs.md` checklist to add a bullet
  referencing the new requirement.

## 2. Restructure `trust-hashing` to canonical headings

- [ ] 2.1 Replace the leading `## ADDED Requirements` line with the canonical
  scaffold: `# Trust-Hashing Specification`, `## Purpose` (write Purpose;
  declare `Trust-relevant: yes` and cross-ref `trust-store`, `trust-command`,
  `trust-provenance`), `## Requirements`.
- [ ] 2.2 Verify all 8 `### Requirement: ...` blocks survive verbatim and
  retain their `#### Scenario:` children.

## 3. Insert canonical `# X Specification` title in 18 specs

For each spec below, insert a new line 1 reading
`# <Spec-Name> Specification` (capital initials, hyphens preserved); push
existing content down. Do not touch any `## Purpose` or `## Requirements`
content.

- [ ] 3.1 `code-quality` → `# Code-Quality Specification`
- [ ] 3.2 `fact-system` → `# Fact-System Specification`
- [ ] 3.3 `human-evaluation-trace` → `# Human-Evaluation-Trace Specification`
- [ ] 3.4 `interactive-trust-review` → `# Interactive-Trust-Review Specification`
- [ ] 3.5 `migration-system` → `# Migration-System Specification`
- [ ] 3.6 `migration-testing` → `# Migration-Testing Specification`
- [ ] 3.7 `parser-engine-invariants` → `# Parser-Engine-Invariants Specification`
- [ ] 3.8 `pattern-expressions` → `# Pattern-Expressions Specification`
- [ ] 3.9 `per-rule-trust` → `# Per-Rule-Trust Specification`
- [ ] 3.10 `pretty-printing` → `# Pretty-Printing Specification`
- [ ] 3.11 `shell-command-security-model` → `# Shell-Command-Security-Model Specification`
- [ ] 3.12 `testing-strategy` → `# Testing-Strategy Specification`
- [ ] 3.13 `trace-system` → `# Trace-System Specification`
- [ ] 3.14 `trust-advisory-boxes` → `# Trust-Advisory-Boxes Specification`
- [ ] 3.15 `trust-block-context` → `# Trust-Block-Context Specification`
- [ ] 3.16 `trust-provenance` → `# Trust-Provenance Specification`
- [ ] 3.17 `trust-ui-listing` → `# Trust-UI-Listing Specification`
- [ ] 3.18 `trust-hashing` covered by §2 above.

## 4. Add `Contributor-only.` lead to contributor-spec Purposes

For each spec, prepend `Contributor-only. ` to the existing Purpose-section
prose. Do not change any other wording.

- [ ] 4.1 `code-quality`
- [ ] 4.2 `parser-engine-invariants`
- [ ] 4.3 `testing-strategy`
- [ ] 4.4 `test-infrastructure`
- [ ] 4.5 `integration-test-coverage`
- [ ] 4.6 `oracle-trace-testing`
- [ ] 4.7 `migration-testing`
- [ ] 4.8 `parser-bindings` (parser internals — uses `Expr<T>`/binding semantics in detail)
- [ ] 4.9 `wordpart-source-spans`
- [ ] 4.10 `span-coalescing`
- [ ] 4.11 `expr-combinator-matching`
- [ ] 4.12 `evaluator-error-handling`
- [ ] 4.13 `v2-expr-fact-binding`
- [ ] 4.14 `unified-renderer`
- [ ] 4.15 `prelude-wrapper-parsers`
- [ ] 4.16 `parameter-many-till`
- [ ] 4.17 `var-trace-breakout`

(Some of these specs will be folded by the consolidation changes; the
hygiene pass still applies to them in the meantime so that intervening
edits and reviews see consistent declarations. Folded contents inherit the
declaration via the parent spec.)

## 5. Add `Trust-relevant: yes` to trust-affecting Purposes

For each spec, append a line `Trust-relevant: yes — see <ref>.` to the
existing Purpose-section prose. References named below.

- [ ] 5.1 `per-rule-trust` — see `trust-store`, `trust-hashing`.
- [ ] 5.2 `trust-hashing` — handled by §2 (Purpose written from scratch).
- [ ] 5.3 `trust-provenance` — see `trust-store`, `trust-gate`.
- [ ] 5.4 `trust-advisory-boxes` — see `trust-gate`, `trust-store`.
- [ ] 5.5 `trust-ui-listing` — see `trust-command`, `trust-store`.
- [ ] 5.6 `trust-block-context` — see `trust-gate`, `trust-store`.
- [ ] 5.7 `interactive-trust-review` — see `trust-command`, `trust-hashing`.

## 6. Verify

- [ ] 6.1 `for d in openspec/specs/*/; do head -1 "$d/spec.md"; done` —
  every line ends with `Specification`.
- [ ] 6.2 `grep -rln '^## ADDED Requirements' openspec/specs/` returns
  empty.
- [ ] 6.3 `openspec validate spec-hygiene --strict` (if available) passes.
- [ ] 6.4 Every spec listed in §4 has the literal `Contributor-only.` token
  in its first 200 characters of `## Purpose`.
- [ ] 6.5 Every spec listed in §5 has the literal `Trust-relevant: yes`
  token in its `## Purpose`.
