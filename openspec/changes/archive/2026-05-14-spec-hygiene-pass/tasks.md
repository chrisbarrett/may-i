## 1. Sharpen `spec-conventions` rule for merges

- [x] 1.1 Apply the `MODIFIED Requirements` delta in `specs/spec-conventions/spec.md` to `openspec/specs/spec-conventions/spec.md`: replace the existing "Capability renames are filesystem moves driven by tasks.md" requirement body (and its 2 scenarios) with the merge-aware version (3 scenarios). Other requirements in the file unchanged.
- [x] 1.2 Run `scripts/validate-spec-frontmatter.sh` — passes.

## 2. Audience corrections

- [x] 2.1 `openspec/specs/trust-gate/spec.md`: frontmatter `audience: user` → `audience: contributor`. Bucket stays `trust` (contributor specs may sit in any bucket per `spec-conventions` §"Each spec belongs to one documented bucket"). Strip leading `Contributor-only. ` from the Purpose section's first sentence.
- [x] 2.2 `openspec/specs/traces/spec.md`: frontmatter `audience: user` → `audience: contributor`. Bucket stays `tracing-and-output` until §3.2 moves it.
- [x] 2.3 `openspec/specs/parser-bindings/spec.md`: keep frontmatter `audience: user`. Strip leading `Contributor-only. ` from the Purpose section's first sentence (it is a stray copy-paste — see design.md).
- [x] 2.4 Run `scripts/validate-spec-frontmatter.sh` — passes.

## 3. Bucket corrections

- [x] 3.1 `openspec/specs/fact-predicates-in-args/spec.md`: frontmatter `bucket: parsing` → `bucket: contributor-internals` (content is the internal `BoolExpr` enum; audience is already `contributor`).
- [x] 3.2 `openspec/specs/traces/spec.md`: frontmatter `bucket: tracing-and-output` → `bucket: contributor-internals` (content covers `TracingFold` / `EvalFold` internals; audience flipped in §2.2).
- [x] 3.3 `openspec/specs/pretty-printing/spec.md`: frontmatter `bucket: tracing-and-output` → `bucket: cli` (governs `may-i fmt` output, not eval traces).
- [x] 3.4 Run `scripts/validate-spec-frontmatter.sh` — passes.

## 4. Retired `(effect …)` surface-syntax sweep

Replace surface-DSL `(effect :allow [REASON])` / `(effect :ask [REASON])` / `(effect :deny [REASON])` with `(allow [REASON])` / `(ask [REASON])` / `(deny [REASON])` in scenario examples. Internal AST references (`Effect::Terminal`, `Decision::Allow`) in contributor-audience specs stay unchanged.

`migration-system` legitimately quotes v1 syntax in its scenarios — DO NOT rewrite that file. `dsl-form-list-syntax` is folded in §7 — defer touch-ups to that group.

- [x] 4.1 `openspec/specs/rule-combination/spec.md` — sweep scenarios.
- [x] 4.2 `openspec/specs/rule-decisions/spec.md` — sweep scenarios.
- [x] 4.3 `openspec/specs/per-rule-trust/spec.md` — sweep scenarios.
- [x] 4.4 `openspec/specs/repo-local-config/spec.md` — sweep scenarios.
- [x] 4.5 `openspec/specs/trust-command/spec.md` — sweep scenarios.
- [x] 4.6 `openspec/specs/harness-integration/spec.md` — sweep scenarios.
- [x] 4.7 `openspec/specs/decision-trace/spec.md` — no sweep needed; the file's lone hit (line 107) is an intentional reference to the legacy form being rejected by the trace renderer.
- [x] 4.8 `openspec/specs/fmt-command/spec.md` — no sweep needed; both hits (lines 121, 131) are intentional references to the legacy form being rejected by `may-i fmt`'s strict canonical loader.
- [x] 4.9 `openspec/specs/patterns/spec.md` — sweep scenarios.
- [x] 4.10 Also swept (not originally listed): `trust-hashing`, `fact-predicates-in-args`, `traces` — they carried scenario-level `(effect :…)` examples that fell under the same sweep rule. Verify: `rg -F '(effect :' openspec/specs/` returns hits only in `migration-system/spec.md` (v1 quotes), `fmt-command/spec.md` (legacy-rejection example), `decision-trace/spec.md` (legacy-rejection reference), and `dsl-form-list-syntax/spec.md` (folded in §7).

## 5. Trust merges (per-rule-trust + trust-provenance → trust-store)

Per the sharpened §1 rule: this is an N:1 absorption driven by `tasks.md`. No `## ADDED Requirements` / `## REMOVED Requirements` blocks under `openspec/changes/spec-hygiene-pass/specs/trust-store/`.

- [x] 5.1 Append the 3 `### Requirement: …` blocks from `openspec/specs/per-rule-trust/spec.md` verbatim (heading + body + all `#### Scenario:` children) into `openspec/specs/trust-store/spec.md`, after the existing requirements.
- [x] 5.2 Append the requirements from `openspec/specs/trust-provenance/spec.md` verbatim into `openspec/specs/trust-store/spec.md`.
- [x] 5.3 Refresh `trust-store`'s Purpose section to cover: hash storage (existing), per-rule granularity (from per-rule-trust), and source-path provenance (from trust-provenance). Keep `trust-relevant: true`. Update "See related trust specs" line — `per-rule-trust` and `trust-provenance` references removed.
- [x] 5.4 `rm -rf openspec/specs/per-rule-trust/`.
- [x] 5.5 `rm -rf openspec/specs/trust-provenance/`.
- [x] 5.6 Cross-reference sweep: `rg -lF 'per-rule-trust\|trust-provenance' openspec/ .claude/ CONTEXT.md CLAUDE.md` — repoint each hit to `trust-store`.

## 6. Rules merge (rule-combination → rule-decisions)

- [x] 6.1 Append the `### Requirement: …` blocks from `openspec/specs/rule-combination/spec.md` verbatim into `openspec/specs/rule-decisions/spec.md`, after the existing requirements.
- [x] 6.2 Refresh `rule-decisions` Purpose to absorb the combination-lattice content (single paragraph; the existing Purpose already mentions "combines them into a single Decision", so just note the lattice ordering `Allow < Ask < Deny` and the order-independence guarantee from rule-combination).
- [x] 6.3 `rm -rf openspec/specs/rule-combination/`.
- [x] 6.4 Cross-reference sweep: `rg -lF 'rule-combination' openspec/ .claude/ CONTEXT.md CLAUDE.md` — repoint to `rule-decisions`.

## 7. Parser merge (dsl-form-list-syntax → parser-bindings)

Both specs are `audience: user, bucket: parsing` after §2.3. `parser-bindings` is the larger surviving spec.

- [x] 7.1 Append the `### Requirement: …` blocks from `openspec/specs/dsl-form-list-syntax/spec.md` verbatim into `openspec/specs/parser-bindings/spec.md`, after the existing requirements.
- [x] 7.2 Apply the §4 retired-`(effect …)` sweep to the absorbed dsl-form-list-syntax content as part of this step (it had `(effect :…)` references in its scenarios).
- [x] 7.3 Refresh `parser-bindings` Purpose to cover: per-program parser declarations (existing), the form-list calling convention for `(parser …)` / `(define-arg-style …)` / `(check …)` bodies (from dsl-form-list-syntax), and the surface syntax for decision verbs (`(allow)`, `(ask)`, `(deny)`) and `(authorise)`.
- [x] 7.4 `rm -rf openspec/specs/dsl-form-list-syntax/`.
- [x] 7.5 Cross-reference sweep: `rg -lF 'dsl-form-list-syntax' openspec/ .claude/ CONTEXT.md CLAUDE.md` — repoint to `parser-bindings`.

## 8. Testing merges (oracle-trace-testing + test-infrastructure → testing-strategy)

- [x] 8.1 Append the `### Requirement: …` blocks from `openspec/specs/oracle-trace-testing/spec.md` verbatim into `openspec/specs/testing-strategy/spec.md`.
- [x] 8.2 Append the `### Requirement: …` blocks from `openspec/specs/test-infrastructure/spec.md` verbatim into `openspec/specs/testing-strategy/spec.md`.
- [x] 8.3 Refresh `testing-strategy` Purpose to cover: property-tests-first strategy (existing), shared integration-test helpers + env-mutation safety (from test-infrastructure), and the oracle-trace snapshot harness (from oracle-trace-testing).
- [x] 8.4 `rm -rf openspec/specs/oracle-trace-testing/`.
- [x] 8.5 `rm -rf openspec/specs/test-infrastructure/`.
- [x] 8.6 Cross-reference sweep: `rg -lF 'oracle-trace-testing\|test-infrastructure' openspec/ .claude/ CONTEXT.md CLAUDE.md` — repoint to `testing-strategy`.

## 9. Migration merge (migration-diff-display → migration-system)

- [x] 9.1 Append the `### Requirement: …` blocks from `openspec/specs/migration-diff-display/spec.md` verbatim into `openspec/specs/migration-system/spec.md`.
- [x] 9.2 Add one sentence to `migration-system` Purpose noting that diff-display behaviour (HOME-rewritten file-path header, NO_COLOR-respecting unified diff, interactive `[y/N]` confirm) is also documented here.
- [x] 9.3 `rm -rf openspec/specs/migration-diff-display/`.
- [x] 9.4 Cross-reference sweep: `rg -lF 'migration-diff-display' openspec/ .claude/ CONTEXT.md CLAUDE.md` — repoint to `migration-system`.

## 10. Verification

- [x] 10.1 `scripts/validate-spec-frontmatter.sh` passes.
- [x] 10.2 `openspec validate spec-hygiene-pass --strict` passes.
- [x] 10.3 `rg -lF 'per-rule-trust\|trust-provenance\|rule-combination\|dsl-form-list-syntax\|oracle-trace-testing\|test-infrastructure\|migration-diff-display' openspec/specs/ .claude/ CONTEXT.md CLAUDE.md` returns no hits.
- [x] 10.4 `rg -F '(effect :' openspec/specs/` returns hits only in `openspec/specs/migration-system/spec.md` (v1 quotes), `openspec/specs/fmt-command/spec.md` (legacy-rejection example), `openspec/specs/decision-trace/spec.md` (legacy-rejection reference), and `openspec/specs/parser-bindings/spec.md` (legacy-rejection reference, absorbed from dsl-form-list-syntax in §7). All four uses are intentional, surfacing the *retired* legacy form to the reader.
- [x] 10.5 Spec count: `ls openspec/specs/ | wc -l` reports 24 (was 31; -7 absorbed, no new).
- [x] 10.6 Each absorbed requirement appears exactly once in its new home (manual grep per merge target).
- [x] 10.7 `prek run --all-files` (or `pre-commit run --all-files`) passes.
- [x] 10.8 `cargo fmt --check` passes (no code touched, but cheap to verify clean tree).
