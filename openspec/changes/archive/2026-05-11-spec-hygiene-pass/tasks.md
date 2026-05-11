## 1. Pre-flight checks

- [x] 1.1 Confirmed no live specs or in-flight changes reference the three doomed capabilities. Grep hits were limited to the three live specs themselves (being deleted) and two archived change proposals that originally created them — historical, not active dependencies
- [x] 1.2 Confirmed `dsl-form-list-syntax` covers the behavioural rules from `arg-tokenisation` worth keeping: `(style NAME)`, `(flag NAME)`, `(parameter NAME …)`, `(define-arg-style …)` attribute forms, `(pun KEYWORD)`, `(authorise)` recursion. Rules about engine behaviour (default-style fallback, parser-applies-to-evaluated-command, trace surfacing) live in the parser engine and trace specs, not the DSL surface
- [x] 1.3 Confirmed no Rust code references the capability names. `rg` over `src crates tests` returned no hits

## 2. Delete the live specs

- [x] 2.1 `git rm -r openspec/specs/arg-tokenisation`
- [x] 2.2 `git rm -r openspec/specs/config-load-surface`
- [x] 2.3 `git rm -r openspec/specs/review-followup`

## 3. Validate

- [x] 3.1 `openspec validate spec-hygiene-pass --strict` → "Change 'spec-hygiene-pass' is valid"
- [x] 3.2 Spec count 49 (was 51 before adding `spec-conventions` and removing the three here). All three capability names confirmed absent from `openspec/specs/`
- [x] 3.3 `cargo build --workspace` → clean. Skipped `cargo test` as deletions are docs-only and `cargo build` confirms no compile-time dependency on the removed paths

## 4. Land

- [x] 4.1 Commit on `main` directly (no worktree this pass, per user direction)
- [ ] 4.2 Run `openspec archive spec-hygiene-pass -y` to archive the change
- [ ] 4.3 Next hygiene pass: open `spec-hygiene-format` to normalise the 22 delta-format stable specs to canonical heading structure. Coordinate timing with `parser-named-bindings` and `order-independent-rules` so neither rewrites a spec we just normalised
