## 1. Pre-flight checks

- [ ] 1.1 Confirm no live specs or in-flight changes reference the three doomed capabilities by name. Run `rg -n 'arg-tokenisation|config-load-surface|review-followup' openspec/specs openspec/changes` and inspect each hit
- [ ] 1.2 Confirm the `dsl-form-list-syntax` spec covers every behavioural rule worth keeping from `arg-tokenisation` (style declaration, parser declaration, recursion verb, pun policy)
- [ ] 1.3 Confirm no Rust code references the capability names in comments or docs. Run `rg -n 'arg-tokenisation|config-load-surface|review-followup' src crates tests` and resolve any hits

## 2. Delete the live specs

- [ ] 2.1 `git rm -r openspec/specs/arg-tokenisation`
- [ ] 2.2 `git rm -r openspec/specs/config-load-surface`
- [ ] 2.3 `git rm -r openspec/specs/review-followup`

## 3. Validate

- [ ] 3.1 `openspec validate spec-hygiene-pass --strict` — change file structure is valid
- [ ] 3.2 `openspec list --specs` — confirm the live spec count drops by three and the three names are gone
- [ ] 3.3 `cargo build && cargo test --workspace` — sanity check; deletions are docs-only but verify nothing depended on these via integration tests

## 4. Land

- [ ] 4.1 Commit the spec deletions plus the change artefacts together on the worktree branch, then merge into main locally
- [ ] 4.2 Run `openspec archive spec-hygiene-pass -y` to archive the change. `--skip-specs` is not needed here because the delta files only contain `## REMOVED Requirements` entries — auto-archive will apply the removals correctly
- [ ] 4.3 Next hygiene pass: open `spec-hygiene-format` to normalise the 22 delta-format stable specs to canonical heading structure. Coordinate timing with `parser-named-bindings` and `order-independent-rules` so neither rewrites a spec we just normalised
