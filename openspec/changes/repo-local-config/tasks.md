## 1. Establish baselines

- [ ] 1.1 Capture current behaviour: run `may-i eval` against a fixture
      set of commands × representative configs. Save outputs to
      `tests/fixtures/repo-local-config/baseline/` (or extend existing
      snapshot infrastructure).
- [ ] 1.2 Catalogue all rules in test configs and the user's own
      config that depend on first-match-wins ordering (narrow rule
      followed by broader rule with different effect). Note in
      `design.md` open questions or fix in step 5.

## 2. Engine: most-strict-wins combine

- [ ] 2.1 Replace the early-return loop in
      `crates/engine/src/eval/entry.rs:126-143` with a fold that
      collects all matching rules' `EffectResult::Decision` outcomes,
      selects the maximum `Decision` under the existing `Ord` impl,
      and breaks ties on `reason` by earliest source order.
- [ ] 2.2 Preserve the no-match default (`Ask`) and the existing
      `any_command_matched` bookkeeping if it informs trace output.
- [ ] 2.3 Update the `first_matching_rule_wins` property test in
      `crates/engine/src/test_generators/effect_eval_tests.rs:413-446`
      to assert most-strict-wins; rename appropriately.
- [ ] 2.4 Add a property test: for any rule list and any command,
      shuffling the rule list does not change the resulting
      `Decision` (only `reason` may shift to a same-decision
      tie-breaker if multiple rules are at the most-strict level).
- [ ] 2.5 Add a property test: appending any rule to a config can
      only keep or increase strictness (never relax it).
- [ ] 2.6 Add unit tests covering the lattice corners explicitly:
      `Allow + Deny → Deny`; `Allow + Ask → Ask`; `Ask + Deny → Deny`;
      duplicates collapse; no-match → `Ask`.

## 3. Engine: trace and segment integration

- [ ] 3.1 Verify per-segment evaluation
      (`crates/engine/src/eval/...` — see `engine-segment-decisions`)
      still operates correctly: each segment independently combines
      under the new lattice rule.
- [ ] 3.2 Inspect trace-system output for any string containing "first
      matching rule"; reword to reflect combine semantics.
- [ ] 3.3 Surface tied-at-most-strict siblings in trace output: list
      every rule that contributed the most-strict effect, mark the
      one whose `reason` survived (earliest-in-source-order) as the
      reason source, and present the others as also-matched siblings.
- [ ] 3.4 Add a snapshot test for trace output showing two rules tied
      at `Deny` — both visible in the trace, only one marked as the
      reason source.

## 4. Resolver: repo-local discovery

- [ ] 4.1 Add `discover_repo_root(cwd: &Path) -> Option<PathBuf>` in
      `crates/config/src/io.rs` (or a new module). Implementation:
      shell out to `git rev-parse --show-toplevel`; on failure, walk
      ancestors for `.git` / `.hg` / `.jj` markers.
- [ ] 4.2 Add `discover_repo_local_files(repo_root: &Path) -> Vec<PathBuf>`
      that returns existing files in the documented order:
      `.may-i.lisp`, `.may-i/**/*.lisp` (sorted), `.may-i.local.lisp`,
      `.claude/may-i.lisp`, `.claude/may-i.local.lisp`.
- [ ] 4.3 Wire discovery into the load pipeline: after the primary
      config is loaded, splice discovered files in as if the primary
      ended with synthesised `(load …)` forms. Each rule's
      `Provenance::Loaded { path }` carries the actual repo-local
      file path.
- [ ] 4.4 Ensure cycle detection still functions if a repo-local file
      itself contains `(load …)` directives.
- [ ] 4.5 Discovery is silent on "no repo found" — tests confirm
      `may-i eval` invoked from `/tmp` behaves identically to today.
- [ ] 4.6 Plumb CWD into the resolver if not already available;
      default to `std::env::current_dir()`.

## 5. Migrate fixtures and audit

- [ ] 5.1 Update test configs that depend on first-match-wins
      ordering. Rewrite whitelist-exceptions inside a single rule's
      effect tree (e.g. `(if narrow-pred :allow :deny)`).
- [ ] 5.2 Re-run baseline fixture set; reconcile any drift between
      old and new outputs. Either the change is intentional (engine
      semantic shift) or a bug.
- [ ] 5.3 Run the user's own config through `may-i eval` for common
      commands and reconcile drift.

## 6. Trust integration

- [ ] 6.1 Verify discovered repo-local rules appear in
      `may-i trust` listing with their correct file paths.
- [ ] 6.2 Verify trust hash for a given rule is identical whether
      the rule was reached via `(load …)` or repo-local discovery
      (provenance carries the same canonical path; hash should match).
- [ ] 6.3 Add an integration test: a `.may-i.lisp` containing
      `(rule "rm" (effect :allow))` does not widen a primary
      `(rule "rm" (effect :deny ...))`, even after approval, because
      the lattice combine selects `Deny`.

## 7. Documentation

- [ ] 7.1 Update CLI help text for the resolver layer order.
- [ ] 7.2 Add a release note entry for the engine semantic change.
      Include before/after example. Recommend the rewrite for
      whitelist-exception users.
- [ ] 7.3 Update README (if present) with the discovered file set
      and a worked example of repo-local rules.
- [ ] 7.4 Suggest `.may-i.local.lisp` for `.gitignore` in
      documentation.

## 8. Coverage

- [ ] 8.1 Run `cargo tarpaulin`; confirm both `rule-combination` and
      `repo-local-config` capabilities are well-covered.
- [ ] 8.2 Add unit tests surgically for any uncovered branches in the
      combine fold or discovery walk.
- [ ] 8.3 Confirm proptest regressions under
      `**/proptest-regressions/` are committed.
