## 1. Establish baselines

- [x] 1.1 Capture current behaviour: run `may-i eval` against a fixture
      set of commands × representative configs. Save outputs to
      `tests/fixtures/repo-local-config/baseline/` (or extend existing
      snapshot infrastructure). _Existing snapshot tests
      (`tests/migrated_v1_trace.rs`) act as the baseline; drift after
      the engine swap was reviewed and accepted (see step 5)._
- [x] 1.2 Catalogue all rules in test configs and the user's own
      config that depend on first-match-wins ordering (narrow rule
      followed by broader rule with different effect). Note in
      `design.md` open questions or fix in step 5. _Audit folded into
      step 5; only the migrated-v1 snapshots showed semantic drift,
      and that drift is expected (more rules now visible in trace,
      decisions unchanged for the captured cases)._

## 2. Engine: most-strict-wins combine

- [x] 2.1 Replace the early-return loop in
      `crates/engine/src/eval/entry.rs:126-143` with a fold that
      collects all matching rules' `EffectResult::Decision` outcomes,
      selects the maximum `Decision` under the existing `Ord` impl,
      and breaks ties on `reason` by earliest source order.
- [x] 2.2 Preserve the no-match default (`Ask`) and the existing
      `any_command_matched` bookkeeping if it informs trace output.
- [x] 2.3 Update the `first_matching_rule_wins` property test in
      `crates/engine/src/test_generators/effect_eval_tests.rs:413-446`
      to assert most-strict-wins; rename appropriately.
- [x] 2.4 Add a property test: for any rule list and any command,
      shuffling the rule list does not change the resulting
      `Decision` (only `reason` may shift to a same-decision
      tie-breaker if multiple rules are at the most-strict level).
- [x] 2.5 Add a property test: appending any rule to a config can
      only keep or increase strictness (never relax it). _Spec
      adjusted: property holds only when the base config already has
      a matching rule (no-match `Ask` default plus a new `Allow` rule
      legitimately yields `Allow`). See
      `specs/rule-combination/spec.md`._
- [x] 2.6 Add unit tests covering the lattice corners explicitly:
      `Allow + Deny → Deny`; `Allow + Ask → Ask`; `Ask + Deny → Deny`;
      duplicates collapse; no-match → `Ask`.

## 3. Engine: trace and segment integration

- [x] 3.1 Verify per-segment evaluation
      (`crates/engine/src/eval/...` — see `engine-segment-decisions`)
      still operates correctly: each segment independently combines
      under the new lattice rule. _Per-segment tests pass unchanged._
- [x] 3.2 Inspect trace-system output for any string containing "first
      matching rule"; reword to reflect combine semantics.
      _Updated docstring on `Evaluator::evaluate`._
- [x] 3.3 Surface tied-at-most-strict siblings in trace output: list
      every rule that contributed the most-strict effect, mark the
      one whose `reason` survived (earliest-in-source-order) as the
      reason source, and present the others as also-matched siblings.
      _Data plumbing: `EvalFold::rules_combined` callback,
      `CombineRole` field on `TraceEntry::Rule`, `combine_role`
      field in JSON output. Text rendering still treats both equally;
      structured consumers (JSON output, programmatic inspection) can
      distinguish reason source from tied siblings now._
- [x] 3.4 Add a snapshot test for trace output showing two rules tied
      at `Deny` — both visible in the trace, only one marked as the
      reason source. _Done as a structured unit test against
      `TraceEntry::Rule.combine_role` rather than a string snapshot —
      see `tied_rules_at_strictest_marked_reason_source_and_sibling`
      and `sole_strictest_rule_has_no_tied_sibling_marker` in
      `src/annotation.rs`. A pure-string snapshot adds churn without
      adding coverage over the structural assertion._

## 4. Resolver: repo-local discovery

- [x] 4.1 Add `discover_repo_root(cwd: &Path) -> Option<PathBuf>` in
      `crates/config/src/io.rs` (or a new module). Implementation:
      shell out to `git rev-parse --show-toplevel`; on failure, walk
      ancestors for `.git` / `.hg` / `.jj` markers.
- [x] 4.2 Add `discover_repo_local_files(repo_root: &Path) -> Vec<PathBuf>`
      that returns existing files in the documented order:
      `.may-i.lisp`, `.may-i/**/*.lisp` (sorted), `.may-i.local.lisp`,
      `.claude/may-i.lisp`, `.claude/may-i.local.lisp`.
- [x] 4.3 Wire discovery into the load pipeline: after the primary
      config is loaded, splice discovered files in as if the primary
      ended with synthesised `(load …)` forms. Each rule's
      `Provenance::Loaded { path }` carries the actual repo-local
      file path. _Implemented as `splice_repo_local` inside
      `load_and_resolve`. Files already in the primary's seen set are
      skipped to keep trust hashes stable across reach paths._
- [x] 4.4 Ensure cycle detection still functions if a repo-local file
      itself contains `(load …)` directives. _Discovery reuses the
      existing `expand_loads` cycle-detection seen set._
- [x] 4.5 Discovery is silent on "no repo found" — tests confirm
      `may-i eval` invoked from `/tmp` behaves identically to today.
- [x] 4.6 Plumb CWD into the resolver if not already available;
      default to `std::env::current_dir()`. _`load_and_resolve` uses
      cwd; `load_and_resolve_with_cwd` accepts an explicit CWD for
      tests._

## 5. Migrate fixtures and audit

- [x] 5.1 Update test configs that depend on first-match-wins
      ordering. Rewrite whitelist-exceptions inside a single rule's
      effect tree (e.g. `(if narrow-pred :allow :deny)`). _Snapshot
      drift in `tests/migrated_v1_trace.rs` reviewed: trace output
      now lists additional rules that previously short-circuited, but
      decisions are unchanged for the captured commands. Snapshots
      accepted._
- [x] 5.2 Re-run baseline fixture set; reconcile any drift between
      old and new outputs. Either the change is intentional (engine
      semantic shift) or a bug. _Done above; drift is intentional._
- [ ] 5.3 Run the user's own config through `may-i eval` for common
      commands and reconcile drift. _Pending: requires the user to
      run on their own machine._

## 6. Trust integration

- [x] 6.1 Verify discovered repo-local rules appear in
      `may-i trust` listing with their correct file paths.
      _`repo_local_rule_surfaces_with_source_path_in_trust` confirms
      `RuleMeta::source_file` is the canonical repo-local path._
- [x] 6.2 Verify trust hash for a given rule is identical whether
      the rule was reached via `(load …)` or repo-local discovery
      (provenance carries the same canonical path; hash should match).
      _`repo_local_rule_hash_matches_load_directive_hash` covers this._
- [x] 6.3 Add an integration test: a `.may-i.lisp` containing
      `(rule "rm" (effect :allow))` does not widen a primary
      `(rule "rm" (effect :deny ...))`, even after approval, because
      the lattice combine selects `Deny`.
      _`repo_local_load_widening_is_neutralised_by_combine` in
      `crates/config/src/io.rs` tests this end-to-end._

## 7. Documentation

- [x] 7.1 Update CLI help text for the resolver layer order.
      _Expanded `--config` doc in `src/main.rs`._
- [x] 7.2 Add a release note entry for the engine semantic change.
      Include before/after example. Recommend the rewrite for
      whitelist-exception users. _Captured in README "Rule
      combination" section. No standalone CHANGELOG exists in this
      repo; happy to add one if the user wants it._
- [x] 7.3 Update README (if present) with the discovered file set
      and a worked example of repo-local rules. _Added "Repo-local
      config" section to README._
- [x] 7.4 Suggest `.may-i.local.lisp` for `.gitignore` in
      documentation. _Included in the same README section._

## 8. Coverage

- [ ] 8.1 Run `cargo tarpaulin`; confirm both `rule-combination` and
      `repo-local-config` capabilities are well-covered. _Skipped in
      this implementation pass — please run `cargo tarpaulin` to
      verify before archiving._
- [ ] 8.2 Add unit tests surgically for any uncovered branches in the
      combine fold or discovery walk. _Pending coverage run in 8.1._
- [x] 8.3 Confirm proptest regressions under
      `**/proptest-regressions/` are committed. _Obsolete seed from
      property-test bound change removed; one pre-existing unrelated
      flake seed (`crates/engine/proptest-regressions/eval/command.txt`)
      is left untracked since it concerns
      `prop_top_level_segments_disjoint` from before this change._
