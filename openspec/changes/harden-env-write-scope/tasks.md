## 1. Parser: surface assignment scope

- [ ] 1.1 Write failing tests: parsing distinguishes a command-prefix assignment, a declaration-builtin scalar/array arg, an `-x`-exported declaration, and a bare assignment-only command; `set -a` / `set -o allexport` state is recoverable.
- [ ] 1.2 Extend the assignment / simple-command AST to carry scope (prefix vs declaration-arg, exported vs shell-local) without disturbing existing `ArrayKind` recording.
- [ ] 1.3 Populate the new scope info in `crates/shell-parser/src/parse.rs`; keep the declaration-array lift but tag it shell-local unless `-x` is present.
- [ ] 1.4 Detect `set -a` / `set -o allexport` (and `set +a`) as a scoped flag over the AST: active for assignments in its own and nested scopes; cleared by `set +a`; barrier-scoped by `Subshell`/pipeline-component/`Background`/`CommandSubstitution` but NOT `BraceGroup`. Conservative toward flooring; document the `SHELLOPTS` pre-activation limitation.

## 2. Entry environment input

- [ ] 2.1 Write failing tests for a names-only, immutable entry-environment type (presence query; no value accessor).
- [ ] 2.2 Add the entry-environment type and thread it through evaluation alongside `ContextFacts`; default empty.
- [ ] 2.3 Capture `std::env` names in `may-i hook` as the first action, before git-env scrubbing; confirm via test that a name exported at entry survives scrubbing in the snapshot.
- [ ] 2.4 Add `--env NAME` (repeatable) and `--inherit-env` to `may-i eval`; default empty; verify combinability.
- [ ] 2.5 Confirm `may-i check` never reads `std::env` (hermetic): a test asserting host-env independence.

## 3. Reframe the env-write floor

- [ ] 3.1 Write failing tests (proptest + targeted unit) for the spec scenarios: export/`declare -x` floor; shell-local array/`declare`/bare-non-entry-env do not floor; bare reassignment of an entry-env name floors; prefix still floors.
- [ ] 3.2 In `crates/engine/src/eval/decompose.rs`, stop emitting `EnvPrefix` for every assignment; emit the floor only for reaching writes, consulting the entry environment for the bare-reassignment case and `set -a` state.
- [ ] 3.3 Ensure embedded substitutions in assignment values are still extracted for shell-local writes (decoupled from the floor decision).

## 4. `(scope …)` predicate

- [ ] 4.1 Write failing tests: `(env NAME (when (scope reaches-child) …))` matches a prefix and a bare entry-env reassignment, and does not match a shell-local bare assignment; raw `prefix`/`export`/`bare` values resolve.
- [ ] 4.2 Add the `(scope …)` predicate to the env-decision sub-language (config parse + eval); reject it outside `(env …)` decisions.
- [ ] 4.3 Verify canonical-form/hash handling for `(env …)` forms carrying `(scope …)`; add a migration if any prelude/example config adopts it.

## 5. Check simulation and advisory

- [ ] 5.1 Write failing tests: `(with-env [NAME …] …)` parses, nests, merges by union, and composes with `(with-facts …)`.
- [ ] 5.2 Implement `(with-env …)` in the check-case DSL and runner.
- [ ] 5.3 Write a failing test for the untested-scope-rule advisory at `warn` level that does not fail the run.
- [ ] 5.4 Implement the advisory: scope-dependent env rule with no `(with-env …)` coverage for its name.

## 6. Trace attribution

- [ ] 6.1 Write a failing test: a decision tipped by entry-environment presence renders the name + presence, never a value; a shell-local write produces no entry-env annotation.
- [ ] 6.2 Implement the entry-environment contribution line in trace rendering.

## 7. Documentation and vocabulary

- [ ] 7.1 Add "entry environment" to the user vocabulary in `CONTEXT.md` and `openspec/config.yaml:context`.
- [ ] 7.2 REFERENCE.md (the shipped `may-i reference` manual): document the reaching-write floor, `(scope …)`, `(with-env …)`, and `--env`/`--inherit-env`; or record "verified, no surface change" if covered elsewhere.
- [ ] 7.3 Update CHANGELOG with the BREAKING note (shell-local writes no longer floor) and the closed `export`/`declare -x` hole.
- [ ] 7.4 Update `examples/`/`starter_config.lisp` if any rely on the old shape-keyed behaviour; run `may-i fmt` on touched `.lisp`.

## 8. Verification

- [ ] 8.1 `cargo fmt` and `cargo test` green; the original probes (`declare -A m=([k]=v)` → `:allow`, `export LD_PRELOAD=/evil.so; echo hi` → `:ask`) behave per spec.
- [ ] 8.2 `cargo tarpaulin`; inspect `lcov.info` for uncovered new branches; add proptests/units for gaps.
- [ ] 8.3 `openspec validate harden-env-write-scope`, `scripts/validate-spec-frontmatter.sh`, and `scripts/validate-change-doc-sync.sh` pass via `prek`.
