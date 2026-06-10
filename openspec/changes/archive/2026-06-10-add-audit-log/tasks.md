## 1. Config form: `(audit …)` parsing + provenance rejection

- [x] 1.1 Write a failing test: `(audit (threshold :ask) (file "x.jsonl"))` in primary config parses to an `AuditConfig { threshold: Ask, file: Some(...) }` field on `Config`.
- [x] 1.2 Add the `AuditConfig` type (engine/core) with an `AuditThreshold` enum (`Off`/`Deny`/`Ask`/`All`) and a `Config.audit` field; default `Off`.
- [x] 1.3 Add the `"audit"` arm to the top-level form dispatch in `crates/config/src/config.rs`; parse the head-keyed `(threshold :KW)` / `(file "…")` sub-forms.
- [x] 1.4 Failing test: `(audit (threshold :loud))` is a load error naming `:off`/`:deny`/`:ask`/`:all`. Implement the closed-set keyword validation.
- [x] 1.5 Failing test: an `(audit …)` form arriving with `Provenance::Loaded` (via `parse_config_from_tagged_sexprs`) is a hard load error stating primary-config-only. Implement the provenance guard.
- [x] 1.6 Failing test: the same form in a discovered repo-local file is rejected with the same error (covered by the `Provenance::Loaded` guard — repo-local discovery tags forms `Loaded`).

## 2. Engine: deciding-rule hash capture

- [x] 2.1 Failing test: `AuditFold` records the canonical-form hash of the rule(s) at `tied_match_indices` and nothing else, across a strictest-wins evaluation with multiple matches.
- [x] 2.2 Implement `AuditFold` in the engine crate using `rule_matched` (capture `index → hash_rule(canonical_rule(rule))`) and `rules_combined` (retain tied subset).
- [x] 2.3 Failing test: `ComposedFold<A, B>` delegates every `EvalFold` method to both halves and pairs the `EffectOut`/`PredicateOut` types; result equals each half run alone.
- [x] 2.4 Implement the `ComposedFold` combinator.

## 3. Audit record type + serialisation

- [x] 3.1 Failing test: an `AuditRecord` serialises to one line of JSON carrying `v`, `ts`, `mode`, `harness`, `command`, `decision`, `reason`, `source`, `parse_ok`, `diagnostic`, `rules`, `config`, `cwd` with the documented null/absent rules.
- [x] 3.2 Implement `AuditRecord` + serde serialisation; pin `v = 1`.
- [x] 3.3 Failing test: a parse-failure outcome yields `source = "parse-floor"`, `parse_ok = false`, and a non-null `diagnostic`; a trust block yields `source = "trust-block"`; a rule denial yields `source = "rule"` with a populated `rules` array.

## 4. Settings resolution (precedence)

- [x] 4.1 Failing test: per-field resolution `flag > env > form > default` — overriding `threshold` leaves `file` at its form/default value.
- [x] 4.2 Add `--audit-threshold` / `--audit-file` global flags in `src/main.rs` and read `MAYI_AUDIT_THRESHOLD` / `MAYI_AUDIT_FILE`.
- [x] 4.3 Implement the resolver producing an effective `AuditConfig`; CLI/env threshold parsed from bare strings (`ask`), form value from keyword.
- [x] 4.4 Failing test: with no flags and `MAYI_AUDIT_THRESHOLD=deny`, hook mode records denials — resolver-level coverage here; end-to-end hook emission asserted in §6.

## 5. File writer

- [x] 5.1 Failing test: default path resolves to `$XDG_STATE_HOME/may-i/audit.jsonl`, falling back to `~/.local/state/may-i/audit.jsonl` when unset.
- [x] 5.2 Implement path resolution + directory create (`0700`) + file open (`0600`).
- [x] 5.3 Failing test: a record is appended as one complete line in a single `O_APPEND` write; a second concurrent write does not interleave (simulate two writers).
- [x] 5.4 Failing test (failure isolation): an unwritable target does not raise, does not change the returned decision, and does not change the exit code. Implement the error-swallowing boundary.

## 6. Pipeline wiring

- [x] 6.1 Failing test: `run_eval` emits a record on the normal closure outcome AND on the `TrustBlock` short-circuit, gated by threshold.
- [x] 6.2 Failing test: `run_hook` emits on both exits; the trust-block record has `source = "trust-block"`.
- [x] 6.3 Failing test: `run_check` emits nothing at any threshold.
- [x] 6.4 Add a single private `CommandPipeline` emit method; call it before each return in `run_eval`/`run_hook`; thread the effective `AuditConfig`.
- [x] 6.5 Switch `cmd_hook` to run `AuditFold` and `cmd_eval` to run `ComposedFold<TracingFold, AuditFold>` instead of the bare `PureFold` / lone `TracingFold`; extract the deciding-rule hashes into the record.

## 7. Formatter + canonical form

- [x] 7.1 Failing test: `may-i fmt` round-trips an `(audit …)` form (sub-forms sorted per the canonical-ordering rule for non-curated forms).
- [x] 7.2 Teach `crates/config/src/canonicalise.rs` and the formatter about the `(audit …)` form.

## 8. Threshold selection semantics

- [x] 8.1 Failing proptest: for every (threshold, decision, parse_ok) combination, a record is written iff the decision meets the threshold OR the command failed to parse.
- [x] 8.2 Implement the threshold predicate; wire it into the emit gate from 6.4.

## 9. Docs + coverage

- [x] 9.1 Add the `(audit …)` form to the DSL reference (`may-i reference` / `cmd_help`) and an `examples/*.lisp` entry; run `may-i fmt` on it.
- [x] 9.2 Document the file location, `0600` secret-surface note, `logrotate`/`copytruncate` rolling guidance, and the NFS caveat in user docs.
- [x] 9.3 Run `cargo fmt`, `cargo test`, and `cargo tarpaulin`; inspect `lcov.info` for uncovered audit code and close gaps with unit tests where a proptest can't reach. (Overall 91.11%; all audit modules ~100%, ComposedFold delegations covered via an equivalence test over rich rule bodies.)
