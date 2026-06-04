## Context

`may-i` evaluates a command and exits; the outcome is gone once the process
ends. Users want a durable, queryable trail of what was denied, asked about, or
failed to parse. The decision pipeline already has a single seam
(`CommandPipeline`) through which the three invocation modes funnel
(`run_eval`, `run_check`, `run_hook`), and the evaluator is already
parameterised over an `EvalFold` — `evaluate_command` is literally
`evaluate_command_with_fold(…, &mut PureFold)`. Both facts make an audit trail
a layering problem rather than an engine change.

Constraints that shape the design:

- Hook mode is JSON-only and stdin-driven (no CLI flags), and a `deny` is
  signalled by exit code 2 fed back to the harness. Audit writing must never
  perturb that contract.
- The `(load …)` graph and repo-local discovery merge external rules as
  `Provenance::Loaded`. Operational config that controls a security trail must
  not be settable from those sources.
- `TracingFold` builds a renderable `Doc`/`TraceEntry` tree; hook mode never
  renders a Trace, so the hook path must not pay trace-tree cost.

This design references `audit-log/spec.md` for the normative requirements and
`proposal.md` for motivation. Audience: contributor.

## Goals / Non-Goals

**Goals:**

- A persisted, append-only JSONL audit trail of Eval and Hook outcomes,
  selected by a single decision threshold.
- Deciding-rule canonical-form hashes in every record from v1, captured
  uniformly on both the eval and hook paths.
- Operational config (`(audit …)` form + env + CLI) that cannot be hijacked by
  a loaded source.
- Best-effort writing that is provably decision- and exit-code-neutral.

**Non-Goals:**

- A severity-graded diagnostic logger for `may-i`'s own internals (that is
  `RUST_LOG`/`tracing` territory; explicitly rejected — see Decisions).
- Embedding the rendered Trace in records (kept out to avoid re-blurring the
  Trace/audit distinction; records stay greppable scalars + a hash array).
- Log rotation inside `may-i` (delegated to `logrotate`; see Decisions).
- Recording Check outcomes (synthetic replay; never blocks).

## Decisions

### D1 — Audit trail, not a severity logger; one `:threshold` knob

The targets (parse-fail / ask / deny) are evaluation *outcomes*, not internal
severity events, so the selector is a **decision threshold**
(`:off` ⊂ `:deny` ⊂ `:ask` ⊂ `:all`), not a `debug/info/warn` level. Parse
failures are always recorded at any non-`:off` threshold because a parse
failure floors the decision to `:ask` and is exactly the forensic case wanted.
A single `:threshold` collapses the redundant `enabled`+`level` pair — `:off`
is the disabled state.

_Alternatives:_ a classic log-level (rejected: cannot express "asks and denies
but not allows"); an explicit include-set `[:deny :ask :parse-fail]` (rejected:
more surface for a knob nobody tunes that precisely).

### D2 — Option A: `AuditFold` + `ComposedFold`, in the engine crate

Capture deciding-rule hashes through the existing `EvalFold` seam:

- `AuditFold` (new, engine crate, beside `canonical_rule`/`hash_rule`): in
  `rule_matched` it records `(match_index → hash_rule(canonical_rule(rule)))`;
  in `rules_combined` it retains the subset at `tied_match_indices` — exactly
  the rules that carried the strictest-wins decision.
- `ComposedFold<A, B>` (new combinator): delegates every trait method to both
  halves, pairing the associated `EffectOut`/`PredicateOut` types.
- **Hook** runs `AuditFold` alone (no trace-tree cost). **Eval** runs
  `ComposedFold<TracingFold, AuditFold>` — the Trace it already needs, plus the
  same audit capture.

This is the honest resolution of the eval/hook path divergence the proposal
flags: both production paths run the *same* `AuditFold`; eval merely layers a
`TracingFold` observer over it. The bare `evaluate_command`/`PureFold`
convenience stays for tests/internal callers but leaves the two production
decision paths.

_Alternatives:_ **B** — an `AuditCollector` struct fed from inside each fold
(less boilerplate, but capture logic lives in two feed sites; acceptable
fallback if the combinator proves heavy). **C** — run `TracingFold` everywhere
and discard the trace on hook (rejected: pays full trace-tree allocation on the
hot hook path, violating the "no trace work in hook mode" intent).

### D3 — Deciding-rule hashes; staleness across `migrate` is accepted

Records carry the canonical-form hashes of the deciding rules only (the
`tied_match_indices` set), not the full matched-candidate field — smaller, and
it answers "what made this decision." The hash is the same key the trust store
uses, so a record links directly into `may-i trust`. Because `migrate`
rehashes the trust store (Class A), a hash written to an old record will not
resolve after a migration. This is inherent to a point-in-time trail and is
accepted, not fought — the record is a fingerprint of the rule *as it was then*.

### D4 — `(audit …)` honoured only from `PrimaryConfig`; loaded use is a hard error

The form is parsed in `crates/config/src/config.rs`. The tagged-provenance
parse path (`parse_config_from_tagged_sexprs`) already carries `Provenance` per
form, so the `(audit …)` arm rejects with a load error when provenance is not
`PrimaryConfig`. A hard error (not silent-ignore) is chosen because the failure
modes — silence the trail, redirect it to an attacker path — are
security-relevant, and a warning has nowhere to surface in JSON-only hook mode.

### D5 — Record at both pipeline terminal points

A command blocked by the Trust gate short-circuits inside `prelude_and_trust`
before the closure runs. To avoid a trail that silently omits trust denials,
`run_eval`/`run_hook` build the audit record at *both* exits — the normal
closure outcome and the `TrustBlock` branch — tagging `source` as `rule`,
`trust-block`, or `parse-floor`. Emission is a single private pipeline method
called just before each return.

### D6 — Append-only, single `write()`, no `flock`; rotation external

Each record is serialised to one complete line and emitted in a single
`write()` under `O_APPEND`. POSIX makes that append atomic on a local
filesystem, so concurrent hook processes do not interleave — no advisory lock
needed. Rolling is delegated to `logrotate` (`copytruncate`). The single-write
atomicity guarantee does not hold on NFS; documented as a known limitation
acceptable for a local `~/.local/state` tool.

### D7 — Location, permissions, precedence, form shape

Default `$XDG_STATE_HOME/may-i/audit.jsonl` (→ `~/.local/state/…`): a trail is
*state*, not config or cache. Dir `0700`, file `0600` — it holds verbatim
commands. Settings resolve per-field, `--audit-* flag > MAYI_AUDIT_* env >
(audit …) form > default`; the env tier exists so hook mode (no flags) is
configurable. The form is alist-style head-keyed sub-forms — `(audit
(threshold :ask) (file "…"))` — matching `(define-arg-style …)`; the threshold
is a closed-set keyword value like `(pun :allow)`. CLI/env values are bare
strings (`ask`), not keywords.

### D8 — Best-effort writing is decision-neutral

The entire audit emit is wrapped in an error-swallowing boundary: a failed
directory create, open, or write is dropped (optionally one stderr breadcrumb),
never propagated. It cannot change the decision, the rendered output, or the
exit code. Logging is best-effort or it is a liability given exit-code-2
semantics.

## Risks / Trade-offs

- **Hash staleness across `migrate`** → Accept and document; the record is a
  point-in-time fingerprint, and forensics tolerate a dangling hash.
- **`ComposedFold` boilerplate** (~20 delegating methods) → One-time mechanical
  cost; reusable for any future observer. Fallback to D2-B if it sours.
- **Hook path gains `AuditFold` work** → Bounded: hash only the
  `tied_match_indices` rules, and only when the threshold would record. No
  trace-tree cost.
- **NFS torn lines** → Out of scope; documented. Local fs is the supported case.
- **Verbatim commands on disk** → `0600`/`0700`, opt-in (`:off` default),
  `/dev/null` escape hatch; flagged in user docs as a secret surface.
- **Two emit sites in the pipeline** (D5) couples audit to the trust-block
  branch → Mitigated by a single private emit method and spec scenarios pinning
  the `trust-block` source.

## Rejected against history

Two architectural alternatives were explored and rejected after studying the
git history of the seams this change touches. Recorded so a future explorer
does not re-suggest them.

- **Unify the pipeline terminal outcome** (one `EvalOutcome` + a single
  `finish()` that renders, to make the audit tap a single call site).
  **Rejected** — `typed-pipeline-mode-entrypoints` (archived 2026-05-26)
  deliberately *deleted* exactly that `EvalOutcome` enum + `render_eval_outcome`
  dispatcher via a deletion-test pass, trading runtime mode-switching for
  compile-time mode-to-body safety. The `command-pipeline` spec forbids both by
  name. D5's per-method emit respects that decision; no outcome-unifying type is
  introduced.
- **Split observation out of `EvalFold` into a narrow `EvalObserver` seam** (so
  `AuditFold` is ~2 methods and `ComposedFold` disappears). **Rejected** —
  `restore-trace-system` (archived 2026-04-01) considered an observer/visitor
  pattern and rejected it (SAX-vs-DOM: tree consumers can't rebuild structure
  from a flat stream), choosing the zygomorphism fold. Audit is the *only* flat
  consumer today (one adapter = hypothetical seam), and a parallel observer
  threaded through every recursive eval call cuts against the deliberate
  "two algebras, one fold, one traversal" design. The idiomatic fit is D2:
  `AuditFold` over `PureFold`'s identity shape, composed via `ComposedFold`
  (D2-A) with the collector-field fallback (D2-B) if the boilerplate bites.

## Migration Plan

Purely additive. New optional form defaulting to `:off`; no existing config
changes meaning, so no user-config migration is needed. Rollback is trivial:
with the default `:off`, the feature is inert unless explicitly enabled, and
removing the form/flags leaves all decisions unchanged.

## Open Questions

- `harness` field value on the eval path (no harness profile there): default to
  `null`. (Leaning yes.)
- `cwd` provenance: read from context facts when present, omit when absent
  rather than emit an empty string.
- Whether a single stderr breadcrumb on first audit-write failure is worth the
  noise, or writing should fail entirely silently.
