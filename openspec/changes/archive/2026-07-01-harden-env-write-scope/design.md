## Context

The env-write floor (`shell-command-security-model`) emits an `EvalUnit::EnvPrefix`
for every entry in a simple command's assignment list and floors any name not in
the `safe-env-vars` allowlist. That assignment list is populated by two unrelated
parser decisions: a genuine command prefix (`FOO=bar cmd`, lifted only when no
command word precedes it) and a declaration builtin's *array* argument
(`declare -A m=([k]=v)`, lifted solely to record `ArrayKind` for sound
`"${arr[@]}"` resolution). Scalar declaration args (`declare FOO=bar`,
`export FOO=bar`) are left as plain words and never floor.

The observable result, confirmed against the built binary:

| command | today |
|---|---|
| `declare -A m=([k]=v)` | `:ask` (env prefix `m`) |
| `declare FOO=bar` | `:allow` |
| `export LD_PRELOAD=/evil.so; echo hi` | `:allow` |
| `LD_PRELOAD=/evil.so echo hi` | `:ask` |

So the floor over-blocks shell-local array declarations and under-blocks exported
writes — both because it keys on "landed in the assignment list," a parsing
artifact, rather than on whether the write crosses a process boundary. The spec
only ever described the command-prefix case, so the first is already a spec
violation and the second an unspecified hole.

`may-i` deliberately does not read its own process environment for decisions
(`runtime_facts.rs` sources facts only from `--fact`; `io.rs` scrubs inherited
git env before spawning subprocesses). Deciding whether a *bare* reassignment of
an already-exported name (`PATH=/evil`) reaches a child requires knowing the
inherited exported set — which crosses that standing posture and must be done
deliberately.

## Goals / Non-Goals

**Goals:**

- Floor an env write iff it reaches a child process; never floor a purely
  shell-local write.
- Close the `export` / `declare -x` under-block and the shell-local-array
  over-block with one coherent discriminator.
- Introduce the entry environment as a first-class, testable, secret-safe input.
- Keep `may-i check` hermetic and reproducible.

**Non-Goals:**

- Cross-segment dataflow / destination correlation ("which later command
  inherits which var"). The entry environment is an entry-state snapshot only.
- A built-in dangerous-name blocklist (LD_*, PYTHONPATH, …) and a realistic
  default check environment (`(with-standard-env)`). Name *policy* stays
  user-authored via `(env …)`; this change only fixes *when* the floor fires and
  adds the scope vocabulary. Shipping curated defaults at varying paranoia levels
  is deferred to a future **profiles** concept that carves the prelude into
  opt-in tiers — that is where a blocklist and a standard check env belong.
- Modelling builtin arithmetic deref of bare identifiers (already an accepted
  read-position limitation).
- Tracking entry-environment *values* for any purpose.

## Decisions

### 1. Discriminator is "reaches a child," not assignment shape

A write reaches a child when it is a prefix, an `export`/`-x` declaration, a bare
reassignment of an entry-environment name (re-export), or any assignment under
`set -a`. Everything else is shell-local and inert. Rationale: the threat the
floor defends (a name like `LD_PRELOAD` changing what executes) only materialises
when the value enters a child's environment. *Alternative considered:* a narrow
fix that just stops array-arg lifting from flooring. Rejected — it fixes the
annoyance but leaves the `export LD_PRELOAD` hole open, and the two share one
root cause; fixing only the visible half would be incoherent.

### 2. The entry environment is a new input, in the `facts` layer but not a fact

It is runtime context observed per invocation, so it belongs to the Facts layer /
`facts` bucket. But it is a *substrate* consumed structurally by the write-floor,
not a leaf predicate, and has different cardinality (hundreds of ambient names)
and provenance (observed, not asserted) than a keyed fact. So it is threaded as a
distinct typed input and is **not** reachable via `(fact? …)`. *Alternative:*
flatten it into the fact namespace (`(fact? :PATH)`). Rejected — pollutes the
fact surface with every env var and blurs asserted-vs-observed.

### 3. Capture once at the entrypoint; engine stays pure

`may-i hook` snapshots `std::env` as its first action (before git-env scrubbing)
and threads an immutable names-only set. `eval`/`check` take an explicit
(default-empty) snapshot. This gives zero-integration acquisition *and* a pure
engine (proptests inject a snapshot, never mutate process state), and the input
is acquisition-agnostic: a future harness can supply the *exact* bash-tool env
through the same channel with no engine change. *Alternative:* let the engine
read `std::env` on demand. Rejected — breaks purity, reproducibility, audit
determinism, and portability.

### 4. Names-only snapshot

"Reaches a child" needs only presence; `std::env` *is* the exported set. No
write decision needs the value (even `PATH=$PATH:/evil` is dangerous regardless
of current value). Carrying names only means the snapshot holds no secret
material, so trace/audit rendering of an entry-environment contribution is
safe by construction.

### 5. `(scope …)` predicate and scope vocabulary

Expose `prefix` / `export` / `bare` raw scopes and the derived `reaches-child`
disjunction as a predicate inside `(env …)` decisions. This is the "rich env
rules" affordance: it reuses the existing fact-conditioned decision sub-language
and adds one matcher kind, rather than a parallel `(rule …)`-scale DSL keyed on
argv (which env vars do not have). `reaches-child` is what most policy wants;
the raw scopes are there for finer control.

### 6. Hermetic check defaults empty; advise the gap

`check` defaults to an empty entry environment and declares presence with
`(with-env …)`. This is purely hermetic, but its default-absent polarity is the
*opposite* of `(with-facts …)`: an absent fact is usually safe, whereas an absent
env name silently under-tests the always-exported dangerous names. Mitigation: an
advisory when a scope-dependent rule has no `(with-env …)` coverage. *Alternative:*
default `check` to a realistic baseline set (PATH, HOME, LD_*, …). Rejected as the
default — it makes "test the absent case" require an explicit clear and bakes in a
magic list; the advisory keeps the default honest while pointing at the gap. A
`(with-standard-env)` preset is deferred to the future **profiles** concept (see
Non-Goals), which will own curated defaults across paranoia tiers.

### 7. Vocabulary and bucket

"Entry environment" is a new **user-facing** term (it appears in `(with-env …)`
and the `--env` flag). It SHALL be added to `CONTEXT.md` and
`openspec/config.yaml:context` user vocabulary. Its bucket is `facts`. The
write-floor reframe and `(scope …)` predicate are trust-relevant (they affect
what runs and they live in trust-scoped `(env …)` capabilities); the
`shell-command-security-model` spec already declares `trust-relevant: true`.

## Risks / Trade-offs

- **Behavioural change: shell-local writes stop flooring.** → Pre-1.0, no
  back-compat guarantee; the prior behaviour was a bug (shape-keyed). Surface in
  the changelog; a user wanting to floor a specific shell-local name can still
  `(env NAME (ask))`.
- **`may-i`'s env only approximates the bash tool's env (mode-3).** → Acceptable:
  tightening-only use (presence only *adds* floors) means an approximation can at
  worst under-tighten, never wrongly authorise; and the channel is ready for a
  harness to supply the exact env later.
- **Env as a decision input is an injection surface.** → Tightening-only is robust:
  an attacker would need to *remove* a name (e.g. `PATH`) from the env to dodge a
  floor, which they cannot; absence merely falls back to other axes. In
  claude-code each Bash call is a fresh `bash -c`, so exported vars don't persist
  into a later `may-i` invocation.
- **`set -a` / `set -o allexport` detection and subshell scoping.** → Tracked as
  a scoped flag over the AST: a `set -a` makes subsequent assignments in its own
  and nested scopes exported (reaching writes); `set +a` clears it. `allexport`
  is a *shell option*, so a child execution scope inherits a copy and its changes
  do not escape — `Subshell` (`( … )`), pipeline components, `Background` (`&`),
  and `CommandSubstitution` (`$( … )`) are barriers, but `BraceGroup` (`{ …; }`)
  runs in the current shell and is **not** a barrier. So a `set -a` reachable only
  inside subshells SHALL NOT mark enclosing-scope assignments as exported. The
  analysis is conservative toward *flooring*: once a non-subshell-confined `set -a`
  precedes an assignment in execution order — even conditionally — the assignment
  is treated as exported, accepting false positives to avoid a false negative.
  *Accepted limitation:* `allexport` pre-activated via `SHELLOPTS` in the entry
  environment is not detected — the names-only snapshot cannot read the value;
  the analysis assumes `allexport` starts off.
- **In-string export attribute.** → Beyond the entry environment, a name given
  the export attribute *within* the command string — `export NAME` / `declare -x
  NAME` (attribute-only) or `export NAME=v` — makes a later bare reassignment of
  `NAME` a reaching write. This is tracked as a scoped per-name set alongside the
  `allexport` flag, with the same barrier/ordering rules (`export` inside a
  subshell does not escape; conditional branches are conservative toward
  flooring). *Accepted limitation, in the non-flooring direction:* an `allexport`
  toggle or `export` performed through a **dynamically-named command** (`x=set;
  $x -a`) or `eval "…"` is not detected — the command name/body is opaque, the
  same accepted limitation the tool already carries for dynamic command names.
- **Entry-environment value never leaks.** → Enforced structurally by the
  names-only type; no code path holds a value to leak.
- **Trust-hash churn for `(env …)` with `(scope …)`.** → New predicate extends
  canonical form; `may-i migrate` preserves approval across the rewrite per the
  migration system.

## Migration Plan

- No user-config rewrite is required: existing `(env …)` forms keep their
  meaning. Configs that *relied on* shell-local writes flooring (e.g. expecting
  `declare -A m=…` → `:ask`) change behaviour; this is called out as BREAKING in
  the proposal and the changelog.
- Add `entry environment` to `CONTEXT.md` and `config.yaml:context` vocabulary.
- The `(scope …)` predicate is additive; canonical-form/hash changes are handled
  by a migration if any prelude/example config adopts it.

## Open Questions

None outstanding. Resolved during proposal: `set -a` detection is in scope
(scope-aware, conservative); the `(scope …)` predicate exposes the raw scopes
*and* the derived `reaches-child`; curated defaults (blocklist,
`(with-standard-env)`) are deferred to a future **profiles** concept.
