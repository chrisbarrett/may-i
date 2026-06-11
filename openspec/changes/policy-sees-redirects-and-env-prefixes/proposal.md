## Why

Two pieces of command structure that change what a command *does* are invisible
to policy. Confirmed against the built binary (`echo`/`git` allowed):

1. **Redirect targets.** `echo x > /home/u/.ssh/authorized_keys` → `:allow`. The
   redirect writes an attacker-controlled file under an allow rule for `echo`; no
   Pattern can see or constrain the target. A tool that authorises commands by
   structure cannot ignore the structure that names a file to overwrite.

2. **Environment-assignment prefixes.** `LD_PRELOAD=/evil.so git status` →
   `:allow`. The prefix is stripped and the command evaluates as plain `git
   status`. `LD_PRELOAD`, `BASH_ENV`, `ENV`, `IFS`, `PATH`, `SHELLOPTS` in prefix
   position change what executes — arbitrary code via the dynamic linker or
   bash's startup hooks — yet are invisible. `trust-hashing` already reserves a
   `safe-env-vars` scope, but no requirement defines what an env prefix *decides*.

Both are the same class as the just-fixed process-substitution hole: real
command structure escaping the authorisation surface.

## What Changes

- **Redirect targets become visible / floor.** A redirect to a file target
  (`>`, `>>`, `<`, `<>`, `&>`, fd dups to a path) SHALL be surfaced to evaluation.
  Minimum viable, safe default: a command carrying a redirect to a non-standard
  target floors to at least `:ask`. There is no opt-in in this change — `may-i`
  classifies by command; path restriction belongs to sandboxing layers below. A
  capability-style opt-in (a rule declaring its command may carry redirects) is
  drafted separately as `rules-grant-redirect-capability`. An
  expansion-bearing target is treated per the asymmetric-soundness invariant.
- **Env-assignment prefixes become a decision input.** A command with one or
  more `NAME=VALUE` prefixes SHALL NOT be evaluated as if the prefixes were
  absent. A prefix assigning a name **not** in the effective `safe-env-vars` set
  SHALL floor the segment to at least `:ask`, naming the variable. Names in
  `safe-env-vars` (a primary-config-governed allowlist, trust-scoped per
  `trust-hashing`) pass through. This change also pins the `safe-env-vars`
  semantics that were previously only referenced.

## Capabilities

### New Capabilities

<!-- none -->

### Modified Capabilities

- `shell-command-security-model` (bucket: parsing; trust-relevant): add
  requirements that a redirect to a file target is not silently ignored (floors
  absent opt-in), and that an env-assignment prefix to a non-`safe-env-vars`
  name floors to `:ask`. Cross-references `trust-hashing` for the `safe-env-vars`
  scope.
- `facts` or a new `safe-env-vars` requirement home — define the effective
  `safe-env-vars` set and its allowlist semantics (currently only referenced by
  `trust-hashing`). *(Bucket/home to confirm in design — likely a dedicated
  requirement within the security model since it gates a decision.)*

## Impact

- `crates/shell-parser` — surface a command's redirect list (operator + target
  word) and its env-assignment prefix list; both are in the AST but not threaded
  to evaluation.
- `crates/config` — parse/resolve `(safe-env-vars …)` into the effective set;
  enforce primary-config-only origin (consistent with `(audit …)`); carry
  provenance for the trust scope.
- `crates/engine/src/eval` — floor on a non-standard redirect target and on a
  non-allowlisted env prefix; apply the asymmetric-soundness invariant to
  expansion-bearing targets/values.
- Trust: `safe-env-vars` hashing already specified in `trust-hashing`; this wires
  the consuming side.
- Migration: none for redirects. `safe-env-vars` is additive. Out of scope:
  modelling redirect dataflow, fd-level semantics beyond "names a file target".
