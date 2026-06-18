# Design: doc-sync-reference-gate

## Context

REFERENCE.md is compiled into the binary (`src/cmd_help.rs:5`,
`include_str!("../REFERENCE.md")`) and rendered by `may-i reference`. It is
the user-facing manual for the DSL surface. Three drift classes exist:

| Class | Example | Catchable by |
| :-- | :-- | :-- |
| Example lisp rotted | a `(rule …)` block no longer parses | executable test |
| New grammar head undocumented | a new top-level form omitted | head-coverage test |
| **Existing form, changed semantics** | implicit-seq quantifiers | only forcing a human to look |

This change addresses the third class — the one that motivated it and the
one no machine check can detect, because the form is already present in
both REFERENCE.md and CONTEXT.md and only its *meaning* changed.

## Goals / Non-Goals

**Goals**
- Force the author of a user-facing DSL change to open REFERENCE.md.
- Fire at proposal time (cheapest fix point), deterministically, in
  existing CI machinery.
- Zero false-positive hard blocks (typo/reword spec deltas must pass).

**Non-Goals**
- Verifying REFERENCE.md prose is *correct* — undecidable; left to review.
- The other two drift classes (example-runner, head-coverage). Worth
  doing later; out of scope here.
- Forking or patching the third-party `openspec` binary.

## Decisions

### D1: Fire at proposal time, require a task — not at archive, not an edit

**Chosen:** the gate checks that `tasks.md` contains a line naming
`REFERENCE.md` when a user-facing delta is present.

Alternatives rejected:
- **Archive-time "REFERENCE.md was actually modified".** Fires long after
  the omission was cheap to fix, and blunt: a typo-only spec delta would
  be forced to touch REFERENCE.md or waive. The omission that motivated
  this (`quantifier-sequence-groups` task 8.1) was a *tasks.md* omission
  at proposal time — catch it there.
- **Require an actual edit at proposal time.** Impossible — REFERENCE.md
  is edited during implementation, not proposal; and it false-positives
  on reword deltas, training reflexive waivers until the gate rots into a
  dead reminder.

### D2: Consideration task, not a hard edit requirement

The required task resolves **either** to a REFERENCE.md edit **or** to an
explicit "verified, no surface change". This keeps the gate's signal high:
it never wrongly blocks a typo fix, but it always forces the author to
open the file — the only thing that catches semantic drift. The honesty of
a "verified, no change" resolution is a **review** concern, deliberately
not machine-checked; trying to prove a doc *needs* no change is the same
undecidable problem we excluded in Non-Goals.

The validator therefore checks **presence of a REFERENCE.md task**, not
its resolution. Satisfied by any `tasks.md` line matching `REFERENCE.md`.

### D3: Standalone script, not a fork of `openspec validate`

`openspec validate` is the third-party CLI; the project's established
extension pattern is a sibling shell script in `scripts/` wired into prek
— `validate-spec-frontmatter.sh` is the precedent, and `spec-conventions`
already anticipates "future siblings". New script:
`scripts/validate-change-doc-sync.sh`, `set -euo pipefail`, a `--self-test`
mode with synthetic fixtures (mirroring the precedent), scoped via prek
`files = "^openspec/changes/"`.

### D4: Audience trigger resolved via the stable spec

Delta files under `openspec/changes/<name>/specs/<cap>/spec.md` carry **no
frontmatter** (verified: `quantifier-sequence-groups/specs/patterns/spec.md`
opens straight on `## ADDED Requirements`). `audience: user` lives on the
stable spec (`openspec/specs/patterns/spec.md:1-4`). So the algorithm is:

```
for delta in openspec/changes/<name>/specs/*/spec.md:
    if delta has no "## ADDED Requirements" and no "## MODIFIED Requirements":
        continue                      # REMOVED-only / structural → not a surface add
    cap   = <the capability dir name>
    stable = openspec/specs/<cap>/spec.md
    if stable exists:
        user_facing = (audience field == "user")
    else:                              # brand-new capability
        user_facing = (bucket != contributor-internals)   # conservative default
    if user_facing: trigger = true

if not trigger:           pass
if no tasks.md:           pass    # proposal stage — see D6
if tasks.md has no line matching REFERENCE.md:
    fail with guidance
```

For a new capability with no stable spec, audience is unknown; defaulting
to user-facing over-prompts at worst, and the cost of over-prompting is a
one-line "verified, no change" note — cheap and safe. The new-capability
bucket is read from the delta's own optional frontmatter if present;
absent that, default user-facing. (`proposal.md` is not parsed — keeping
the trigger deterministic and dependency-free.)

### D5: Steering reminder in config.yaml so agents emit the task

The validator is the enforcement; `openspec/config.yaml` `rules.tasks:`
gets a bullet so generated `tasks.md` carries the task by construction,
not only after a failed hook. This mirrors the existing split documented
in `spec-conventions` Purpose: the spec + script *enforce*; `config.yaml`
*steers* generation.

### D6: Gate begins at tasks-authoring time, not before

A change with a user-facing delta but **no `tasks.md`** passes. Discovered
during implementation: `rules-grant-redirect-capability` is proposal-stage
(user-facing delta, no tasks artifact yet) and the first draft blocked it.
Gating a change that has not authored tasks is over-eager — it cannot be
applied or archived anyway (openspec `applyRequires=[tasks]`), and the
omission this gate guards is specifically a *tasks.md* omission. The gate
fires the moment `tasks.md` exists. The motivating case
(`quantifier-sequence-groups`) has a `tasks.md`, so D6 does not weaken it.

## Risks / Trade-offs

- **Checkbox-able.** D2 means a dishonest "verified, no change" passes the
  validator. Accepted: machine-proving doc necessity is undecidable;
  review is the backstop. The gate still guarantees the file was *named*,
  which is what failed here.
- **New-capability audience guess (D4).** Over-prompts when a new
  contributor capability isn't bucketed `contributor-internals`. Mitigated
  by the cheap "verified, no change" escape and by the bucket default.

## Migration

None. Pre-1.0; the gate only governs new/edited changes. Existing archived
changes are untouched (validator scopes to live `openspec/changes/`).
