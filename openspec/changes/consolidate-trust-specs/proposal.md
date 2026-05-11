## Why

The Trust bucket holds 10 specs — `trust-store`, `trust-hashing`,
`trust-gate`, `trust-provenance`, `per-rule-trust`, `trust-command`,
`trust-ui-listing`, `interactive-trust-review`, `trust-advisory-boxes`,
`trust-block-context` — versus 5–6 in any other bucket. The fragmentation
spreads what is one user surface (the trust subsystem) across nine
overlapping documents, making it expensive to find the single requirement
that governs any given behaviour and easy to introduce silent overlap.

The split is along *implementation* lines, not *audience* lines. The four
"model" specs (store, hashing, gate, provenance) are genuinely distinct
concerns and stay separate. The other five (`trust-command`,
`trust-ui-listing`, `interactive-trust-review`, `trust-advisory-boxes`,
`trust-block-context`) all describe the **rendering and CLI surface** of
trust state, and would read more clearly as two specs:

- One CLI surface — every requirement about `may-i trust`, listing
  approvals, the per-rule review prompt — in `trust-command`.
- One rendering surface — every requirement about how trust state is
  embedded in trace output (advisory boxes around loaded rules, the
  trust-block-context shown when the gate blocks evaluation) — in
  `trust-advisory-boxes`.

`per-rule-trust` is borderline (97 lines, 6 reqs, distinct topic). We keep
it standalone but cross-reference it from `trust-gate`.

Net 10 → 6 trust specs. This is a Trust-relevant change in name only — no
requirement's *content* changes; we move them between files. Behavioural
contracts on what gets approved, what gets hashed, and what runs are
unaffected.

## What Changes

- **Fold `trust-ui-listing` into `trust-command`**: every requirement (4)
  about listing pending/approved trust state moves under the
  `trust-command` umbrella. `trust-ui-listing` directory is removed at
  archive.
- **Fold `interactive-trust-review` into `trust-command`**: every
  requirement (6) about the per-rule interactive prompt moves under
  `trust-command`. `interactive-trust-review` directory is removed at
  archive.
- **Fold `trust-block-context` into `trust-advisory-boxes`**: both
  describe trust output rendered into traces; the 2 requirements about
  block-context display merge alongside the existing advisory-box
  requirements. `trust-block-context` directory is removed at archive.
- **Keep standalone**: `trust-store`, `trust-hashing`, `trust-gate`,
  `trust-provenance`, `per-rule-trust`. Each is a distinct, sized concern.

The renamed `trust-command` and `trust-advisory-boxes` may grow expanded
Purpose sections to reflect their broader scope (full CLI surface; full
rendering surface). Names stay because both already use user vocabulary.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `trust-command` — ABSORBS `trust-ui-listing` and `interactive-trust-review`
  in full. Purpose section rewritten to cover the entire CLI surface.
- `trust-advisory-boxes` — ABSORBS `trust-block-context` in full. Purpose
  section rewritten to cover both advisory-box and block-context rendering.

### Removed Capabilities

- `trust-ui-listing` — capability folded into `trust-command`. Directory
  `openspec/specs/trust-ui-listing/` removed at archive.
- `interactive-trust-review` — capability folded into `trust-command`.
  Directory removed at archive.
- `trust-block-context` — capability folded into `trust-advisory-boxes`.
  Directory removed at archive.

## Spec-delta convention used in this change

The spec deltas under `specs/<source>/` enumerate `## REMOVED Requirements`
as bullets per OpenSpec convention. The deltas under `specs/<target>/`
enumerate `## ADDED Requirements` by name; the apply step (`tasks.md` §3)
copies the requirement bodies and their `#### Scenario:` children verbatim
from the source `openspec/specs/<source>/spec.md` files into the target,
preserving wording and ordering. No requirement body is rewritten.

## Impact

- `openspec/specs/trust-command/spec.md` — receives 10 requirements
  (4 from `trust-ui-listing`, 6 from `interactive-trust-review`) verbatim.
  Purpose section rewritten.
- `openspec/specs/trust-advisory-boxes/spec.md` — receives 2 requirements
  from `trust-block-context` verbatim. Purpose section rewritten.
- `openspec/specs/trust-ui-listing/` — directory removed.
- `openspec/specs/interactive-trust-review/` — directory removed.
- `openspec/specs/trust-block-context/` — directory removed.
- No source-code, test, or runtime config changes. Trust subsystem
  behaviour is unaffected by this change — it is a pure documentation
  reshuffle.

## Compatibility

This change does not change any trust-subsystem requirement's content or
ordering. Cross-references in other specs that point to the absorbed
specs (`trust-ui-listing`, `interactive-trust-review`,
`trust-block-context`) MUST be updated to point to their new home; this
is enumerated in `tasks.md` §4.
