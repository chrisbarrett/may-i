## Context

The user wants `.may-i.lisp` and friends at the repo root to carry
project rules. The existing `(load …)` infrastructure already handles
multi-file merge with cycle detection, glob expansion, and per-rule
provenance tagging. Adding a new layer to the resolver is mechanically
cheap.

The security argument is the load-bearing part. Investigation
(`crates/engine/src/eval/entry.rs:126-143`,
`crates/engine/src/test_generators/effect_eval_tests.rs:413-446`)
confirmed that the engine returns on the first matching rule. The
`Decision::Ord` impl declares `Allow < Ask < Deny` but is never used
in the evaluator. The trust gate filters un-approved `Loaded` rules,
which protects against the obvious attack — but a single misjudged
approval click on a loaded `(rule "rm" (effect :allow))` is enough to
shadow a primary `:deny`, because order-as-semantics applies to
the merged rule list.

Bundling the engine fix with discovery makes the security claim
mechanical: "loaded rules cannot widen primary policy" follows from the
lattice combine, not from user vigilance.

## Goals / Non-Goals

**Goals:**
- Order-independent rule combination at the top level. Adding a rule
  to a config can never produce a less-strict outcome than the
  config without that rule.
- Repo-local config discovered automatically; works for plain repos
  and linked worktrees alike.
- Loaded rules from any source (existing `(load …)`, repo-local
  discovery, future sources) cannot widen primary policy.
- Trust UX unchanged in shape; trust hashing unchanged.

**Non-Goals:**
- Changing semantics inside a single rule's effect tree (`or`, `and`,
  `if` short-circuit behaviour) — only top-level rule combination.
- Changing the trust hash algorithm or store format.
- Per-segment evaluation rework (`engine-segment-decisions` is
  preserved).
- Cross-repo or "monorepo" config inheritance — discovery stops at the
  first repo root.
- Honouring `.gitignore` for `.may-i.local.lisp` — that's a user
  convention, enforced by their VCS, not by may-i.

## Decisions

### Decision: Pure most-strict-wins combine (no override escape hatch)

The engine collects all matching rules and returns the maximum under
`Allow < Ask < Deny`. No `:override` modifier; no specificity
heuristics; no asymmetric primary/loaded ordering.

Alternatives considered:

- **Most-strict + explicit `:override`** — preserves whitelist-exception
  patterns (narrow `:allow` shadowing broad `:deny`). Rejected because
  the user prefers the simpler model and judges that real configs do
  not depend on this pattern. If demand surfaces, `:override` can be
  added later as a strictly opt-in extension that only `PrimaryConfig`
  rules may use.
- **Specificity-wins (longest-prefix-match)** — order-independent and
  preserves whitelist exceptions. Rejected because "specificity" over
  arbitrary predicate trees has no obvious total order; defining one
  would itself be a project.
- **Provenance-aware ordering (primary before loaded)** — order-
  independent across the boundary but order-sensitive within each
  side. Rejected as half-measure: still has the same sharp edge
  within a single config, just smaller.

### Decision: Tie-break on `reason` is earliest source order

When multiple matching rules share the most-strict effect, the
earliest-in-source-order rule supplies the `reason` string. This is
deterministic, useful for trace output, and matches the principle of
least surprise (the rule the user wrote first "explains" the decision).

Source order: primary config rules in file order, then loaded files
in load order, then within each loaded file in file order.

### Decision: No-match default stays `Ask`

If no rule matches, the engine returns `Ask`. Today's behaviour
(`crates/engine/src/eval/entry.rs:109`). Consistent with the lattice
view: `Ask` is the safe default for unrecognised commands.

### Decision: Discovery via `git rev-parse`, fallback to marker walk

`git rev-parse --show-toplevel` is the authoritative answer for git
repos and worktrees. If `git` is unavailable, walk parents looking for
`.git`, `.hg`, or `.jj` directories.

Alternatives considered:
- **Pure ancestor walk for `.git`** — simpler, no dependency on `git`
  binary. Rejected because it gets linked worktrees wrong (a worktree's
  `.git` is a file pointing into the main repo, and walks would
  find the main repo's `.git` instead). `git rev-parse` handles this.
- **Search for `.may-i.lisp` directly without an SCM marker** —
  rejected because it gives no upper bound on the walk and conflicts
  with users who keep a `.may-i.lisp` in their home directory.

### Decision: File discovery order

Within a repo root, discovered files are loaded in this order:

1. `.may-i.lisp`
2. `.may-i/**/*.lisp` (lexically sorted)
3. `.may-i.local.lisp`
4. `.claude/may-i.lisp`
5. `.claude/may-i.local.lisp`

Order matters only for `reason` tie-breaking, since the engine combine
is now order-independent for `Decision`.

`.local` variants come after the shared variants in their family,
matching convention (local overrides shared in tools that use this
pattern, e.g. `direnv`'s `.envrc.local`). With most-strict-wins this
is mostly a tie-breaking nicety.

### Decision: Discovery is silent on "no repo"

If `git rev-parse` fails and no marker is found by walk, discovery
contributes nothing. No error. `may-i` invoked outside any repo (e.g.
in `/tmp`) behaves exactly as it does today.

### Decision: Repo-local files use `Loaded` provenance, not a new variant

`Provenance::Loaded { path }` already carries the file path and is
already integrated with the trust gate. Adding a new
`Provenance::RepoLocal` variant would require touching every match arm
in the engine for no semantic gain — repo-local files share the
trust-gated, hash-keyed semantics of files reached via `(load …)`.

### Decision: Discovery is part of the load result, not a separate pipeline

Repo-local files are spliced into the resolver output as if the primary
config had ended with `(load "<repo-root>/.may-i.lisp") ...` — same
mechanism, same provenance tagging, same cycle detection. This keeps
the load pipeline as the single source of truth for file inclusion.

## Risks / Trade-offs

- **Risk: behaviour change for existing users who depend on
  first-match-wins ordering.** Examples: a narrow `:allow` exception
  positioned before a broad `:deny`. After the change the deny wins
  for that command.
  - Mitigation: audit the user's own config and test fixtures
    before/after. Encode the new contract in property tests so future
    regressions are caught. Release note flagging the semantic
    change.
  - Open question: is this a breaking change worthy of a major bump?
    Project versioning is pre-1.0 so probably not, but the release
    note must be loud.

- **Risk: discovery walks contribute surprising config in unexpected
  CWDs.** A user invokes `may-i` from inside someone else's checked-out
  repo. Repo-local files there are discovered and presented for
  trust review.
  - Mitigation: trust gate already filters un-approved rules. Worst
    case is a one-off review prompt. The user is the same person who
    chose to clone the repo; this is consistent with the existing
    contract.

- **Risk: `.may-i.local.lisp` not gitignored ships sensitive
  per-user rules to teammates.**
  - Mitigation: documentation only. We cannot enforce gitignore from
    inside may-i. Suggest adding `.may-i.local.lisp` to a project
    template or `.gitignore` snippet in the README.

- **Trade-off: pure most-strict drops the whitelist-exception
  pattern.** Users today can write a narrow `:allow` followed by a
  broad `:deny` to permit specific cases inside an otherwise denied
  command. After the change, they must express the exception inside
  a single rule's effect tree (`(if narrow-pred :allow :deny)`).
  - Acceptable: the pattern is rare in practice (per the user's
    judgement), and the rewrite is mechanical.

- **Trade-off: discovery requires git on PATH for full correctness on
  linked worktrees.** Marker walk handles plain repos but misidentifies
  the main repo from inside a linked worktree.
  - Acceptable: the user's environment has git; CI environments
    typically do too. Document this behaviour clearly.

## Migration Plan

1. **Engine first.** Implement most-strict combine behind property
   tests. Verify existing rule-evaluation snapshots; update or replace
   any test that asserted first-match-wins as a contract rather than
   an incidental observation.
2. **Audit user's own config.** Run `may-i eval` against a fixture
   set covering common commands; diff the decisions before and after
   the engine swap. Reconcile any drift before merging.
3. **Discovery layer.** Add repo-local resolution. Property tests
   ensure unrelated CWDs produce identical results to today.
4. **Trust integration.** Verify that discovered files appear in
   trust review with correct file paths, hash to the same values
   regardless of discovery path (so a file that was previously
   `(load …)`-included and is now repo-local-discovered is treated
   as the same approved entry).
5. **Release note.** Document the engine semantic change loudly.
   Suggest the rewrite for whitelist-exception users.

Rollback: the engine change is the only breaking part. If a regression
surfaces post-merge, revert the engine commit and keep discovery — the
discovery layer is independently safe under the trust gate even with
first-match semantics, just not as principled.

### Decision: Trace surfaces all tied entries

When multiple rules tie at the most-strict effect, trace output SHALL
list **all** of them as evaluated entries — not just the one that
supplied the `reason` string. The user reading a trace should see
every rule the engine considered to reach the decision; hiding
siblings would obscure the combine.

The single rule whose `reason` survived (earliest-in-source-order
tie-breaker) is marked as the source of the reason; the others are
shown as also-matched-at-this-effect.

### Decision: No major version bump now; defer to next release cut

The engine semantic change is breaking in principle, but the project
is pre-1.0 and the user will bump appropriately when cutting the next
release tag. The release note in `tasks.md` step 7.2 captures the
behaviour change for users; no version action inside this change.

## Open Questions

- Does the trust-review UI need any update to highlight that a loaded
  `:allow` will not, in fact, override a primary `:deny`? Probably no
  — but worth confirming the existing display still reads sensibly
  given the new combine semantics.
- Where exactly does discovery hook into the resolver — alongside
  `expand_loads`, or as a pre-pass that synthesises `(load …)` forms?
  Defer to implementation; both are viable.
