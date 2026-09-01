## Context

See `proposal.md` — Why. What shapes the approach:

- Archiving is a filesystem move: `openspec/changes/<name>/` →
  `openspec/changes/archive/<date>-<name>/`. By the time a commit exists, the
  change already sits under `archive/`.
- `prek` hooks run at the pre-commit stage with `files = "^openspec/changes/"`
  and `pass_filenames = false`, so a validator sees the whole tree, not just the
  staged paths. `validate-change-doc-sync.sh` and `validate-spec-frontmatter.sh`
  both work this way.
- 19 archived changes already carry unchecked tasks, the worst at 30 of 79.
- Task text is not a fixed vocabulary. Withdrawal notes in the one worked example
  read as prose under the checked box (`fast-iteration-loop` 3.4, 5.1, 5.2), not
  as a marker a script could match.

## Goals / Non-Goals

**Goals:**

- Make an unfinished change impossible to archive silently.
- Keep the legitimate withdrawal path cheap, so the gate is not routed around.
- Fail with the specific task numbers, so the fix is mechanical.

**Non-Goals:**

- Judging whether a recorded outcome is *true*. That is review's job; the gate
  only enforces that a decision was recorded. Same division as the REFERENCE.md
  doc-sync gate.
- Blocking work in progress. Active changes are expected to have unchecked
  tasks — that is their normal state.
- Retro-fitting outcomes onto the 19 historical changes.

## Decisions

### Validate the archive directory, not active changes

The validator scans `openspec/changes/archive/*/tasks.md` and fails on any
`- [ ]`. Active changes under `openspec/changes/<name>/` are not checked.

This puts the gate at exactly the right moment. The archive move and the commit
recording it are the same event, so a pre-commit hook scoped to
`^openspec/changes/` fires precisely when a change crosses the line — and never
while someone is mid-implementation.

*Alternatives considered.*

- **Validate active changes too, and require completeness before archive is
  run.** Rejected: an active change with unchecked tasks is the normal state, so
  the hook would fail on every commit during implementation. Contributors would
  disable it.
- **Wrap `openspec archive` in a script that checks first.** Rejected: it only
  helps whoever remembers to use the wrapper, and `openspec archive` remains one
  keystroke away. The hook binds to the commit, which is unavoidable.

### Resolve withdrawn tasks by checking the box, not by a marker syntax

A task whose premise dies is resolved by checking it and writing the reason in
its body. The validator does not look for a keyword.

Requiring a marker (`- [~]`, a `WITHDRAWN:` prefix) would buy machine-checkable
intent at the cost of a syntax nobody remembers under pressure, and OpenSpec's
own parser counts `- [ ]` and `- [x]` for progress — a third state would either
be miscounted or need upstream support. Checking the box with prose is what the
one good example in the repo already does.

The cost is honest and stated: a contributor can check a box and write nothing.
The gate catches *silence*, not dishonesty, and that is the failure that
actually occurred — 5.1 and 5.2 were forgotten, not concealed.

*Alternative considered.* **Require a non-empty note on any task whose body
mentions a dependency.** Rejected: it needs the validator to parse task prose
for dependency claims, which is guesswork, and it would fire on well-written
tasks that simply reference each other.

### Grandfather the existing 19 by cutoff date, not allowlist

The validator skips archived changes whose directory-name date precedes the date
this gate lands. Nothing is listed by name.

A 19-entry allowlist is a file someone has to prune, and a name left in it after
the change is fixed silently re-exempts it. A date is one constant, it needs no
maintenance, and it cannot drift: every change archived after the gate exists is
covered, forever.

*Alternatives considered.*

- **Fix all 19 first.** Rejected: they are finished work from up to six months
  ago. Reconstructing what was done would produce plausible-looking records
  nobody verified — manufacturing exactly the false assurance this change fights.
  Their unchecked boxes are honest signal and should stay.
- **Named allowlist.** Rejected as above: maintenance burden and silent
  re-exemption.

## Risks / Trade-offs

**The gate blocks the archive commit, and the obvious escape is `--no-verify`.**
→ Accepted. Every hook in `prek.toml` has this property; the gate raises the cost
of skipping from zero to deliberate.

**A contributor checks a box with no note to get past the hook.** → Not
defended against, by design (see Decisions). The failure mode observed was
forgetting, not evasion, and a gate that tried to detect evasion would need to
judge prose.

**The cutoff date is a magic constant that needs a comment.** → It carries one,
naming this change and the count it grandfathers, so a later reader knows why it
exists rather than deleting it as dead.

**A change archived, then amended in a later commit, re-triggers the hook.** →
Correct behaviour: the amended change is post-cutoff and should be complete. This
is how `fast-iteration-loop`'s two stragglers would have been caught.

## Migration Plan

Land the validator and hook together, with the cutoff set to the landing date.
No existing archive is touched. Rollback is deleting the hook entry.
