## 1. Validator script

- [x] 1.1 Create `scripts/validate-archive-complete.sh` following the shape of
      `scripts/validate-change-doc-sync.sh`: `set -euo pipefail`, re-exec into
      the Nix devshell when mikefarah `yq` is absent, a header comment naming
      `openspec/specs/spec-conventions/spec.md` as the authority.
- [x] 1.2 Implement the scan: for each `openspec/changes/archive/*/tasks.md`,
      report every line matching `- [ ]` with its task number and text, and exit
      non-zero if any change has one.
- [x] 1.3 Implement the cutoff: skip archived changes whose directory-name date
      precedes the date this change lands. Carry a comment naming this change and
      the 19 changes grandfathered, so the constant is not later deleted as dead.
- [x] 1.4 Add a `--self-test` mode with fixtures, matching the other two
      validators: a complete change (passes), a change with one unchecked task
      (fails, names it), a pre-cutoff change with unchecked tasks (skipped), a
      post-cutoff change with unchecked tasks (fails), and a `tasks.md` with no
      checkboxes at all (passes — nothing to enforce).
- [x] 1.5 Run `scripts/validate-archive-complete.sh --self-test` and confirm all
      cases pass.

## 2. Hook wiring

- [x] 2.1 Add a `validate-archive-complete` hook to `prek.toml` at the
      `pre-commit` stage, `files = "^openspec/changes/"`,
      `pass_filenames = false`, mirroring `validate-change-doc-sync`.
- [x] 2.2 Confirm the hook fires on a commit that archives a change and passes
      on a commit touching only an active change.

## 3. Specification

- [x] 3.1 Confirm the delta in `specs/spec-conventions/spec.md` matches what the
      validator enforces — in particular that the withdrawal path is "checked box
      plus recorded reason", with no marker syntax.
- [x] 3.2 Add the cutoff and the grandfathered backlog to the requirement's prose
      if the spec should record them; otherwise confirm they are design-level
      only and leave the requirement unqualified.

## 4. Verification

- [x] 4.1 Run the validator against the current tree and confirm it passes: the
      19 historical changes are skipped by the cutoff, and
      `2026-09-01-fast-iteration-loop` passes on its merits now that 5.1 and 5.2
      are resolved.
- [x] 4.2 Construct a throwaway post-cutoff archived change with one unchecked
      task, confirm the hook blocks the commit, then remove it.
- [x] 4.3 Run `cargo fmt --all`, `openspec validate archive-completeness-gate
      --strict --no-interactive`, `scripts/validate-spec-frontmatter.sh`, and
      `scripts/validate-change-doc-sync.sh`.
- [ ] 4.4 Confirm CI is green on the branch.
