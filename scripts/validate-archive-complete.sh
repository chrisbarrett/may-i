#!/usr/bin/env bash
# Enforce the archive-completeness gate on archived OpenSpec changes.
#
# Required: yq-go (mikefarah/yq) v4+. Provided by the Nix devshell.
#
# Rule (per openspec/specs/spec-conventions/spec.md, added by the
# `archive-completeness-gate` change):
#   A change SHALL NOT be archived while its tasks.md contains an unchecked
#   task (`- [ ]`). Every task reaches a recorded outcome — done, or
#   withdrawn with the reason recorded in its own body — before the change
#   moves to openspec/changes/archive/.
#
# This validator scans openspec/changes/archive/*/tasks.md and fails on any
# unchecked task, naming each by its number and text. Active changes are not
# scanned: unchecked tasks are their normal state. The pre-commit hook
# (files = ^openspec/changes/) fires when the archive move is committed,
# which is the moment a change crosses the line.
#
# A withdrawn task is resolved by checking the box and recording in its body
# what replaced it — the validator looks only for `- [ ]`, never for a
# marker syntax. It enforces that every task reached a recorded outcome, not
# that the record is honest (honesty is a review concern, as with the
# REFERENCE.md doc-sync gate).

set -euo pipefail

# Require mikefarah/yq-go (not kislyuk/yq). Re-exec inside the Nix devshell
# if the wrong yq is on PATH or yq is missing entirely.
if ! command -v yq >/dev/null 2>&1 || ! yq --version 2>&1 | grep -q mikefarah; then
  if [[ -z ${MAYI_VALIDATE_REEXEC:-} ]] && command -v nix >/dev/null 2>&1; then
    export MAYI_VALIDATE_REEXEC=1
    exec nix develop -c "$0" "$@"
  fi
  echo "validate-archive-complete: requires mikefarah/yq-go (provided by the Nix devshell)" >&2
  exit 2
fi

# Grandfather cutoff, an ISO date compared lexicographically against the
# directory-name date prefix of openspec/changes/archive/<YYYY-MM-DD>-<name>/.
#
# Archived changes dated before this day predate the archive-completeness
# gate (OpenSpec change `archive-completeness-gate`) and are skipped: 19
# archived changes carried unchecked tasks when the gate landed, and
# retro-fitting outcomes onto finished work would manufacture exactly the
# false records the gate exists to prevent. Their unchecked boxes are honest
# signal and stay. Every change archived on or after this date is covered,
# forever — the constant needs no maintenance and cannot silently re-exempt
# anything. Do not remove it as dead; do not lower it.
CUTOFF="2026-09-01"

# validate_archive ARCHIVE_ROOT CUTOFF
# Scan every <change>/tasks.md under ARCHIVE_ROOT. Changes whose
# directory-name date precedes CUTOFF are grandfathered and skipped.
# Returns non-zero if any covered change has an unchecked task, after
# printing each one with its number and text.
validate_archive() {
  local archive_root=$1 cutoff=$2
  local errors=0 change_dir name date_part tasks

  for change_dir in "$archive_root"/*/; do
    [[ -d $change_dir ]] || continue
    name=$(basename "$change_dir")
    tasks="${change_dir%/}/tasks.md"
    [[ -f $tasks ]] || continue

    # Directory names are <YYYY-MM-DD>-<slug>; the first 10 characters are
    # the date. An unparseable name is treated as post-cutoff: the gate
    # applies. Comparison is lexicographic, which is correct for ISO dates.
    date_part=${name:0:10}
    if [[ ! $date_part =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || [[ $date_part < "$cutoff" ]]; then
      continue
    fi

    if grep -qE '^[[:space:]]*- \[ \]' "$tasks"; then
      errors=$((errors + 1))
      printf '%s: unchecked task(s):\n' "$tasks" >&2
      # Keep the `- [ ]` and task number in the report so the fix is
      # mechanical: the number is the task's identity, the text its claim.
      grep -nE '^[[:space:]]*- \[ \]' "$tasks" | sed 's/^[0-9]*:[[:space:]]*/    /' >&2
    fi
  done

  (( errors == 0 ))
}

run_self_test() {
  local tmp
  tmp=$(mktemp -d)
  # shellcheck disable=SC2064  # intentional: expand $tmp now while in scope
  trap "rm -rf '$tmp'" EXIT

  local archive="$tmp/archive"
  mkdir -p "$archive"
  local pass=0 fail=0

  # fixture LABEL NAME
  # Create an isolated archive root $tmp/<LABEL>/archive containing the one
  # change <NAME>, so cases cannot pollute each other. Echoes the root.
  fixture() {
    local label=$1 name=$2
    mkdir -p "$tmp/$label/archive/$name"
    printf '%s/%s/archive' "$tmp" "$label"
  }

  expect_pass() {
    local label=$1 root=$2
    if validate_archive "$root" "$CUTOFF" 2>/dev/null; then
      pass=$((pass + 1))
    else
      printf 'SELF-TEST FAIL: %s — validator unexpectedly failed\n' "$label" >&2
      fail=$((fail + 1))
    fi
  }

  # expect_fail_named LABEL NEEDLE ROOT
  # Fails the case unless the validator rejects ROOT *and* its output names
  # NEEDLE (the unchecked task's number and text).
  expect_fail_named() {
    local label=$1 needle=$2 root=$3
    local err
    if err=$(validate_archive "$root" "$CUTOFF" 2>&1); then
      printf 'SELF-TEST FAIL: %s — validator unexpectedly passed\n' "$label" >&2
      fail=$((fail + 1))
    elif [[ $err != *"$needle"* ]]; then
      printf 'SELF-TEST FAIL: %s — validator failed but did not name the task (%s)\n' "$label" "$needle" >&2
      fail=$((fail + 1))
    else
      pass=$((pass + 1))
    fi
  }

  # 1. post-cutoff change with every task checked → pass
  cat > "$(fixture complete 2026-09-01-complete-change)/2026-09-01-complete-change/tasks.md" <<'EOF'
# Tasks

## 1. Work

- [x] 1.1 Do the thing.
- [x] 1.2 Do the other thing.
EOF
  expect_pass "complete change" "$(fixture complete 2026-09-01-complete-change)"

  # 2. post-cutoff change with one unchecked task → fail, naming it
  cat > "$(fixture one-unchecked 2026-09-01-one-unchecked)/2026-09-01-one-unchecked/tasks.md" <<'EOF'
# Tasks

## 1. Work

- [ ] 1.1 Create the widget.
- [x] 1.2 Polish the widget.
EOF
  expect_fail_named "one unchecked task is named" "1.1 Create the widget." "$(fixture one-unchecked 2026-09-01-one-unchecked)"

  # 3. pre-cutoff change with unchecked tasks → grandfathered, pass
  cat > "$(fixture pre-cutoff 2000-01-01-pre-cutoff-history)/2000-01-01-pre-cutoff-history/tasks.md" <<'EOF'
# Tasks

## 1. Work

- [ ] 1.1 Abandoned long ago.
- [ ] 1.2 Also abandoned.
EOF
  expect_pass "pre-cutoff change is grandfathered" "$(fixture pre-cutoff 2000-01-01-pre-cutoff-history)"

  # 4. post-cutoff change with unchecked tasks → fail
  cat > "$(fixture post-cutoff 2099-12-31-post-cutoff-unchecked)/2099-12-31-post-cutoff-unchecked/tasks.md" <<'EOF'
# Tasks

## 1. Work

- [x] 1.1 Done.
- [ ] 1.2 Never finished.
- [ ] 1.3 Also never finished.
EOF
  expect_fail_named "post-cutoff unchecked tasks fail" "1.2 Never finished." "$(fixture post-cutoff 2099-12-31-post-cutoff-unchecked)"

  # 5. change dated the cutoff day itself → covered (only *precedes* skips)
  cat > "$(fixture cutoff-day "${CUTOFF}-cutoff-day-is-covered")/${CUTOFF}-cutoff-day-is-covered/tasks.md" <<'EOF'
# Tasks

## 1. Work

- [ ] 1.1 Forgot this one.
EOF
  expect_fail_named "cutoff-day change is covered" "1.1 Forgot this one." "$(fixture cutoff-day "${CUTOFF}-cutoff-day-is-covered")"

  # 6. tasks.md with no checkboxes at all → pass (nothing to enforce)
  cat > "$(fixture no-checkboxes 2099-12-31-no-checkboxes)/2099-12-31-no-checkboxes/tasks.md" <<'EOF'
# Tasks

## 1. Work

Free-form notes; no task list was authored for this change.
EOF
  expect_pass "no checkboxes at all" "$(fixture no-checkboxes 2099-12-31-no-checkboxes)"

  # 7. withdrawn task resolved by checking it with a recorded reason → pass
  cat > "$(fixture withdrawn 2099-12-31-withdrawn-with-reason)/2099-12-31-withdrawn-with-reason/tasks.md" <<'EOF'
# Tasks

## 1. Work

- [x] 1.1 Batch the renders.
  - Withdrawn: measurement showed rendering was already batched upstream;
    no change made.
- [x] 1.2 Ship it.
EOF
  expect_pass "withdrawn task checked with recorded reason" "$(fixture withdrawn 2099-12-31-withdrawn-with-reason)"

  printf 'self-test: %d passed, %d failed\n' "$pass" "$fail"
  return $((fail > 0 ? 1 : 0))
}

main() {
  if [[ ${1:-} == "--self-test" ]]; then
    run_self_test
    return
  fi

  if validate_archive "openspec/changes/archive" "$CUTOFF"; then
    return 0
  fi

  printf '\nResolve each task above: complete it, or check it and record in its body what replaced it and why.\n' >&2
  printf 'Archives dated before %s are grandfathered; see the CUTOFF comment in this script.\n' "$CUTOFF" >&2
  return 1
}

main "$@"
