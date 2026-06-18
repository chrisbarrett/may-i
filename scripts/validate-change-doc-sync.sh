#!/usr/bin/env bash
# Enforce the REFERENCE.md doc-sync gate on OpenSpec changes.
#
# Required: yq-go (mikefarah/yq) v4+. Provided by the Nix devshell.
#
# Rule (per openspec/specs/spec-conventions/spec.md):
#   A change whose delta under openspec/changes/<change>/specs/<cap>/spec.md
#   ADDS or MODIFIES a requirement for a *user-facing* capability MUST carry
#   at least one task in that change's tasks.md whose text names REFERENCE.md.
#
# REFERENCE.md is compiled into the binary (src/cmd_help.rs, include_str!) and
# rendered by `may-i reference`, so a surface change that skips it ships a
# stale manual. The task is a *consideration* task — satisfied by either an
# edit or a recorded "verified, no surface change" note. This script enforces
# the task's PRESENCE, not its resolution (honesty is a review concern).
#
# Audience is read from the stable spec (openspec/specs/<cap>/spec.md); delta
# files carry no frontmatter. A delta for a capability with no stable spec is
# treated as user-facing unless its own optional frontmatter declares
# bucket: contributor-internals.

set -euo pipefail

# Require mikefarah/yq-go (not kislyuk/yq). Re-exec inside the Nix devshell
# if the wrong yq is on PATH or yq is missing entirely.
if ! command -v yq >/dev/null 2>&1 || ! yq --version 2>&1 | grep -q mikefarah; then
  if [[ -z ${MAYI_VALIDATE_REEXEC:-} ]] && command -v nix >/dev/null 2>&1; then
    export MAYI_VALIDATE_REEXEC=1
    exec nix develop -c "$0" "$@"
  fi
  echo "validate-change-doc-sync: requires mikefarah/yq-go (provided by the Nix devshell)" >&2
  exit 2
fi

# delta_is_user_facing DELTA SPECS_ROOT
# Echoes "user" if the delta adds/modifies a requirement for a user-facing
# capability, "" otherwise. Removal-only / structural deltas echo "".
delta_is_user_facing() {
  local delta=$1 specs_root=$2

  # Only ADDED/MODIFIED count; REMOVED-only and structural deltas do not.
  if ! grep -qE '^## (ADDED|MODIFIED) Requirements' "$delta"; then
    return 0
  fi

  local cap stable audience bucket
  cap=$(basename "$(dirname "$delta")")
  stable="$specs_root/$cap/spec.md"

  if [[ -f $stable ]]; then
    audience=$(yq --front-matter=extract '.audience // "null"' "$stable" 2>/dev/null || echo "null")
    [[ $audience == "user" ]] && echo "user"
    return 0
  fi

  # New capability: no stable spec. Default user-facing unless the delta opts
  # out via its own frontmatter declaring bucket: contributor-internals.
  bucket="null"
  if head -1 "$delta" | grep -qxF -- '---'; then
    bucket=$(yq --front-matter=extract '.bucket // "null"' "$delta" 2>/dev/null || echo "null")
  fi
  [[ $bucket != "contributor-internals" ]] && echo "user"
  return 0
}

# validate_change CHANGE_DIR SPECS_ROOT
validate_change() {
  local change_dir=$1 specs_root=$2
  local triggered=0 delta

  for delta in "$change_dir"/specs/*/spec.md; do
    [[ -f $delta ]] || continue
    if [[ -n $(delta_is_user_facing "$delta" "$specs_root") ]]; then
      triggered=1
    fi
  done

  (( triggered == 0 )) && return 0

  # The gate begins at tasks-authoring time. A change with no tasks.md has not
  # reached apply-readiness (openspec applyRequires=[tasks]); it cannot be
  # applied or archived until tasks.md exists, at which point the gate fires.
  local tasks="$change_dir/tasks.md"
  [[ -f $tasks ]] || return 0

  if grep -q 'REFERENCE\.md' "$tasks"; then
    return 0
  fi

  printf '%s: user-facing spec delta requires a tasks.md task naming REFERENCE.md\n' "$change_dir" >&2
  printf '  (consideration task: edit REFERENCE.md or record "verified, no surface change")\n' >&2
  return 1
}

run_self_test() {
  local tmp
  tmp=$(mktemp -d)
  # shellcheck disable=SC2064  # intentional: expand $tmp now while in scope
  trap "rm -rf '$tmp'" EXIT

  local specs="$tmp/specs"
  mkdir -p "$specs/patterns" "$specs/spec-conventions"
  cat > "$specs/patterns/spec.md" <<'EOF'
---
audience: user
bucket: parsing
---
# patterns Specification
EOF
  cat > "$specs/spec-conventions/spec.md" <<'EOF'
---
audience: contributor
bucket: contributor-internals
---
# spec-conventions Specification
EOF

  local pass=0 fail=0

  expect_fail() {
    local label=$1 dir=$2
    if validate_change "$dir" "$specs" 2>/dev/null; then
      printf 'SELF-TEST FAIL: %s — validator unexpectedly passed\n' "$label" >&2
      fail=$((fail + 1))
    else
      pass=$((pass + 1))
    fi
  }
  expect_pass() {
    local label=$1 dir=$2
    if validate_change "$dir" "$specs" 2>/dev/null; then
      pass=$((pass + 1))
    else
      printf 'SELF-TEST FAIL: %s — validator unexpectedly failed\n' "$label" >&2
      fail=$((fail + 1))
    fi
  }

  # 1. user-facing ADDED, no REFERENCE.md task → fail
  mkdir -p "$tmp/c1/specs/patterns"
  printf '## ADDED Requirements\n\n### Requirement: X\n\nFoo SHALL bar.\n' > "$tmp/c1/specs/patterns/spec.md"
  printf '# Tasks\n\n## 1. Work\n- [ ] 1.1 Do the thing.\n' > "$tmp/c1/tasks.md"
  expect_fail "user-facing add without REFERENCE.md task" "$tmp/c1"

  # 2. user-facing ADDED, with REFERENCE.md task → pass
  mkdir -p "$tmp/c2/specs/patterns"
  printf '## ADDED Requirements\n\n### Requirement: X\n\nFoo SHALL bar.\n' > "$tmp/c2/specs/patterns/spec.md"
  printf '# Tasks\n\n## 1. Docs\n- [ ] 1.1 Update REFERENCE.md quantifier table.\n' > "$tmp/c2/tasks.md"
  expect_pass "user-facing add with REFERENCE.md task" "$tmp/c2"

  # 3. contributor-only ADDED (spec-conventions), no task → pass
  mkdir -p "$tmp/c3/specs/spec-conventions"
  printf '## ADDED Requirements\n\n### Requirement: Y\n\nThing SHALL hold.\n' > "$tmp/c3/specs/spec-conventions/spec.md"
  printf '# Tasks\n\n## 1. Work\n- [ ] 1.1 Do it.\n' > "$tmp/c3/tasks.md"
  expect_pass "contributor-only add without REFERENCE.md task" "$tmp/c3"

  # 4. user-facing REMOVED-only, no task → pass
  mkdir -p "$tmp/c4/specs/patterns"
  printf '## REMOVED Requirements\n\n- Old thing.\n' > "$tmp/c4/specs/patterns/spec.md"
  printf '# Tasks\n\n## 1. Work\n- [ ] 1.1 Remove it.\n' > "$tmp/c4/tasks.md"
  expect_pass "removal-only user-facing without REFERENCE.md task" "$tmp/c4"

  # 5. new capability (no stable spec), default user-facing, no task → fail
  mkdir -p "$tmp/c5/specs/brand-new-cap"
  printf '## ADDED Requirements\n\n### Requirement: Z\n\nNew SHALL exist.\n' > "$tmp/c5/specs/brand-new-cap/spec.md"
  printf '# Tasks\n\n## 1. Work\n- [ ] 1.1 Build it.\n' > "$tmp/c5/tasks.md"
  expect_fail "new capability default user-facing without REFERENCE.md task" "$tmp/c5"

  # 6. new contributor capability opting out via delta frontmatter, no task → pass
  mkdir -p "$tmp/c6/specs/internal-cap"
  cat > "$tmp/c6/specs/internal-cap/spec.md" <<'EOF'
---
bucket: contributor-internals
---
## ADDED Requirements

### Requirement: W

Internal SHALL hold.
EOF
  printf '# Tasks\n\n## 1. Work\n- [ ] 1.1 Build it.\n' > "$tmp/c6/tasks.md"
  expect_pass "new contributor capability (delta opt-out) without REFERENCE.md task" "$tmp/c6"

  # 7. change with no spec deltas → pass
  mkdir -p "$tmp/c7"
  printf '# Tasks\n\n## 1. Work\n- [ ] 1.1 Tooling only.\n' > "$tmp/c7/tasks.md"
  expect_pass "change with no spec deltas" "$tmp/c7"

  # 8. user-facing delta but no tasks.md yet (proposal stage) → pass (deferred)
  mkdir -p "$tmp/c8/specs/patterns"
  printf '## ADDED Requirements\n\n### Requirement: V\n\nFoo SHALL bar.\n' > "$tmp/c8/specs/patterns/spec.md"
  expect_pass "user-facing delta with no tasks.md yet" "$tmp/c8"

  printf 'self-test: %d passed, %d failed\n' "$pass" "$fail"
  return $((fail > 0 ? 1 : 0))
}

main() {
  if [[ ${1:-} == "--self-test" ]]; then
    run_self_test
    return
  fi

  local total_errors=0
  local change_dir name
  for change_dir in openspec/changes/*/; do
    [[ -d $change_dir ]] || continue
    name=$(basename "$change_dir")
    [[ $name == "archive" ]] && continue
    if ! validate_change "${change_dir%/}" "openspec/specs"; then
      total_errors=$((total_errors + 1))
    fi
  done

  if (( total_errors > 0 )); then
    printf '\n%d change(s) failed the REFERENCE.md doc-sync gate\n' "$total_errors" >&2
    return 1
  fi
}

main "$@"
