#!/usr/bin/env bash
# Validate YAML frontmatter on stable specs.
#
# Required: yq-go (mikefarah/yq) v4+. Provided by the Nix devshell.
#
# Schema (per openspec/specs/spec-conventions/spec.md):
#   audience: user | contributor          (required)
#   bucket:   <one of the 10 buckets>     (required)
#   trust-relevant: true | false          (optional, default false)
#
# Invariant: audience: user MUST NOT pair with bucket: contributor-internals.

set -euo pipefail

# Require mikefarah/yq-go (not kislyuk/yq). Re-exec inside the Nix devshell
# if the wrong yq is on PATH or yq is missing entirely.
if ! command -v yq >/dev/null 2>&1 || ! yq --version 2>&1 | grep -q mikefarah; then
  if [[ -z ${MAYI_VALIDATE_REEXEC:-} ]] && command -v nix >/dev/null 2>&1; then
    export MAYI_VALIDATE_REEXEC=1
    exec nix develop -c "$0" "$@"
  fi
  echo "validate-spec-frontmatter: requires mikefarah/yq-go (provided by the Nix devshell)" >&2
  exit 2
fi

readonly BUCKETS=(
  rules-and-evaluation
  facts
  parsing
  trust
  loading
  tracing-and-output
  migration
  cli
  testing
  contributor-internals
)

readonly AUDIENCES=(user contributor)

contains() {
  local needle=$1
  shift
  local item
  for item in "$@"; do
    [[ $item == "$needle" ]] && return 0
  done
  return 1
}

validate_spec() {
  local spec=$1
  local errors=0

  if ! head -1 "$spec" | grep -qxF -- '---'; then
    printf '%s: missing YAML frontmatter (file must start with ---)\n' "$spec" >&2
    return 1
  fi

  local audience bucket trust
  if ! audience=$(yq --front-matter=extract '.audience' "$spec" 2>/dev/null); then
    printf '%s: frontmatter is not valid YAML\n' "$spec" >&2
    return 1
  fi

  bucket=$(yq --front-matter=extract '.bucket' "$spec")
  trust=$(yq --front-matter=extract '.["trust-relevant"] // false' "$spec")

  if [[ $audience == "null" || -z $audience ]]; then
    printf '%s: missing required field: audience\n' "$spec" >&2
    errors=$((errors + 1))
  elif ! contains "$audience" "${AUDIENCES[@]}"; then
    printf "%s: audience must be 'user' or 'contributor', got '%s'\n" "$spec" "$audience" >&2
    errors=$((errors + 1))
  fi

  if [[ $bucket == "null" || -z $bucket ]]; then
    printf '%s: missing required field: bucket\n' "$spec" >&2
    errors=$((errors + 1))
  elif ! contains "$bucket" "${BUCKETS[@]}"; then
    printf "%s: unknown bucket '%s' (valid: %s)\n" "$spec" "$bucket" "${BUCKETS[*]}" >&2
    errors=$((errors + 1))
  fi

  if [[ $trust != "true" && $trust != "false" ]]; then
    printf "%s: trust-relevant must be boolean, got '%s'\n" "$spec" "$trust" >&2
    errors=$((errors + 1))
  fi

  if [[ $audience == "user" && $bucket == "contributor-internals" ]]; then
    printf '%s: audience=user incompatible with bucket=contributor-internals\n' "$spec" >&2
    errors=$((errors + 1))
  fi

  return $((errors > 0 ? 1 : 0))
}

run_self_test() {
  local tmp
  tmp=$(mktemp -d)
  # shellcheck disable=SC2064  # intentional: expand $tmp now while in scope
  trap "rm -rf '$tmp'" EXIT

  local pass=0 fail=0

  expect_fail() {
    local label=$1 spec=$2
    if validate_spec "$spec" 2>/dev/null; then
      printf 'SELF-TEST FAIL: %s — validator unexpectedly passed\n' "$label" >&2
      fail=$((fail + 1))
    else
      pass=$((pass + 1))
    fi
  }
  expect_pass() {
    local label=$1 spec=$2
    if validate_spec "$spec" 2>/dev/null; then
      pass=$((pass + 1))
    else
      printf 'SELF-TEST FAIL: %s — validator unexpectedly failed\n' "$label" >&2
      fail=$((fail + 1))
    fi
  }

  cat > "$tmp/no-frontmatter.md" <<'EOF'
# Foo Specification

## Purpose
...
EOF
  expect_fail "missing frontmatter" "$tmp/no-frontmatter.md"

  cat > "$tmp/bad-audience.md" <<'EOF'
---
audience: internal
bucket: parsing
---
# Foo Specification
EOF
  expect_fail "unknown audience" "$tmp/bad-audience.md"

  cat > "$tmp/bad-bucket.md" <<'EOF'
---
audience: user
bucket: nonsense
---
# Foo Specification
EOF
  expect_fail "unknown bucket" "$tmp/bad-bucket.md"

  cat > "$tmp/missing-bucket.md" <<'EOF'
---
audience: user
---
# Foo Specification
EOF
  expect_fail "missing bucket" "$tmp/missing-bucket.md"

  cat > "$tmp/contradiction.md" <<'EOF'
---
audience: user
bucket: contributor-internals
---
# Foo Specification
EOF
  expect_fail "contradictory audience+bucket" "$tmp/contradiction.md"

  cat > "$tmp/valid-user.md" <<'EOF'
---
audience: user
bucket: parsing
---
# Foo Specification
EOF
  expect_pass "valid user/parsing" "$tmp/valid-user.md"

  cat > "$tmp/valid-trust.md" <<'EOF'
---
audience: user
bucket: trust
trust-relevant: true
---
# Trust Specification
EOF
  expect_pass "valid user/trust + trust-relevant" "$tmp/valid-trust.md"

  cat > "$tmp/valid-contributor.md" <<'EOF'
---
audience: contributor
bucket: contributor-internals
---
# Foo Specification
EOF
  expect_pass "valid contributor/internals" "$tmp/valid-contributor.md"

  printf 'self-test: %d passed, %d failed\n' "$pass" "$fail"
  return $((fail > 0 ? 1 : 0))
}

main() {
  if [[ ${1:-} == "--self-test" ]]; then
    run_self_test
    return
  fi

  local total_errors=0
  local spec
  for spec in openspec/specs/*/spec.md; do
    [[ -f $spec ]] || continue
    if ! validate_spec "$spec"; then
      total_errors=$((total_errors + 1))
    fi
  done

  if (( total_errors > 0 )); then
    printf '\n%d spec(s) failed frontmatter validation\n' "$total_errors" >&2
    return 1
  fi
}

main "$@"
