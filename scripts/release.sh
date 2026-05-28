#!/usr/bin/env bash
# @describe Cut a may-i release. Verifies before mutating; refuses on dirty tree or out-of-sync main.
# @arg version! Version string without leading 'v' (e.g. 0.5.2)
# @flag --dry-run Run preconditions and verification only; skip bump, commit, tag, and push.

set -euo pipefail

die() {
  echo "error: $*" >&2
  exit 1
}

step() {
  echo
  echo "==> $*"
}

require_clean_tree() {
  if [[ -n "$(git status --porcelain)" ]]; then
    die "working tree is dirty; commit or stash before releasing"
  fi
}

require_main_branch() {
  local branch
  branch=$(git rev-parse --abbrev-ref HEAD)
  if [[ $branch != main ]]; then
    die "must release from 'main' (currently on '$branch')"
  fi
}

require_in_sync_with_origin() {
  git fetch --quiet origin main
  local local_sha origin_sha
  local_sha=$(git rev-parse HEAD)
  origin_sha=$(git rev-parse origin/main)
  if [[ $local_sha != "$origin_sha" ]]; then
    die "local main ($local_sha) does not match origin/main ($origin_sha); pull or push before releasing"
  fi
}

require_tooling() {
  if ! command -v cargo-fuzz >/dev/null 2>&1; then
    die "cargo-fuzz not found; install with: cargo install cargo-fuzz"
  fi
  if ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
    die "nightly toolchain not installed; install with: rustup toolchain install nightly"
  fi
}

require_tag_unused() {
  local tag="$1"
  if git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null; then
    die "tag $tag already exists locally"
  fi
  if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then
    die "tag $tag already exists on origin"
  fi
}

verify() {
  step "cargo fmt --all --check"
  cargo fmt --all --check

  step "cargo clippy --workspace --all-targets -- -D warnings"
  cargo clippy --workspace --all-targets -- -D warnings

  step "cargo tarpaulin"
  cargo tarpaulin

  step "cargo +nightly fuzz run fuzz_evaluator (60s)"
  (cd fuzz && cargo +nightly fuzz run fuzz_evaluator -- -max_total_time=60)

  step "nix build .#default --no-link"
  nix build .#default --no-link
}

bump_cargo_version() {
  local version="$1"
  local file=Cargo.toml
  if ! grep -qE '^version = ".*"' "$file"; then
    die "could not find 'version = \"...\"' line in $file"
  fi
  sed -i.bak -E "s/^version = \".*\"/version = \"$version\"/" "$file"
  rm -f "$file.bak"
}

mutate_and_push() {
  local version="$1"
  local tag="v$version"

  step "bump Cargo.toml to $version"
  bump_cargo_version "$version"

  step "cargo check (refresh Cargo.lock)"
  cargo check --workspace --quiet

  step "commit"
  git add Cargo.toml Cargo.lock
  git commit -m "Release $tag"

  step "tag $tag"
  git tag -a "$tag" -m "$tag"

  step "push main"
  git push origin main

  step "push tag $tag"
  git push origin "$tag"
}

main() {
  # shellcheck disable=SC2154  # set by argc-eval below
  local version="$argc_version"
  # shellcheck disable=SC2154
  local dry_run="${argc_dry_run:-0}"
  local tag="v$version"

  step "preconditions"
  require_clean_tree
  require_main_branch
  require_in_sync_with_origin
  require_tooling
  require_tag_unused "$tag"

  step "verification (no mutations yet)"
  verify

  if [[ $dry_run == 1 ]]; then
    echo
    echo "==> dry run: verification passed for $tag; skipping bump, commit, tag, and push"
    exit 0
  fi

  step "mutations"
  mutate_and_push "$version"

  echo
  echo "==> released $tag"
}

eval "$(argc --argc-eval "$0" "$@")"
