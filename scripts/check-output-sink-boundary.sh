#!/usr/bin/env bash
# Output-boundary gate (display-safe-output capability):
#
# The single output sink (`src/sink.rs`) is the only code allowed to acquire a
# process stream handle. clippy's `print_stdout`/`print_stderr` denies catch the
# `print*!` macros, but miss handle acquisition like `writeln!(io::stderr(), …)`
# or `console::Term::stderr()`. This hook closes that gap with an ast-grep
# structural scan (which ignores comments and string literals) for `io::stdout`,
# `io::stderr`, `console::Term::stdout`/`stderr`, and raw terminal fds anywhere
# outside the sink module and test code.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

rule="scripts/output-sink-boundary.yml"

# Tracked Rust sources, excluding the sink (the sanctioned owner) and test code
# (integration tests under tests/, and crate-internal test submodules under
# src/**/tests/ or crates/**/tests/).
mapfile -t files < <(
  git ls-files '*.rs' \
    | grep -v '^src/sink.rs$' \
    | grep -v '/tests/' \
    | grep -v '^tests/' \
    | while IFS= read -r f; do [[ -f "$f" ]] && printf '%s\n' "$f"; done
)

if [[ ${#files[@]} -eq 0 ]]; then
  exit 0
fi

# ast-grep scan exits non-zero when an error-severity rule matches.
ast-grep scan --rule "$rule" "${files[@]}"
