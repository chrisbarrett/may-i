## 1. Parse process substitutions self-containedly

- [ ] 1.1 Write failing parser tests: `cat <(rm -rf /danger)` yields a `WordPart::ProcessSubstitution` whose inner command is `rm -rf /danger`; `diff <(a) <(b)` yields two; a nested `<(grep $(date) f)` parses with balanced parens.
- [ ] 1.2 Write failing parser tests for redirect-target position: `while read x; do :; done < <(rm -rf /danger)` captures the procsub inner command and parses with no Error diagnostic.
- [ ] 1.3 Ensure process-substitution parsing stops at the matching `)` in both positions; disambiguate `<(` (procsub) from `< (` (subshell). Balanced-paren scan over the inner command.

## 2. No desync inside compounds

- [ ] 2.1 Write failing tests: `f() { while read x; do :; done < <(find .); rm -rf /danger; }` retains `rm -rf /danger`; subshell variant `( … done < <(find .); rm x )` retains `rm`; assert no `MissingClosingKeyword` warning for these.
- [ ] 2.2 Fix the redirect/compound interaction so a procsub redirect target does not consume the enclosing group's terminator (`}` / `)`).
- [ ] 2.3 Regression guard (stays green): the command-substitution target `< "$(echo f)"` case keeps its trailing `rm`.

## 3. Evaluate inner commands

- [ ] 3.1 Write failing engine scenarios: the four spec scenarios — inner `rm` in argument and redirect position evaluated to `:ask`; trailing `rm` after the loop evaluated; `>(…)` output form evaluated.
- [ ] 3.2 In `decompose`, emit an embedded unit for a process substitution's inner command (arg + redirect target), reusing the `$(…)` `EmbeddedCommand` path; keep procsub reason unannotated.

## 4. No-silent-loss backstop & docs

- [ ] 4.1 Write a test that any residual unplaceable procsub input emits an Error-severity diagnostic and floors to `:ask` (no dropped tokens).
- [ ] 4.2 Run the motivating terragrunt script in hook mode; confirm the `find` inside `< <(…)` and commands after the loop are now evaluated (residual asks limited to the out-of-scope dynamic `$TGBIN`).
- [ ] 4.3 `cargo fmt`; run `cargo tarpaulin`, inspect `lcov.info` for uncovered branches in the procsub paths.
- [ ] 4.4 Check in any new `proptest-regressions/` files.
