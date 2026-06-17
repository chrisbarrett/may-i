## 1. Reproduce the gap

- [ ] 1.1 Write failing decompose tests: a `$(rm -rf /)` in a bare assignment value (`z=$(rm -rf /); echo done`), in for-loop words (`for x in $(rm -rf /); do :; done`), and in a case subject (`case $(rm -rf /) in *) :;; esac`) each yields an `EmbeddedCommand` unit with source `rm -rf /`.
- [ ] 1.2 Write failing engine scenario tests mirroring the spec: each of the three inputs decides `:deny` when a rule denies `rm` (proving the embedded `rm` is now evaluated).

## 2. Extend embedded extraction to all word positions

- [ ] 2.1 Add a whole-tree word walk (sibling to `push_embedded_units_from_redirect_targets`) that hands assignment values (bare `Command::Assignment`), `For` iteration words, and `Case` subject + pattern words to `push_embedded_units_from_word`. Partition ownership so simple-command words and redirect targets keep their existing source and nothing is double-counted.
- [ ] 2.2 Confirm span/coordinate handling matches the existing paths: the existing top-level-segment-disjointness and span-bounds proptests still pass; nested substitutions colour correctly.

## 3. Coverage invariant

- [ ] 3.1 Add a property test (generator covering assignment/For/Case contexts, not just simple commands): for every command/backtick/process substitution in the input, `decompose` produces a matching `EmbeddedCommand` unit. Arithmetic `$(( … ))` produces none.
- [ ] 3.2 Check in any new `proptest-regressions/` files.

## 4. Verify

- [ ] 4.1 `cargo fmt`; run the full suite and `cargo tarpaulin`, inspecting `lcov.info` for uncovered branches in the new walk.
- [ ] 4.2 End-to-end via the binary: the three motivating inputs no longer resolve `:allow` with an unreviewed `rm`.
