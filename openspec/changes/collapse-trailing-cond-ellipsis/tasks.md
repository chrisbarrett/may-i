## 1. Core Implementation

- [ ] 1.1 Modify `TracingFold::effect_cond` in `src/annotation.rs` to detect trailing `(Skipped, Skipped)` branches and collapse them (plus any skipped fallback) into a single dimmed `…` atom
- [ ] 1.2 Add unit tests for the new collapsing behaviour: match in middle, match at first branch, no match (all evaluated), single trailing branch

## 2. Snapshot Updates

- [ ] 2.1 Run existing tests, update any failing trace snapshots to reflect collapsed cond output
- [ ] 2.2 Verify oracle trace output matches expected collapsed format using `may-i` binary
