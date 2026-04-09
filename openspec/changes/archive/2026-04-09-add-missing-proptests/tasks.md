## 1. Config parse roundtrip proptest

- [ ] 1.1 Add proptest to crates/config/: generate valid config sexpr → parse → serialize → parse → compare
- [x] 1.2 Verify proptest passes with 256 cases

## 2. CST pretty_serialize roundtrip proptest

- [x] 2.1 Add proptest to crates/sexpr/src/cst.rs: parse → pretty_serialize(width) → parse → compare structure
- [x] 2.2 Test with widths from 20..120 columns

## 3. Positional backtracking proptest

- [ ] 3.1 Add proptest to crates/engine/src/eval/positional.rs: verify matched + unconsumed = original
- [ ] 3.2 Add property: ZeroOrMore is greedy (maximal match)
- [ ] 3.3 Add property: matching is deterministic

## 4. Cycle detection proptest

- [x] 4.1 Add proptest to crates/config/src/resolve.rs: generate random define graphs
- [x] 4.2 Add property: acyclic graphs pass validation
- [x] 4.3 Add property: graphs with cycles are rejected

## 5. Expression parser roundtrip proptest

- [x] 5.1 Add proptest to crates/config/src/pattern.rs: generate Expr → serialize → parse → compare

## 6. Rendering never-panics proptest

- [x] 6.1 Add proptest to src/output/render_rule.rs: random annotated configs → render without panic

## 7. Layout word_wrap proptest

- [x] 7.1 Add proptest to crates/layout/src/lib.rs: all words preserved, no line exceeds width
