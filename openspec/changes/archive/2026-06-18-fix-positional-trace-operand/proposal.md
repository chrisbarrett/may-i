## Why

The human trace mis-labels the tested value for every positional element after
the first. `distribute_positional_at_top` (`src/annotation.rs`) extracts only
`positional_args.first()` and threads that single value into every pattern
element, so a rule like

```
(positional "source-file" (or "~/.config/tmux/custom.conf" "~/.config/tmux/tmux.conf"))
```

evaluated against `tmux source-file ~/.config/tmux/custom.conf` renders the
`or` branches as `"source-file" = "~/.config/tmux/custom.conf" → no` — comparing
the second pattern against the *first* argv slot. The decision is correct
(matching runs in the engine, which advances args per element); only the
rendered evidence picks the wrong operand, which is actively misleading when a
trace is the thing a user is reading to understand a floor or a no-match.

## What Changes

- The positional matcher (`match_positional_patterns`) SHALL record, along its
  **winning (backtracking) path**, a per-element trace: for each pattern element
  the argument index it was tested against (the match cursor when the element
  was evaluated), the count it consumed, and whether it matched. On a failed
  match the trace covers the prefix up to and including the element that failed.
  Because this is the same path the decision is taken on, it is correct for
  optional/repeated quantifiers that backtrack — a greedy renderer-side walk is
  not (a `(* X) X`-shape pattern gives back args, so a forward greedy walk
  misattributes the required element's operand).
- `build_positional_element_details` SHALL derive each element's
  `tested_arg`/`consumed_args`/`matched` from that trace instead of re-deriving
  consumption greedily.
- The detail (with `tested_arg`) SHALL be available on **both** the effect path
  (`effect_arg_match`/`effect_arg_continuation`) and the predicate path: the
  `EvalFold::predicate_arg` method gains the `Vec<PositionalElementDetail>`, and
  the predicate evaluator builds it.
- The trace renderer SHALL annotate each positional element against its
  `tested_arg`, removing the renderer-side `tested_args_for` cursor walk and the
  `extract_positional_args` flag stripper — both of which duplicated, and could
  drift from, the engine's matching.
- Element match detail (`match_kind`) SHALL be keyed off the tested value, not
  the consumed value, so an element that failed or a skipped optional — which
  consumed nothing — still carries its comparison. A regex element SHALL render
  its `(regex "…")` source on the left with the `~`-comparison on the right in
  both the matched and failed cases (the renderer attaches evidence to the
  source node instead of collapsing it to an empty atom).
- Add the operand-fidelity contract to the `traces` spec as new scenarios under
  "Argument match annotations show evidence".

## Capabilities

### Modified Capabilities

- `traces` (bucket: tracing-and-output; contributor): a multi-element positional
  match annotates each element against the argument the matcher tested it with
  on its winning backtracking path; unreached elements are unannotated.

## Impact

- `crates/engine/src/eval/positional.rs` — `PositionalMatch` carries a
  per-element match trace built on the winning path; `build_positional_element_details`
  becomes a mapper over it and emits `tested_arg`. Display-only fields; no
  decision change (the trace records the path the decision already took).
- `crates/engine/src/fold.rs`, `audit_fold.rs` — `PositionalElementDetail`
  gains `tested_arg`; `predicate_arg` gains the positional-element detail.
- `crates/engine/src/eval/predicates.rs` — predicate arg evaluation builds the
  element detail.
- `src/annotation.rs` — consumes `tested_arg`; deletes `tested_args_for` and
  `extract_positional_args`; `predicate_arg`/`effect_arg_*` annotate via the
  shared per-element pass.
