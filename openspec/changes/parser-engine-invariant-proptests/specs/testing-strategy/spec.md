## MODIFIED Requirements

### Requirement: Key invariants are verified

Property tests SHALL cover these invariant classes:

- **No panics**: Evaluation functions never panic on valid inputs
- **Boolean algebra**: And/Or/Not obey standard laws including De Morgan's
- **Determinism**: Same input always produces same output
- **Recursion limits**: Depth limits are respected and produce Ask
- **Type safety**: Predicates return Match/NoMatch, effects return Decision/Nil
- **Span bounds**: every span emitted by the evaluation pipeline lies
  within input bounds (`0 ≤ start ≤ end ≤ input.len()`)
- **Embedded source fidelity**: every `EvalUnit::EmbeddedCommand`'s
  recorded source agrees with the bytes at its recorded span
- **Quoted-region inviolability**: bytes inside single-quoted strings
  or quoted-delimiter heredoc bodies (`<<'EOF' … EOF`) do not surface
  as `SimpleCommand` or `EmbeddedCommand` units
- **Recursive locality**: segment decisions produced by recursing
  into an embedded command stay within the embedded command's span
- **Parser/engine paren-matcher agreement**: the lexer's
  `read_balanced_parens` and the engine's `find_balanced_paren`
  identify the same closing position for any `$()` substitution

#### Scenario: Suite covers each named invariant
- **WHEN** the test suite runs
- **THEN** at least one `proptest!` function exercises each invariant
  class above, and the property-to-spec mapping is documented in the
  `parser-engine-invariants` capability
