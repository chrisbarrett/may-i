## MODIFIED Requirements

### Requirement: Argument match annotations show evidence
When an argument pattern is evaluated, the right-column annotation SHALL show
the tested value, the argument set, and the match verdict. Annotations SHALL be
correlated with rendered lines via structural annotation threading through the
pretty-printer, not via string-based needle matching.

#### Scenario: Anywhere match shows set membership
- **WHEN** `(anywhere "-r")` matches against args `["-r", "-f", "/"]`
- **THEN** the annotation reads `"-r" ∈ {"-r", "-f", "/"} → yes`

#### Scenario: Positional match shows equality test
- **WHEN** `(positional "push")` is tested against positional arg `"pull"`
- **THEN** the annotation reads `"pull" = "push" → no`

#### Scenario: Multi-token anywhere distributes annotations to atoms
- **WHEN** `(anywhere "rm" "rf")` is rendered in broken layout with each token
  on its own line
- **THEN** each token's line carries its own annotation directly from the
  pretty-printer output
- **AND** no substring search is needed to place annotations

### Requirement: Annotation placement is structural, not string-based
The trace renderer SHALL place right-column annotations on rendered lines by
reading annotation data carried through the pretty-printer's structured output,
not by searching rendered text for annotation needles.

#### Scenario: Identical tokens on different lines get correct annotations
- **WHEN** a rule contains two identical string literals on different lines with
  different evaluation results
- **THEN** each line receives its own correct annotation without ambiguity

#### Scenario: Rendered output is identical to prior string-matching approach
- **WHEN** any trace is rendered using the structural annotation approach
- **THEN** the terminal output is byte-identical to the output produced by the
  prior string-matching approach (validated by oracle snapshot tests)
