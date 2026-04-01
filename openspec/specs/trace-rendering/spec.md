## ADDED Requirements

### Requirement: Two-column terminal trace layout
The trace renderer SHALL display rule evaluations in a two-column layout: the
left column contains the pretty-printed s-expression of the rule, and the right
column contains evaluation annotations separated by a `│` divider.

#### Scenario: Basic rule trace
- **WHEN** rendering a trace for `ls -la` matching a read-only filesystem rule
- **THEN** the left column shows the rule s-expression (e.g., `(rule (command (or "cat" "ls" ...)) (effect :allow "Read-only filesystem access"))`)
- **AND** the right column shows `→ :allow "Read-only filesystem access"` on the
  effect line

#### Scenario: Layout adapts to terminal width
- **WHEN** the terminal width is detected
- **THEN** the left column occupies approximately half the usable width
- **AND** annotations in the right column are placed adjacent to their
  corresponding s-expression lines

### Requirement: Argument match annotations show evidence
When an argument pattern is evaluated, the right-column annotation SHALL show
the tested value, the argument set, and the match verdict.

#### Scenario: Anywhere match shows set membership
- **WHEN** `(anywhere "-r")` matches against args `["-r", "-f", "/"]`
- **THEN** the annotation reads `"-r" ∈ {"-r", "-f", "/"} → yes`

#### Scenario: Positional match shows equality test
- **WHEN** `(positional "push")` is tested against positional arg `"pull"`
- **THEN** the annotation reads `"pull" = "push" → no`

### Requirement: Decision keywords are colorised
Terminal trace output SHALL colorise decision keywords: `:allow` in green,
`:ask` in yellow, `:deny` in red.

#### Scenario: Allow is green
- **WHEN** the trace shows `→ :allow "reason"`
- **THEN** `:allow` is rendered in green

#### Scenario: Deny is red
- **WHEN** the trace shows `→ :deny "reason"`
- **THEN** `:deny` is rendered in red

### Requirement: Unevaluated branches are dimmed
When short-circuiting skips child nodes, those nodes SHALL be rendered in dimmed
style in the left column with no right-column annotation.

#### Scenario: Or stops at first match
- **GIVEN** `(or (positional "push") (positional "pull"))` where `"push"` matches
- **THEN** the `(positional "pull")` line is rendered dimmed

### Requirement: Long or-lists are truncated with elision
When a `(command (or ...))` list contains many alternatives, the renderer SHALL
truncate after a reasonable number of items and show `…` for the rest.

#### Scenario: Command list with many alternatives
- **WHEN** a command pattern has 20+ alternatives and the matching one is present
- **THEN** the rendered s-expression shows the matching command and a few
  neighbours, with `…` indicating omitted items

### Requirement: Compound commands show per-segment traces
When evaluating a compound command (e.g., `echo hello && rm -rf /`), each
command segment SHALL be traced separately with a segment header showing the
command text and its decision.

#### Scenario: Compound command with mixed decisions
- **WHEN** evaluating `echo hello && rm -rf /`
- **THEN** the trace shows a header for `echo hello` (allow) and a separate
  header for `rm -rf /` (deny)
- **AND** each segment has its own rule trace

### Requirement: Result section shows aggregate decision
After the trace section, the renderer SHALL print a result section showing the
full command (colorised per-segment by decision), an arrow with the aggregate
decision keyword, and the config file path.

#### Scenario: Simple command result
- **WHEN** `ls -la` evaluates to allow
- **THEN** the result section shows `ls -la` followed by `→ :allow "reason"`
  and the config path

#### Scenario: Compound command result with color
- **WHEN** `echo hello && rm -rf /` evaluates to deny
- **THEN** `echo hello` is shown in green (allow) and `rm -rf /` in red (deny)

### Requirement: JSON trace serialises Doc<Ann> tree
When `--json` is passed to `may-i eval`, the output SHALL include a `trace`
array where each entry contains the rule's source line, a structured
representation of the s-expression, and an array of annotations with type,
decision, match details, and failure reasons.

#### Scenario: JSON trace for simple eval
- **WHEN** `may-i eval --json 'ls -la'` is run
- **THEN** the output is valid JSON with `decision`, `reason`, and `trace` fields
- **AND** the `trace` array contains rule entries with `line`, `structure`, and
  `annotations`

### Requirement: Check command runs all embedded checks
`may-i check` SHALL evaluate all embedded `(check ...)` forms (both rule-level
and top-level) and report pass/fail results.

#### Scenario: All checks pass
- **WHEN** all checks in the config match their expected decisions
- **THEN** the output shows a summary line like `✓ N passed, 0 failed`

#### Scenario: Check failure shows trace
- **WHEN** a check's actual decision differs from its expected decision
- **THEN** the output shows the failing check's command, location, expected vs
  actual decisions, and a full evaluation trace

### Requirement: Check verbose mode shows passing checks
When `may-i check -v` is run, the output SHALL list every check with its
command and actual decision, not just failures.

#### Scenario: Verbose lists all checks
- **WHEN** `may-i check -v` is run with 10 checks
- **THEN** all 10 checks are listed with PASS/FAIL status

### Requirement: Check JSON mode outputs structured results
When `may-i check --json` is run, the output SHALL be a JSON object with
`passed` count, `failed` count, and a `results` array where each entry includes
command, expected/actual decisions, pass/fail flag, context, location, reason,
and trace.

#### Scenario: JSON check output
- **WHEN** `may-i check --json` is run
- **THEN** the output is valid JSON with `passed`, `failed`, and `results` fields

### Requirement: Dimmed nodes produce no right-column annotations
When a Doc node is dimmed (representing an unevaluated branch), the renderer
SHALL NOT produce any right-column annotation for that node or its children.

#### Scenario: Dimmed effect branch has no annotation
- **WHEN** a `(effect :deny)` node is dimmed because an earlier branch matched
- **THEN** no `→ :deny` annotation appears in the right column for that line

#### Scenario: Dimmed anywhere pattern has no annotation
- **WHEN** an `(anywhere "token")` node is dimmed
- **THEN** no `"token" ∈ {...} → yes/no` annotation appears

### Requirement: Structural annotation placement via AnnotatedLineBuilder
The renderer SHALL use `AnnotatedLineBuilder` to collect annotations
structurally during pretty-printing, rather than string-matching rendered output
with `find_line`.

#### Scenario: EffectDecision placed on correct line
- **WHEN** `(effect :allow "reason")` is rendered in broken layout across
  multiple lines
- **THEN** the `→ :allow "reason"` annotation appears on the line containing
  `(effect`, not on the `:allow` line

#### Scenario: Per-token anywhere annotations
- **WHEN** `(anywhere "t1" "t2")` with a parent ArgMatch is rendered
- **THEN** each token atom gets its own `"t" ∈ {args} → yes/no` annotation on
  its rendered line

### Requirement: Multiple annotations per line use priority ordering
When multiple annotations exist on a single rendered line, the renderer SHALL
display only the highest-priority annotation.

#### Scenario: EffectDecision takes priority over ArgMatch
- **WHEN** a line contains both an `EffectDecision` and an `ArgMatch` annotation
- **THEN** only the `EffectDecision` annotation is shown in the right column
