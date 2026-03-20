## 1. Core AST Types

- [ ] 1.1 Define `Predicate` enum with `Has`, `Arg`, `And`, `Or`, `Not` variants
- [ ] 1.2 Define `ArgPattern` enum covering positional, exact, anywhere, forbidden
- [ ] 1.3 Define `Effect` enum with terminal effects and `Evaluate`, `Case`, `When`, `Unless`, `If`
- [ ] 1.4 Define `Rule` struct with command pattern, predicate, effect, and source span
- [ ] 1.5 Define `Define` struct for named predicates
- [ ] 1.6 Add span tracking to all AST nodes for error reporting

## 2. Parser Implementation

- [ ] 2.1 Implement command pattern parser (literals, `or`, `regex`)
- [ ] 2.2 Implement fact query parser for `(has ...)` forms
- [ ] 2.3 Implement argument pattern parsers (`positional`, `exact`, `anywhere`, `forbidden`)
- [ ] 2.4 Implement boolean combinator parsers (`and`, `or`, `not`)
- [ ] 2.5 Implement unified predicate parser that dispatches to fact or arg parsers
- [ ] 2.6 Implement effect parser (`effect`, `may-i`, `case`, `when`, `unless`, `if`)
- [ ] 2.7 Implement dot syntax parsing for remaining args
- [ ] 2.8 Implement rule parser with simplified syntax
- [ ] 2.9 Implement define parser for named predicates
- [ ] 2.10 Implement safe-env-vars and check parsers (preserve existing behavior)

## 3. Define Resolution and Validation

- [ ] 3.1 Build define resolution map from parsed config
- [ ] 3.2 Detect duplicate define names and report errors
- [ ] 3.3 Detect undefined predicate references and report errors
- [ ] 3.4 Detect cyclic define references using cycle detection algorithm
- [ ] 3.5 Resolve named predicates at parse time (keep runtime representation)

## 4. Evaluator Implementation

- [ ] 4.1 Implement predicate evaluation against facts and args
- [ ] 4.2 Implement fact query evaluation (`has` matching)
- [ ] 4.3 Implement argument pattern evaluation (positional, anywhere, etc.)
- [ ] 4.4 Implement boolean combinator evaluation
- [ ] 4.5 Implement effect evaluation with decision results
- [ ] 4.6 Implement effect combination logic (most restrictive wins)
- [ ] 4.7 Implement recursive evaluation for `(may-i ...)`
- [ ] 4.8 Implement recursion depth tracking and limit enforcement
- [ ] 4.9 Implement case/when/unless/if evaluation
- [ ] 4.10 Implement full rule evaluation pipeline

## 5. Trace Output

- [ ] 5.1 Design trace output format for unified predicates
- [ ] 5.2 Implement trace generation for fact queries
- [ ] 5.3 Implement trace generation for argument patterns
- [ ] 5.4 Implement trace generation for boolean combinators
- [ ] 5.5 Implement trace generation for effects
- [ ] 5.6 Implement trace generation for recursive evaluation
- [ ] 5.7 Preserve sugar forms (when/unless/if) in trace output

## 6. Migration Tool

- [ ] 6.1 Implement v1 rule parser (reuse existing or create isolated copy)
- [ ] 6.2 Implement rule syntax migration (command, context, args → unified)
- [ ] 6.3 Implement wrapper to rule with may-i migration
- [ ] 6.4 Implement defcontext to define migration
- [ ] 6.5 Implement args cond to case migration
- [ ] 6.6 Implement check form preservation
- [ ] 6.7 Implement migration validation (output parses with v2 parser)
- [ ] 6.8 Implement unhandled case reporting
- [ ] 6.9 Add `may-i migrate` CLI subcommand
- [ ] 6.10 Add dry-run and diff options to migration command

## 7. Integration and Testing

- [ ] 7.1 Wire up new parser to config loading
- [ ] 7.2 Wire up new evaluator to engine
- [ ] 7.3 Update CLI to use new parser/evaluator
- [ ] 7.4 Write parser unit tests for all predicate types
- [ ] 7.5 Write evaluator unit tests for all effect types
- [ ] 7.6 Write integration tests for end-to-end evaluation
- [ ] 7.7 Write migration tool tests
- [ ] 7.8 Write tests for edge cases (cycles, depth limits, empty matches)
- [ ] 7.9 Remove or archive old parser and evaluator code
- [ ] 7.10 Update documentation with new syntax examples
