1: ## 1. Core AST Types
2: 
3: - [x] 1.1 Define `Predicate` enum with `Has`, `Arg`, `And`, `Or`, `Not` variants
4: - [x] 1.2 Define `ArgPattern` enum covering positional, exact, anywhere, forbidden
5: - [x] 1.3 Define `Effect` enum with terminal effects and `Evaluate`, `Case`, `When`, `Unless`, `If`
6: - [x] 1.4 Define `Rule` struct with command pattern, predicate, effect, and source span
7: - [x] 1.5 Define `Define` struct for named predicates
8: - [x] 1.6 Add span tracking to all AST nodes for error reporting
9: 
10: ## 2. Parser Implementation
11: 
12: - [x] 2.1 Implement command pattern parser (literals, `or`, `regex`)
13: - [x] 2.2 Implement fact query parser for `(has ...)` forms
14: - [x] 2.3 Implement argument pattern parsers (`positional`, `exact`, `anywhere`, `forbidden`)
15: - [x] 2.4 Implement boolean combinator parsers (`and`, `or`, `not`)
16: - [x] 2.5 Implement unified predicate parser that dispatches to fact or arg parsers
17: - [x] 2.6 Implement effect parser (`effect`, `may-i`, `case`, `when`, `unless`, `if`)
18: - [x] 2.7 Implement dot syntax parsing for remaining args
19: - [x] 2.8 Implement rule parser with simplified syntax
20: - [x] 2.9 Implement define parser for named predicates
21: - [x] 2.10 Implement safe-env-vars and check parsers (preserve existing behavior)
22: 
23: ## 3. Define Resolution and Validation
24: 
25: - [x] 3.1 Build define resolution map from parsed config
26: - [x] 3.2 Detect duplicate define names and report errors
27: - [x] 3.3 Detect undefined predicate references and report errors
28: - [x] 3.4 Detect cyclic define references using cycle detection algorithm
29: - [x] 3.5 Resolve named predicates at parse time (keep runtime representation)
30: 
31: ## 4. Evaluator Implementation
32: 
33: - [x] 4.1 Implement predicate evaluation against facts and args
34: - [x] 4.2 Implement fact query evaluation (`has` matching)
35: - [x] 4.3 Implement argument pattern evaluation (positional, anywhere, etc.)
36: - [x] 4.4 Implement boolean combinator evaluation
37: - [x] 4.5 Implement effect evaluation with decision results
38: - [x] 4.6 Implement effect combination logic (most restrictive wins)
39: - [x] 4.7 Implement recursive evaluation for `(may-i ...)`
40: - [x] 4.8 Implement recursion depth tracking and limit enforcement
41: - [x] 4.9 Implement case/when/unless/if evaluation
42: - [x] 4.10 Implement full rule evaluation pipeline
43: 
44: ## 5. Trace Output
45: 
46: - [x] 5.1 Design trace output format for unified predicates
47: - [x] 5.2 Implement trace generation for fact queries
48: - [x] 5.3 Implement trace generation for argument patterns
49: - [x] 5.4 Implement trace generation for boolean combinators
50: - [x] 5.5 Implement trace generation for effects
51: - [x] 5.6 Implement trace generation for recursive evaluation
52: - [x] 5.7 Preserve sugar forms (when/unless/if) in trace output
53: 
54: ## 6. Migration Tool
55: 
56: - [x] 6.1 Implement v1 rule parser (reuse existing or create isolated copy)
57: - [x] 6.2 Implement rule syntax migration (command, context, args → unified)
58: - [x] 6.3 Implement wrapper to rule with may-i migration
59: - [x] 6.4 Implement defcontext to define migration
60: - [x] 6.5 Implement args cond to case migration
61: - [x] 6.6 Implement check form preservation
62: - [x] 6.7 Implement migration validation (output parses with v2 parser)
63: - [x] 6.8 Implement unhandled case reporting
64: - [x] 6.9 Add `may-i migrate` CLI subcommand
65: - [x] 6.10 Add dry-run and diff options to migration command
66: 
67: ## 7. Integration and Testing
68: 
69: - [x] 7.1 Wire up new parser to config loading
70: - [x] 7.2 Wire up new evaluator to engine
71: - [x] 7.3 Update CLI to use new parser/evaluator
72: - [x] 7.4 Write parser unit tests for all predicate types
73: - [x] 7.5 Write evaluator unit tests for all effect types
74: - [x] 7.6 Write integration tests for end-to-end evaluation
75: - [x] 7.7 Write migration tool tests
76: - [x] 7.8 Write tests for edge cases (cycles, depth limits, empty matches)
77: - [x] 7.9 Remove or archive old parser and evaluator code
78: - [x] 7.10 Update documentation with new syntax examples
