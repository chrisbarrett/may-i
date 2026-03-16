# Fact Predicates in Args

## Summary

This feature adds support for using `(has ...)` and other fact predicates directly
within `(args ...)` expressions. This enables more precise authorization decisions
that depend on both argument patterns AND runtime context facts.

## What's New

### 1. BoolExpr type for fact predicates

A new `BoolExpr` type represents fact predicates with variants:
- `Has(FactQuery)` - check for presence or value of a fact
- `And(Vec<BoolExpr>)` - all sub-predicates must match
- `Or(Vec<BoolExpr>)` - any sub-predicate must match  
- `Not(Box<BoolExpr>)` - negate a predicate

### 2. ArgMatcher::Has variant

ArgMatcher now has a `Has(BoolExpr)` variant that evaluates fact predicates:

```scheme
(args (has :via/ssh))                    ; presence check
(args (has [:env "prod"]))               ; value check
(args (and (positional "delete")         ; combined with args
           (has [:env "prod"])))
```

### 3. Polymorphic conditionals

`cond`, `when`, `unless`, and `if` in args now support three types of predicates:
- **ArgMatcher** - full matchers like `positional`, `anywhere`
- **Expr** - string predicates like literals, wildcards, regexes
- **BoolExpr** - fact predicates with `has`, `and`, `or`, `not`

### 4. First-class sugar forms

`when`, `unless`, and `if` are now first-class AST nodes (not desugared to `cond`).
This preserves them in traces so users see what they wrote.

## Current Limitations

### Validation: Embedded effects vs rule-level effects

**The current validation treats rules with embedded arg effects AND rule-level
effects as mutually exclusive.**

This config will fail validation:
```scheme
; ERROR: cond and effect are mutually exclusive in a rule
(rule (command "kubectl")
      (args (when (has [:env "prod"])
                 (effect :deny)))
      (effect :allow))  ; <- rule-level effect
```

**Workaround**: Use `cond` with an explicit `else` branch:
```scheme
; CORRECT: cond with else for fallthrough
(rule (command "kubectl")
      (args (cond
              ((has [:env "prod"]) (effect :deny))
              (else (effect :allow)))))
```

See task 5.6 for planned support of rule-level fallback effects.

## Usage

### To use the new feature

1. Update rules to use fact predicates in args where helpful
2. Remember to use `cond` with `else` instead of `when` + rule-level effect
3. Run `may-i check` to validate your config

## Examples

### Before: Separate rules for different contexts

```scheme
; Had to duplicate the command matcher
(rule (command "kubectl")
      (context (has [:env "prod"]))
      (effect :deny))

(rule (command "kubectl")
      (effect :allow))
```

### After: Single rule with contextual args

```scheme
; One rule handles both cases
(rule (command "kubectl")
      (args (cond
              ((has [:env "prod"]) (effect :deny))
              (else (effect :allow)))))
```

### Before: Wrapper facts only in context

```scheme
; Could only check wrapper facts in (context ...)
(defcontext remote-prod
  (and (has :via/ssh)
       (has [:ssh/host (regex "^prod-")])))

(rule (command "rm")
      (context remote-prod)
      (effect :deny))
```

### After: Wrapper facts in args for fine-grained control

```scheme
; Can check wrapper facts alongside arg patterns
(rule (command "rm")
      (args (cond
              ((and (anywhere "-rf")
                    (has [:ssh/host (regex "^prod-")]))
               (effect :deny))
              (else (effect :ask)))))
```

## See Also

- Updated starter_config.lisp with new examples
- README section on "Fact predicates in argument matching"
- Design.md for implementation details
