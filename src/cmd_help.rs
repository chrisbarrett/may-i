// Help subcommand — print detailed DSL syntax reference.

use colored::Colorize;

/// Print comprehensive DSL syntax help.
#[allow(clippy::print_literal)]
pub fn cmd_help() -> miette::Result<()> {
    print!(
        "{}",
        r#"
may-i — Shell command authorization evaluator

OVERVIEW
    may-i evaluates shell commands against a policy you define, returning:
    • allow  — run without asking
    • ask    — escalate to normal permission prompt
    • deny   — block execution

USAGE
    may-i eval 'COMMAND...'           Evaluate a command
    may-i check                       Validate config and run checks
    may-i migrate FILE                Migrate v1 config to v2
    may-i help                        Show this help

QUICK START
    1. may-i creates ~/.config/may-i/config.lisp on first run
    2. Edit rules to define your policy
    3. Run `may-i check` to validate
    4. Use `may-i eval 'cmd'` to test rules

"#
        .trim()
    );

    println!("\n{}", "RULE SYNTAX".bold().underline());
    print!(
        "{}",
        r#"
(rule COMMAND-EFFECT
  EFFECT...
  :effect DEFAULT-EFFECT)

COMMAND-EFFECT:  String, (or STRING...), or (regex "PATTERN")
EFFECT:          Pattern, combinator, conditional, or terminal
DEFAULT-EFFECT:  Fallback if all effects return Nil

Examples:
  (rule "ls" :effect :allow)

  (rule "rm"
    (when (anywhere "-r" "--recursive")
      (effect :ask "Recursive deletion"))
    :effect (effect :allow))
"#
    );

    println!("\n{}", "EFFECTS".bold().underline());
    print!(
        "{}",
        r#"
Terminal Effects (return a decision):
  (effect :allow)
  (effect :ask "Reason")
  (effect :deny "Reason")

Pattern Effects (return Allow on match, Nil otherwise):
  (positional PAT...)         Match args positionally (skip flags)
  (exact PAT...)              Exact match (no extra args)
  (anywhere PAT...)           Match anywhere in args
  (forbidden PAT...)          Fail if pattern found

  Pattern syntax:
    "string"                    Literal match
    *                           Wildcard
    (regex "PATTERN")           Regex match
    (or PAT...)                 Match any
    (and PAT...)                Match all
    (not PAT)                   Negate

Combinators:
  (and EFFECT...)             All must match
  (or EFFECT...)              First match wins
  (not EFFECT)                Invert Allow/Nil

Conditionals:
  (when PATTERN EFFECT)       Effect if pattern matches
  (unless PATTERN EFFECT)     Effect if pattern doesn't match
  (if PATTERN THEN ELSE)      If-then-else
  (cond ((PAT) EFF)... (else EFF))   Multi-way branch

Recursive Evaluation:
  (may-i PATTERN)             Evaluate inner command
  (positional [:host *] . (may-i *))   ; capture host, eval rest
"#
    );

    println!("\n{}", "FACTS".bold().underline());
    print!(
        "{}",
        r#"
Facts provide runtime context. They are namespaced keys like :via/ssh.

Presence:  :via/ssh
Scalar:    [:env "prod"]

Query with (fact? ...):
  (fact? :via/ssh)                       ; presence check
  (fact? [:env "prod"])                  ; exact value
  (fact? [:host (regex "^prod-")])       ; regex match
  (and (fact? A) (fact? B))              ; combined

Pass facts to eval:
  may-i eval --fact :via/ssh --fact :env=prod 'kubectl get pods'
"#
    );

    println!("\n{}", "NAMED PREDICATES".bold().underline());
    print!(
        "{}",
        r#"
Define reusable predicates:
  (define prod
    (and (fact? :via/ssh)
         (fact? [:ssh/host (regex "^prod-")])))

Use in rules:
  (rule "kubectl"
    (when prod (effect :deny "No prod access"))
    :effect (effect :allow))
"#
    );

    println!("\n{}", "CHECKS".bold().underline());
    print!(
        "{}",
        r#"
Embed tests in rules:
  (check :allow "ls -la"
         :deny "rm -rf /")

With facts:
  (check (with-facts [[:env "prod"]]
           :deny "kubectl get pods")
         (with-facts [[:env "dev"]]
           :allow "kubectl get pods"))

Validate with: may-i check
"#
    );

    println!("\n{}", "MIGRATION".bold().underline());
    print!(
        "{}",
        r#"
Convert v1 configs to v2:
  may-i migrate ~/.config/may-i/config.lisp

Options:
  --dry-run    Preview changes
  --diff       Show detailed diff
  --yes        Skip confirmation
"#
    );

    println!("\n{}", "GLOBAL FLAGS".bold().underline());
    print!(
        "{}",
        r#"
  --json       Output as JSON
  --config F   Use specific config file
  --v2         Use v2 unified DSL (default)
"#
    );

    Ok(())
}
