// Pretty-printer snapshot suite. Pins the canonical formatting of every
// surface DSL form so future changes to the pretty-printer (column
// alignment, line breaks, fill-vs-broken policy) can't drift silently.
//
// Each test pairs a small DSL fragment with the expected pretty output
// at width 80. To regenerate after an intentional formatting change,
// run `INSTA_UPDATE=always cargo test --test pretty_print_snapshots`
// and review the diff.

use may_i_sexpr::parse_cst;

fn render(input: &str) -> String {
    render_at_width(input, 80)
}

fn render_at_width(input: &str, width: usize) -> String {
    let (forms, errs) = parse_cst(input);
    assert!(errs.is_empty(), "parse errors: {errs:?}");
    forms
        .iter()
        .map(|f| f.pretty_serialize(width))
        .collect::<Vec<_>>()
        .join("\n")
}

// ── Rule body — decision verbs ────────────────────────────────────────

#[test]
fn rule_bare_allow() {
    let out = render(r#"(rule "ls" (allow))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn rule_allow_with_reason() {
    let out = render(r#"(rule "ls" (allow "safe ls"))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn rule_ask_with_reason() {
    let out = render(r#"(rule "rm" (ask "Recursive deletion — confirm the target"))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn rule_deny_with_reason() {
    let out = render(r#"(rule "rm" (deny "No filesystem operations on production hosts"))"#);
    insta::assert_snapshot!(out);
}

// ── Rule body — combinators ───────────────────────────────────────────

#[test]
fn rule_and_two_clauses() {
    let out = render(r#"(rule "git" (and (positional "push") (allow "push ok")))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn rule_or_command_alternation_short() {
    let out = render(r#"(rule (or "ls" "ll" "la") (allow))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn rule_or_command_alternation_wraps() {
    let out = render(
        r#"(rule (or "date" "hostname" "uname" "uptime" "ps" "top" "htop" "pgrep" "lsof"
  "df" "du" "id" "whoami" "groups" "printenv" "env" "which" "whereis"
  "type" "command" "netstat" "scutil")
  (allow "Read-only system state access"))"#,
    );
    insta::assert_snapshot!(out);
}

#[test]
fn rule_not() {
    let out = render(r#"(rule "rm" (and (not (flag "r")) (allow "non-recursive")))"#);
    insta::assert_snapshot!(out);
}

// ── Rule body — conditionals ──────────────────────────────────────────

#[test]
fn rule_when() {
    let out = render(r#"(rule "rm" (when (flag "r") (ask "recursive")))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn rule_unless() {
    let out = render(r#"(rule "rm" (unless (flag "r") (allow)))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn rule_if() {
    let out = render(r#"(rule "rm" (if (flag "r") (ask "recursive") (allow)))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn rule_cond_three_clauses() {
    let out = render(
        r#"(rule "rm"
  (cond ((positional "/") (deny "filesystem root"))
        ((flag ["r" "recursive"]) (ask "recursive"))
        (else (allow))))"#,
    );
    insta::assert_snapshot!(out);
}

#[test]
fn rule_cond_user_authored_three_space_indent() {
    // User writes 3-space clause indent; pretty-printer normalises to
    // its canonical convention. Pinning this so future "preserve user
    // breaks" changes can't drift cond formatting silently.
    let out = render(
        r#"(rule (or "terraform" "tofu")
  (cond
   ((or (exact) (positional "version"))
    (allow "Program introspection"))

   ((positional (or "fmt" "init" "plan" "test" "validate"))
    (allow "Safe operation"))

   ((positional (or "apply" "destroy"))
    (ask "Infra change requires confirmation"))))"#,
    );
    insta::assert_snapshot!(out);
}

// ── Rule body — argv matchers ─────────────────────────────────────────

#[test]
fn rule_positional_atoms() {
    let out = render(r#"(rule "git" (and (positional "push") (allow)))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn rule_positional_with_quantifier() {
    let out = render(r#"(rule "rm" (and (positional (* (regex "^/tmp/"))) (allow)))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn rule_exact_form() {
    let out = render(r#"(rule "true" (and (exact) (allow)))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn rule_flag_short() {
    let out = render(r#"(rule "rm" (and (flag "r") (deny)))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn rule_flag_short_long_pair() {
    let out = render(r#"(rule "rm" (and (flag ["r" "recursive"]) (deny)))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn rule_parameter_with_regex() {
    let out = render(r#"(rule "curl" (and (parameter ["X" "request"] (regex "^GET$")) (allow)))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn rule_anywhere() {
    let out = render(r#"(rule "rm" (and (anywhere "-r") (deny)))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn rule_forbidden() {
    let out = render(r#"(rule "git" (and (forbidden "--force") (allow)))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn rule_forbidden_many_atoms_wraps() {
    // Stresses fill layout for atom-only forbidden lists.
    let out = render(
        r#"(rule "rm" (and (forbidden "-r" "-R" "--recursive" "-rf" "-fr" "-rR"
                                "--force" "-Rf" "-fR" "/")
                  (allow)))"#,
    );
    insta::assert_snapshot!(out);
}

// ── Rule body — recursion ─────────────────────────────────────────────

#[test]
fn rule_authorise_inside_parameter() {
    let out = render(r#"(rule "bash" (parameter "c" (authorise)))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn rule_tail_authorise() {
    let out = render(r#"(rule "sudo" (tail (authorise)))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn rule_and_positional_then_tail() {
    let out = render(r#"(rule "ssh" (and (positional [:ssh/host *]) (tail (authorise))))"#);
    insta::assert_snapshot!(out);
}

// ── Patterns — fact bindings and predicates ───────────────────────────

#[test]
fn rule_fact_query_presence() {
    let out = render(r#"(rule "rm" (when (fact? :via/ssh) (deny "no rm over ssh")))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn rule_fact_query_value() {
    let out = render(
        r#"(rule "rm" (when (fact? [:ssh/host (regex "^prod-")]) (deny "production host")))"#,
    );
    insta::assert_snapshot!(out);
}

#[test]
fn define_predicate() {
    let out =
        render(r#"(define prod-host (and (fact? :via/ssh) (fact? [:ssh/host (regex "^prod-")])))"#);
    insta::assert_snapshot!(out);
}

// ── Top-level: parser ────────────────────────────────────────────────

#[test]
fn parser_minimal() {
    let out = render(r#"(parser "find" (style single-dash-long))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn parser_with_flag_and_parameter() {
    let out = render(r#"(parser "kubectl" (style gnu) (flag "v") (parameter ["n" "namespace"]))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn parser_with_tail_after_flags() {
    let out = render(r#"(parser "sudo" (style gnu) (tail (after :flags)))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn parser_with_tail_after_token() {
    let out = render(r#"(parser "mise" (style gnu) (tail (after "--")))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn parser_with_many_till() {
    let out = render(
        r#"(parser "find" (style single-dash-long)
  (parameter "exec" (many-till (or ";" "+")))
  (parameter "execdir" (many-till (or ";" "+")))
  (parameter ["name" "type" "size"]))"#,
    );
    insta::assert_snapshot!(out);
}

#[test]
fn parser_xargs_with_flags_and_parameters() {
    let out = render(
        r#"(parser "xargs" (style gnu) (parameter ["n" "I" "L" "P" "d"])
  (flag ["0" "r"]) (tail (after :flags)))"#,
    );
    insta::assert_snapshot!(out);
}

// ── Top-level: define-arg-style ──────────────────────────────────────

#[test]
fn define_arg_style_minimal() {
    let out = render(r#"(define-arg-style gnu (long-prefix "--") (short-prefix "-"))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn define_arg_style_full() {
    let out = render(
        r#"(define-arg-style gnu
  (long-prefix "--")
  (short-prefix "-")
  (separators " " "=")
  (combined-shorts t)
  (pun :allow))"#,
    );
    insta::assert_snapshot!(out);
}

#[test]
fn define_arg_style_overrides() {
    let out = render(r#"(define-arg-style java (overrides gnu) (separators " " "=" ":"))"#);
    insta::assert_snapshot!(out);
}

// ── Top-level: check ─────────────────────────────────────────────────

#[test]
fn check_form_list() {
    let out = render(r#"(check (allow "ls -la") (ask "rm -rf /tmp/foo") (deny "rm -rf /"))"#);
    insta::assert_snapshot!(out);
}

#[test]
fn check_with_facts_nested() {
    let out = render(
        r#"(check (with-facts [[:client/opencode] [:via/ssh]]
  (allow "git push")
  (deny "rm /etc/passwd")))"#,
    );
    insta::assert_snapshot!(out);
}

// ── Top-level: safe-env-vars and load ────────────────────────────────

#[test]
fn safe_env_vars() {
    let out = render(r#"(safe-env-vars "HOME" "USER" "PATH")"#);
    insta::assert_snapshot!(out);
}

#[test]
fn load_glob() {
    let out = render(r#"(load "rules/*.lisp")"#);
    insta::assert_snapshot!(out);
}

// ── Width-sensitive cases ────────────────────────────────────────────

#[test]
fn narrow_width_30_breaks_rule() {
    let out = render_at_width(
        r#"(rule "git" (and (positional "push") (allow "push is fine")))"#,
        30,
    );
    insta::assert_snapshot!(out);
}

#[test]
fn very_narrow_width_20_drops_each_arg() {
    let out = render_at_width(r#"(rule "rm" (and (flag "r") (anywhere "/") (deny)))"#, 20);
    insta::assert_snapshot!(out);
}

// ── Multi-form document ──────────────────────────────────────────────

#[test]
fn multi_form_document() {
    let out = render(
        r#"(safe-env-vars "HOME" "USER")

(define safe-cmd (or (positional "status") (positional "log")))

(parser "kubectl" (style gnu) (parameter ["n" "namespace"]))

(rule "ls" (allow))

(rule "rm"
  (cond ((positional "/") (deny "root"))
        ((flag "r") (ask "recursive"))
        (else (allow))))

(check (allow "ls -la") (deny "rm -rf /"))"#,
    );
    insta::assert_snapshot!(out);
}
