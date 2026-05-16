use may_i_sexpr::{Sexpr, parse};

fn first_form(input: &str) -> Sexpr {
    let (forms, errs) = parse(input);
    assert!(errs.is_empty(), "parse errors: {errs:?}");
    forms.into_iter().next().expect("at least one form")
}

fn agree(input: &str) {
    let sexpr = first_form(input);
    let via_rule_body = crate::parse_rule_body(&sexpr);
    let via_effect = crate::effect::parse_effect(&sexpr);
    match (via_rule_body, via_effect) {
        (Ok(a), Ok(b)) => assert_eq!(
            format!("{:?}", a.value),
            format!("{:?}", b.value),
            "disagreement on input: {input}",
        ),
        (Err(a), Err(b)) => assert_eq!(format!("{a}"), format!("{b}")),
        (a, b) => panic!("ok/err disagreement on {input}: rule_body={a:?} effect={b:?}"),
    }
}

#[test]
fn agrees_on_every_effect_variant() {
    // Terminal — with and without reason, every decision verb.
    agree("(allow)");
    agree(r#"(allow "ok")"#);
    agree("(ask)");
    agree(r#"(ask "confirm please")"#);
    agree("(deny)");
    agree(r#"(deny "no way")"#);

    // And / Or / Not combinators.
    agree(r#"(and (positional "x") (deny))"#);
    agree(r#"(or (positional "x") (positional "y"))"#);
    agree(r#"(not (positional "x"))"#);

    // When / Unless / If conditionals.
    agree(r#"(when (fact? [:env "prod"]) (deny))"#);
    agree(r#"(unless (fact? [:env "prod"]) (allow))"#);
    agree(r#"(if (fact? [:env "prod"]) (deny) (allow))"#);

    // Cond with else fallback.
    agree(r#"(cond ((fact? [:env "prod"]) (deny)) (else (allow)))"#);

    // ArgPattern variants in effect position.
    agree(r#"(positional "x")"#);
    agree(r#"(exact "x")"#);
    agree(r#"(anywhere "x")"#);
    agree(r#"(forbidden "x")"#);
    agree(r#"(flag "v")"#);
    agree(r#"(parameter "j" *)"#);

    // CommandPattern via bare string and `(or …)` form.
    agree(r#""git""#);
    agree(r#"(or "git" "gh")"#);

    // Authorise.
    agree("(authorise #cmd)");

    // Error path: malformed input.
    agree("(allow extra extra)");
    agree("(cond)");
}
