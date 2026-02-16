// S-expression parser — R10f
// Zero-dependency parser producing Atom | List AST.
//
// Quoted strings: "hello\nworld" (supports \\, \", \n, \t)
// Bare atoms: letters, digits, - _ * . / ^ :
// Comments: ; to end of line
// Parentheses delimit lists.

/// S-expression AST node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sexpr {
    Atom(String),
    List(Vec<Sexpr>),
}

impl Sexpr {
    /// Return the atom string, or `None` if this is a list.
    pub fn as_atom(&self) -> Option<&str> {
        match self {
            Sexpr::Atom(s) => Some(s),
            Sexpr::List(_) => None,
        }
    }

    /// Return the list contents, or `None` if this is an atom.
    pub fn as_list(&self) -> Option<&[Sexpr]> {
        match self {
            Sexpr::Atom(_) => None,
            Sexpr::List(v) => Some(v),
        }
    }
}

impl std::fmt::Display for Sexpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Sexpr::Atom(s) => {
                if s.is_empty() || s.contains(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == '"' || c == ';' || c == '\\') {
                    write!(f, "\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
                } else {
                    write!(f, "{s}")
                }
            }
            Sexpr::List(items) => {
                write!(f, "(")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, ")")
            }
        }
    }
}

// --- Tokenizer ---

#[derive(Debug, PartialEq)]
enum Token {
    Open,
    Close,
    Atom(String),
    Str(String),
}

fn is_atom_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '*' | '.' | '/' | '^' | ':')
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(&ch) = chars.peek() {
        match ch {
            ' ' | '\t' | '\n' | '\r' => {
                chars.next();
            }
            ';' => {
                // Comment: skip to end of line
                while let Some(&c) = chars.peek() {
                    chars.next();
                    if c == '\n' {
                        break;
                    }
                }
            }
            '(' => {
                tokens.push(Token::Open);
                chars.next();
            }
            ')' => {
                tokens.push(Token::Close);
                chars.next();
            }
            '"' => {
                chars.next();
                let mut s = String::new();
                loop {
                    match chars.next() {
                        None => return Err("unterminated string".into()),
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some('\\') => s.push('\\'),
                            Some('"') => s.push('"'),
                            Some('n') => s.push('\n'),
                            Some('t') => s.push('\t'),
                            Some(c) => return Err(format!("unknown escape: \\{c}")),
                            None => return Err("unterminated escape in string".into()),
                        },
                        Some(c) => s.push(c),
                    }
                }
                tokens.push(Token::Str(s));
            }
            c if is_atom_char(c) => {
                let mut s = String::new();
                while let Some(&c) = chars.peek() {
                    if is_atom_char(c) {
                        s.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }
                tokens.push(Token::Atom(s));
            }
            _ => return Err(format!("unexpected character: {ch:?}")),
        }
    }

    Ok(tokens)
}

// --- Parser ---

/// Parse a string containing zero or more s-expressions into a list of top-level forms.
pub fn parse(input: &str) -> Result<Vec<Sexpr>, String> {
    let tokens = tokenize(input)?;
    let mut pos = 0;
    let mut results = Vec::new();
    while pos < tokens.len() {
        let (sexpr, next) = parse_one(&tokens, pos)?;
        results.push(sexpr);
        pos = next;
    }
    Ok(results)
}

fn parse_one(tokens: &[Token], pos: usize) -> Result<(Sexpr, usize), String> {
    match tokens.get(pos) {
        None => Err("unexpected end of input".into()),
        Some(Token::Close) => Err("unexpected ')'".into()),
        Some(Token::Atom(s) | Token::Str(s)) => Ok((Sexpr::Atom(s.clone()), pos + 1)),
        Some(Token::Open) => {
            let mut items = Vec::new();
            let mut p = pos + 1;
            loop {
                match tokens.get(p) {
                    None => return Err("unclosed '('".into()),
                    Some(Token::Close) => return Ok((Sexpr::List(items), p + 1)),
                    _ => {
                        let (item, next) = parse_one(tokens, p)?;
                        items.push(item);
                        p = next;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn atom(s: &str) -> Sexpr {
        Sexpr::Atom(s.to_string())
    }

    fn list(items: Vec<Sexpr>) -> Sexpr {
        Sexpr::List(items)
    }

    // --- Empty input ---

    #[test]
    fn parse_empty() {
        assert_eq!(parse("").unwrap(), vec![]);
    }

    #[test]
    fn parse_whitespace_only() {
        assert_eq!(parse("   \n\t  ").unwrap(), vec![]);
    }

    #[test]
    fn parse_comment_only() {
        assert_eq!(parse("; this is a comment\n").unwrap(), vec![]);
    }

    // --- Atoms ---

    #[test]
    fn parse_bare_atom() {
        assert_eq!(parse("hello").unwrap(), vec![atom("hello")]);
    }

    #[test]
    fn parse_bare_atom_with_special_chars() {
        assert_eq!(parse("after-flags").unwrap(), vec![atom("after-flags")]);
        assert_eq!(parse("foo_bar").unwrap(), vec![atom("foo_bar")]);
        assert_eq!(parse("*").unwrap(), vec![atom("*")]);
        assert_eq!(
            parse("^foo.*bar").unwrap(),
            vec![atom("^foo.*bar")]
        );
    }

    #[test]
    fn parse_multiple_atoms() {
        assert_eq!(
            parse("foo bar baz").unwrap(),
            vec![atom("foo"), atom("bar"), atom("baz")]
        );
    }

    // --- Quoted strings ---

    #[test]
    fn parse_quoted_string() {
        assert_eq!(parse(r#""hello""#).unwrap(), vec![atom("hello")]);
    }

    #[test]
    fn parse_quoted_string_with_spaces() {
        assert_eq!(
            parse(r#""hello world""#).unwrap(),
            vec![atom("hello world")]
        );
    }

    #[test]
    fn parse_quoted_string_escapes() {
        assert_eq!(
            parse(r#""a\"b\\c\nd\te""#).unwrap(),
            vec![atom("a\"b\\c\nd\te")]
        );
    }

    #[test]
    fn parse_empty_string() {
        assert_eq!(parse(r#""""#).unwrap(), vec![atom("")]);
    }

    #[test]
    fn parse_unterminated_string() {
        assert!(parse(r#""hello"#).is_err());
    }

    #[test]
    fn parse_unknown_escape() {
        assert!(parse(r#""\q""#).is_err());
    }

    #[test]
    fn parse_unterminated_escape() {
        assert!(parse(r#""hello\"#).is_err());
    }

    // --- Lists ---

    #[test]
    fn parse_empty_list() {
        assert_eq!(parse("()").unwrap(), vec![list(vec![])]);
    }

    #[test]
    fn parse_simple_list() {
        assert_eq!(
            parse("(a b c)").unwrap(),
            vec![list(vec![atom("a"), atom("b"), atom("c")])]
        );
    }

    #[test]
    fn parse_nested_list() {
        assert_eq!(
            parse("(a (b c) d)").unwrap(),
            vec![list(vec![
                atom("a"),
                list(vec![atom("b"), atom("c")]),
                atom("d"),
            ])]
        );
    }

    #[test]
    fn parse_deeply_nested() {
        assert_eq!(
            parse("(((a)))").unwrap(),
            vec![list(vec![list(vec![list(vec![atom("a")])])])]
        );
    }

    #[test]
    fn parse_unclosed_paren() {
        assert!(parse("(a b").is_err());
    }

    #[test]
    fn parse_unexpected_close() {
        assert!(parse(")").is_err());
    }

    #[test]
    fn parse_extra_close() {
        assert!(parse("(a))").is_err());
    }

    // --- Mixed ---

    #[test]
    fn parse_strings_in_list() {
        assert_eq!(
            parse(r#"(command "rm")"#).unwrap(),
            vec![list(vec![atom("command"), atom("rm")])]
        );
    }

    #[test]
    fn parse_multiple_top_level_forms() {
        assert_eq!(
            parse("(a) (b) (c)").unwrap(),
            vec![
                list(vec![atom("a")]),
                list(vec![atom("b")]),
                list(vec![atom("c")]),
            ]
        );
    }

    // --- Comments ---

    #[test]
    fn parse_comment_before_form() {
        assert_eq!(
            parse("; comment\n(a)").unwrap(),
            vec![list(vec![atom("a")])]
        );
    }

    #[test]
    fn parse_comment_after_form() {
        assert_eq!(
            parse("(a) ; comment").unwrap(),
            vec![list(vec![atom("a")])]
        );
    }

    #[test]
    fn parse_comment_between_forms() {
        assert_eq!(
            parse("(a)\n; comment\n(b)").unwrap(),
            vec![list(vec![atom("a")]), list(vec![atom("b")])]
        );
    }

    #[test]
    fn parse_inline_comment_in_list() {
        assert_eq!(
            parse("(a ; comment\n b)").unwrap(),
            vec![list(vec![atom("a"), atom("b")])]
        );
    }

    // --- Unexpected characters ---

    #[test]
    fn parse_unexpected_char() {
        assert!(parse("[").is_err());
    }

    // --- Display round-trip ---

    #[test]
    fn display_atom() {
        assert_eq!(format!("{}", atom("hello")), "hello");
    }

    #[test]
    fn display_atom_needs_quoting() {
        assert_eq!(format!("{}", atom("hello world")), r#""hello world""#);
    }

    #[test]
    fn display_empty_string_atom() {
        assert_eq!(format!("{}", atom("")), r#""""#);
    }

    #[test]
    fn display_list() {
        assert_eq!(
            format!("{}", list(vec![atom("a"), atom("b")])),
            "(a b)"
        );
    }

    #[test]
    fn display_nested() {
        let s = list(vec![atom("rule"), list(vec![atom("command"), atom("rm")])]);
        assert_eq!(format!("{s}"), "(rule (command rm))");
    }

    // --- as_atom / as_list ---

    #[test]
    fn as_atom_on_atom() {
        assert_eq!(atom("x").as_atom(), Some("x"));
    }

    #[test]
    fn as_atom_on_list() {
        assert_eq!(list(vec![]).as_atom(), None);
    }

    #[test]
    fn as_list_on_list() {
        let l = list(vec![atom("a")]);
        assert_eq!(l.as_list(), Some(&[atom("a")][..]));
    }

    #[test]
    fn as_list_on_atom() {
        assert_eq!(atom("x").as_list(), None);
    }

    // --- Display: quoting edge cases ---

    #[test]
    fn display_atom_with_backslash() {
        // atom contains literal `a\b`, display should produce `"a\\b"`
        assert_eq!(format!("{}", atom("a\\b")), "\"a\\\\b\"");
    }

    #[test]
    fn display_atom_with_quote() {
        assert_eq!(format!("{}", atom(r#"a"b"#)), r#""a\"b""#);
    }

    #[test]
    fn display_atom_with_semicolon() {
        assert_eq!(format!("{}", atom("a;b")), r#""a;b""#);
    }

    #[test]
    fn display_atom_with_parens() {
        assert_eq!(format!("{}", atom("a(b)")), r#""a(b)""#);
    }

    #[test]
    fn display_empty_list() {
        assert_eq!(format!("{}", list(vec![])), "()");
    }

    // --- Tokenizer edge cases ---

    #[test]
    fn parse_comment_at_eof_no_newline() {
        assert_eq!(parse("; comment").unwrap(), vec![]);
    }

    #[test]
    fn parse_string_adjacent_to_parens() {
        assert_eq!(
            parse(r#"("foo")"#).unwrap(),
            vec![list(vec![atom("foo")])]
        );
    }

    #[test]
    fn parse_consecutive_strings() {
        assert_eq!(
            parse(r#""a""b""#).unwrap(),
            vec![atom("a"), atom("b")]
        );
    }

    #[test]
    fn parse_atom_immediately_before_close() {
        assert_eq!(
            parse("(a)").unwrap(),
            vec![list(vec![atom("a")])]
        );
    }

    // --- Display round-trip ---

    #[test]
    fn display_round_trip() {
        let input = r#"(rule (command "rm") (args (and (anywhere "-r") (anywhere "/"))) (effect :deny "bad"))"#;
        let parsed = parse(input).unwrap();
        let displayed = format!("{}", parsed[0]);
        let reparsed = parse(&displayed).unwrap();
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn display_round_trip_with_special_atoms() {
        let original = list(vec![
            atom("test"),
            atom("hello world"),
            atom(""),
            atom("a\"b"),
            atom("c\\d"),
        ]);
        let displayed = format!("{original}");
        let reparsed = parse(&displayed).unwrap();
        assert_eq!(reparsed, vec![original]);
    }

    // --- Realistic config fragment ---

    #[test]
    fn parse_rule_form() {
        let input = r#"
            (rule (command "rm")
                  (args (and (anywhere "-r" "--recursive")
                             (anywhere "/")))
                  (effect :deny "Recursive deletion from root"))
        "#;
        let forms = parse(input).unwrap();
        assert_eq!(forms.len(), 1);
        let rule = forms[0].as_list().unwrap();
        assert_eq!(rule[0].as_atom(), Some("rule"));

        let cmd = rule[1].as_list().unwrap();
        assert_eq!(cmd[0].as_atom(), Some("command"));
        assert_eq!(cmd[1].as_atom(), Some("rm"));

        let args = rule[2].as_list().unwrap();
        assert_eq!(args[0].as_atom(), Some("args"));
        let and = args[1].as_list().unwrap();
        assert_eq!(and[0].as_atom(), Some("and"));

        let effect = rule[3].as_list().unwrap();
        assert_eq!(effect[0].as_atom(), Some("effect"));
        assert_eq!(effect[1].as_atom(), Some(":deny"));
        assert_eq!(effect[2].as_atom(), Some("Recursive deletion from root"));
    }

    #[test]
    fn parse_wrapper_form() {
        let input = r#"(wrapper "nohup" after-flags)"#;
        let forms = parse(input).unwrap();
        let w = forms[0].as_list().unwrap();
        assert_eq!(w[0].as_atom(), Some("wrapper"));
        assert_eq!(w[1].as_atom(), Some("nohup"));
        assert_eq!(w[2].as_atom(), Some("after-flags"));
    }

    #[test]
    fn parse_blocked_paths_form() {
        let input = r#"(blocked-paths "\\.env" "\\.ssh/")"#;
        let forms = parse(input).unwrap();
        let bp = forms[0].as_list().unwrap();
        assert_eq!(bp[0].as_atom(), Some("blocked-paths"));
        assert_eq!(bp[1].as_atom(), Some("\\.env"));
        assert_eq!(bp[2].as_atom(), Some("\\.ssh/"));
    }

    #[test]
    fn parse_full_config() {
        let input = r#"
            ;; Deny rules
            (rule (command "rm")
                  (args (and (anywhere "-r" "--recursive")
                             (anywhere "/")))
                  (effect :deny "Recursive deletion from root"))

            ;; Allow rules
            (rule (command (oneof "cat" "ls" "grep"))
                  (effect :allow))

            (rule (command "aws")
                  (args (positional * (regex "^(get|describe|list).*")))
                  (effect :allow))

            ;; Wrappers
            (wrapper "nohup" after-flags)
            (wrapper "mise" (positional "exec") (after "--"))

            ;; Security
            (blocked-paths "\\.env" "\\.ssh/")
        "#;
        let forms = parse(input).unwrap();
        assert_eq!(forms.len(), 6);

        // Verify form types by first atom
        let tags: Vec<&str> = forms
            .iter()
            .map(|f| f.as_list().unwrap()[0].as_atom().unwrap())
            .collect();
        assert_eq!(tags, vec!["rule", "rule", "rule", "wrapper", "wrapper", "blocked-paths"]);
    }
}
