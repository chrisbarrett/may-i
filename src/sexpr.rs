// S-expression parser — R10f
// Zero-dependency parser producing Atom | List AST.
//
// Quoted strings: "hello\nworld" (supports \\, \", \n, \t)
// Bare atoms: letters, digits, - _ * . / ^ :
// Comments: ; to end of line
// Parentheses delimit lists.

use crate::errors::{RawError, Span};

/// S-expression AST node with source spans.
#[derive(Debug, Clone, Eq)]
pub enum Sexpr {
    Atom(String, Span),
    List(Vec<Sexpr>, Span),
}

/// PartialEq ignores spans so existing test assertions are preserved.
impl PartialEq for Sexpr {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Sexpr::Atom(a, _), Sexpr::Atom(b, _)) => a == b,
            (Sexpr::List(a, _), Sexpr::List(b, _)) => a == b,
            _ => false,
        }
    }
}

impl Sexpr {
    /// Return the atom string, or `None` if this is a list.
    pub fn as_atom(&self) -> Option<&str> {
        match self {
            Sexpr::Atom(s, _) => Some(s),
            Sexpr::List(..) => None,
        }
    }

    /// Return the list contents, or `None` if this is an atom.
    pub fn as_list(&self) -> Option<&[Sexpr]> {
        match self {
            Sexpr::Atom(..) => None,
            Sexpr::List(v, _) => Some(v),
        }
    }

    /// Return the byte-offset span of this node.
    pub fn span(&self) -> Span {
        match self {
            Sexpr::Atom(_, s) | Sexpr::List(_, s) => *s,
        }
    }
}

impl std::fmt::Display for Sexpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Sexpr::Atom(s, _) => {
                if s.is_empty() || s.contains(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == '"' || c == ';' || c == '\\') {
                    write!(f, "\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
                } else {
                    write!(f, "{s}")
                }
            }
            Sexpr::List(items, _) => {
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

#[derive(Debug)]
struct Token {
    kind: TokenKind,
    span: Span,
}

#[derive(Debug, PartialEq)]
enum TokenKind {
    Open,
    Close,
    Atom(String),
    Str(String),
}

fn is_atom_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '*' | '.' | '/' | '^' | ':' | '+' | '?')
}

fn tokenize(input: &str) -> Result<Vec<Token>, RawError> {
    let mut tokens = Vec::new();
    let mut chars = input.char_indices().peekable();

    while let Some(&(pos, ch)) = chars.peek() {
        match ch {
            ' ' | '\t' | '\n' | '\r' => {
                chars.next();
            }
            ';' => {
                // Comment: skip to end of line
                while let Some(&(_, c)) = chars.peek() {
                    chars.next();
                    if c == '\n' {
                        break;
                    }
                }
            }
            '(' => {
                tokens.push(Token { kind: TokenKind::Open, span: Span::new(pos, pos + 1) });
                chars.next();
            }
            ')' => {
                tokens.push(Token { kind: TokenKind::Close, span: Span::new(pos, pos + 1) });
                chars.next();
            }
            '"' => {
                let start = pos;
                chars.next();
                let mut s = String::new();
                loop {
                    match chars.next() {
                        None => {
                            return Err(RawError::new(
                                "unterminated string",
                                Span::new(start, input.len()),
                            ));
                        }
                        Some((end_pos, '"')) => {
                            tokens.push(Token {
                                kind: TokenKind::Str(s),
                                span: Span::new(start, end_pos + 1),
                            });
                            break;
                        }
                        Some((esc_pos, '\\')) => match chars.next() {
                            Some((_, '\\')) => s.push('\\'),
                            Some((_, '"')) => s.push('"'),
                            Some((_, 'n')) => s.push('\n'),
                            Some((_, 't')) => s.push('\t'),
                            Some((end_pos, c)) => {
                                return Err(RawError::new(
                                    format!("unknown escape: \\{c}"),
                                    Span::new(esc_pos, end_pos + c.len_utf8()),
                                ));
                            }
                            None => {
                                return Err(RawError::new(
                                    "unterminated escape in string",
                                    Span::new(esc_pos, input.len()),
                                ));
                            }
                        },
                        Some((_, c)) => s.push(c),
                    }
                }
            }
            c if is_atom_char(c) => {
                let start = pos;
                let mut s = String::new();
                let mut end = input.len();
                loop {
                    match chars.peek() {
                        Some(&(end_pos, c)) if is_atom_char(c) => {
                            s.push(c);
                            chars.next();
                        }
                        Some(&(end_pos, _)) => {
                            end = end_pos;
                            break;
                        }
                        None => break,
                    }
                }
                tokens.push(Token {
                    kind: TokenKind::Atom(s),
                    span: Span::new(start, end),
                });
            }
            _ => {
                return Err(RawError::new(
                    format!("unexpected character: {ch:?}"),
                    Span::new(pos, pos + ch.len_utf8()),
                ));
            }
        }
    }

    Ok(tokens)
}

// --- Parser ---

/// Return the 0-based column (byte offset from start of line) for an offset.
fn column_of(input: &str, offset: usize) -> usize {
    let before = &input[..offset];
    match before.rfind('\n') {
        Some(nl) => offset - nl - 1,
        None => offset,
    }
}

/// Return the 0-based line number for an offset.
fn line_of(input: &str, offset: usize) -> usize {
    input[..offset].bytes().filter(|&b| b == b'\n').count()
}

/// Parse a string containing zero or more s-expressions into a list of top-level forms.
pub fn parse(input: &str) -> Result<Vec<Sexpr>, RawError> {
    let tokens = tokenize(input)?;
    let mut pos = 0;
    let mut results: Vec<Sexpr> = Vec::new();
    while pos < tokens.len() {
        // Case C: extra ')' at top level
        if let Some(Token { kind: TokenKind::Close, span }) = tokens.get(pos) {
            let mut err = RawError::new("unexpected ')'", *span);
            if let Some(prev) = results.last() {
                let prev_span = prev.span();
                let close_offset = prev_span.end - 1;
                err = err.with_secondary(
                    Span::new(close_offset, close_offset + 1),
                    "previous form closed here",
                );
            }
            return Err(err);
        }
        let (sexpr, next) = parse_one(input, &tokens, pos)?;
        results.push(sexpr);
        pos = next;
    }
    Ok(results)
}

fn parse_one(input: &str, tokens: &[Token], pos: usize) -> Result<(Sexpr, usize), RawError> {
    match tokens.get(pos) {
        None => Err(RawError::new(
            "unexpected end of input",
            Span::new(0, 0),
        )),
        Some(Token { kind: TokenKind::Close, span }) => Err(RawError::new(
            "unexpected ')'",
            *span,
        )),
        Some(Token { kind: TokenKind::Atom(s) | TokenKind::Str(s), span }) => {
            Ok((Sexpr::Atom(s.clone(), *span), pos + 1))
        }
        Some(Token { kind: TokenKind::Open, span: open_span }) => {
            let opener_col = column_of(input, open_span.start);
            let opener_line = line_of(input, open_span.start);
            let mut items: Vec<Sexpr> = Vec::new();
            let mut p = pos + 1;
            loop {
                match tokens.get(p) {
                    None => {
                        // Case A: unclosed '(' at EOF
                        let mut err = RawError::new("unclosed '('", *open_span)
                            .with_help("add a closing ')'");
                        if let Some(last_item) = items.last() {
                            let last_span = last_item.span();
                            err = err.with_secondary(
                                Span::new(last_span.end, last_span.end),
                                "last item ends here",
                            );
                        }
                        return Err(err);
                    }
                    Some(Token { kind: TokenKind::Close, span: close_span }) => {
                        let list_span = Span::new(open_span.start, close_span.end);
                        return Ok((Sexpr::List(items, list_span), p + 1));
                    }
                    Some(Token { kind: TokenKind::Open, span: next_span }) => {
                        // Case B: indentation heuristic for sibling absorbed
                        let next_col = column_of(input, next_span.start);
                        let next_line = line_of(input, next_span.start);
                        if !items.is_empty()
                            && next_line > opener_line
                            && next_col == opener_col
                        {
                            let mut err = RawError::new("unclosed '('", *open_span)
                                .with_help("add a closing ')'");
                            err = err.with_secondary(*next_span, "this looks like a new form");
                            return Err(err);
                        }
                        let (item, next) = parse_one(input, tokens, p)?;
                        items.push(item);
                        p = next;
                    }
                    _ => {
                        let (item, next) = parse_one(input, tokens, p)?;
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
        Sexpr::Atom(s.to_string(), Span::new(0, 0))
    }

    fn list(items: Vec<Sexpr>) -> Sexpr {
        Sexpr::List(items, Span::new(0, 0))
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

    // --- Paren mismatch diagnostics ---

    #[test]
    fn unclosed_paren_at_eof_with_secondary() {
        // Case A: unclosed '(' at EOF shows last item
        let input = "(rule foo";
        let err = parse(input).unwrap_err();
        assert_eq!(err.message, "unclosed '('");
        assert_eq!(err.span, Span::new(0, 1));
        assert!(err.help.as_deref() == Some("add a closing ')'"));
        let (sec_span, sec_label) = err.secondary.as_deref().unwrap();
        assert_eq!(sec_label, "last item ends here");
        // "foo" ends at offset 9
        assert_eq!(sec_span.start, 9);
    }

    #[test]
    fn unclosed_paren_at_eof_empty_list() {
        // Case A with no items: no secondary
        let input = "(";
        let err = parse(input).unwrap_err();
        assert_eq!(err.message, "unclosed '('");
        assert!(err.secondary.is_none());
    }

    #[test]
    fn extra_close_with_previous_form() {
        // Case C: extra ')' shows previous form's close
        let input = "(a b))";
        let err = parse(input).unwrap_err();
        assert_eq!(err.message, "unexpected ')'");
        assert_eq!(err.span, Span::new(5, 6));
        let (sec_span, sec_label) = err.secondary.as_deref().unwrap();
        assert_eq!(sec_label, "previous form closed here");
        // The ')' at offset 4 closed the form (a b)
        assert_eq!(sec_span.start, 4);
        assert_eq!(sec_span.end, 5);
    }

    #[test]
    fn extra_close_no_previous_form() {
        // Case C: bare ')' at top level with no previous form
        let input = ")";
        let err = parse(input).unwrap_err();
        assert_eq!(err.message, "unexpected ')'");
        assert!(err.secondary.is_none());
    }

    #[test]
    fn sibling_absorbed_by_indentation() {
        // Case B: second form at same column as opener triggers heuristic
        let input = "(rule foo\n(other bar)";
        let err = parse(input).unwrap_err();
        assert_eq!(err.message, "unclosed '('");
        assert_eq!(err.span, Span::new(0, 1)); // opener
        let (sec_span, sec_label) = err.secondary.as_deref().unwrap();
        assert_eq!(sec_label, "this looks like a new form");
        // The '(' of (other bar) is at offset 10
        assert_eq!(sec_span.start, 10);
    }

    #[test]
    fn indented_sublist_no_false_positive() {
        // Indented sublists should NOT trigger Case B
        let input = "(rule\n  (command foo)\n  (effect bar))";
        let forms = parse(input).unwrap();
        assert_eq!(forms.len(), 1);
        let items = forms[0].as_list().unwrap();
        assert_eq!(items.len(), 3);
    }

    #[test]
    fn atom_at_column_zero_no_heuristic() {
        // Atoms at column 0 should NOT trigger Case B (only '(' does)
        let input = "(blocked-paths\n\"foo\")";
        let forms = parse(input).unwrap();
        assert_eq!(forms.len(), 1);
        let items = forms[0].as_list().unwrap();
        assert_eq!(items[0].as_atom(), Some("blocked-paths"));
        assert_eq!(items[1].as_atom(), Some("foo"));
    }

    #[test]
    fn same_line_opens_no_heuristic() {
        // Multiple opens on the same line should NOT trigger Case B
        let input = "((a) (b))";
        let forms = parse(input).unwrap();
        assert_eq!(forms.len(), 1);
    }

    #[test]
    fn column_of_basic() {
        assert_eq!(column_of("hello", 3), 3);
        assert_eq!(column_of("ab\ncd", 3), 0); // 'c' is at col 0
        assert_eq!(column_of("ab\ncd", 4), 1); // 'd' is at col 1
        assert_eq!(column_of("ab\n\ncd", 4), 0); // 'c' after blank line
    }

    #[test]
    fn line_of_basic() {
        assert_eq!(line_of("hello", 3), 0);
        assert_eq!(line_of("ab\ncd", 3), 1);
        assert_eq!(line_of("ab\ncd\nef", 6), 2);
    }
}
