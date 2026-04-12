use super::Lexer;
use crate::ast::*;
use crate::diagnostic::{ParseDiagnostic, ParseDiagnosticKind, Severity, Span};

impl Lexer {
    pub(super) fn read_word_parts(&mut self) -> Vec<WordPart> {
        let mut parts = Vec::new();
        loop {
            match self.peek() {
                None => break,
                Some(ch) if super::is_metachar(ch) => break,
                Some('\'') => {
                    let open_pos = self.byte_pos;
                    self.advance();
                    let s = self.read_until_char('\'');
                    if self.peek().is_none() {
                        self.diagnostics.push(ParseDiagnostic {
                            span: Span {
                                start: open_pos,
                                end: self.byte_pos,
                            },
                            kind: ParseDiagnosticKind::UnterminatedSingleQuote,
                            severity: Severity::Error,
                        });
                    }
                    self.advance(); // skip closing quote (if present)
                    parts.push(WordPart::SingleQuoted(s));
                }
                Some('"') => {
                    let open_pos = self.byte_pos;
                    self.advance();
                    let inner = self.read_double_quoted_parts();
                    if self.peek().is_none() {
                        self.diagnostics.push(ParseDiagnostic {
                            span: Span {
                                start: open_pos,
                                end: self.byte_pos,
                            },
                            kind: ParseDiagnosticKind::UnterminatedDoubleQuote,
                            severity: Severity::Error,
                        });
                    }
                    self.advance(); // skip closing quote (if present)
                    parts.push(WordPart::DoubleQuoted(inner));
                }
                Some('$') => {
                    if let Some(part) = self.read_dollar() {
                        parts.push(part);
                    }
                }
                Some('`') => {
                    let open_pos = self.byte_pos;
                    self.advance();
                    let s = self.read_until_char('`');
                    if self.peek().is_none() {
                        self.diagnostics.push(ParseDiagnostic {
                            span: Span {
                                start: open_pos,
                                end: self.byte_pos,
                            },
                            kind: ParseDiagnosticKind::UnterminatedBacktick,
                            severity: Severity::Error,
                        });
                    }
                    self.advance(); // skip closing backtick
                    parts.push(WordPart::Backtick(s));
                }
                Some('{') => {
                    // Check for brace expansion: {a,b,c}
                    if let Some(exp) = self.try_read_brace_expansion() {
                        parts.push(WordPart::BraceExpansion(exp));
                    } else {
                        // Just a literal {
                        self.advance();
                        parts.push(WordPart::Literal("{".to_string()));
                    }
                }
                Some('*') | Some('?') => {
                    let mut glob = String::new();
                    glob.push(self.advance().unwrap());
                    parts.push(WordPart::Glob(glob));
                }
                Some('[') => {
                    self.advance(); // consume '['
                    match self.peek() {
                        // `[` followed by space, metachar, EOF, or `[` → literal, not glob
                        None | Some('[') | Some(']') => {
                            if let Some(WordPart::Literal(s)) = parts.last_mut() {
                                s.push('[');
                            } else {
                                parts.push(WordPart::Literal("[".to_string()));
                            }
                        }
                        Some(ch) if super::is_metachar(ch) => {
                            if let Some(WordPart::Literal(s)) = parts.last_mut() {
                                s.push('[');
                            } else {
                                parts.push(WordPart::Literal("[".to_string()));
                            }
                        }
                        Some(_) => {
                            // Glob bracket expression: [abc], [a-z], etc.
                            let mut glob = String::from("[");
                            while let Some(ch) = self.peek() {
                                glob.push(ch);
                                self.advance();
                                if ch == ']' {
                                    break;
                                }
                            }
                            parts.push(WordPart::Glob(glob));
                        }
                    }
                }
                Some('\\') => {
                    self.advance();
                    if let Some(escaped) = self.advance() {
                        parts.push(WordPart::Literal(escaped.to_string()));
                    }
                }
                Some(_) => {
                    // Regular literal characters
                    let mut s = String::new();
                    while let Some(ch) = self.peek() {
                        if super::is_metachar(ch)
                            || ch == '\''
                            || ch == '"'
                            || ch == '$'
                            || ch == '`'
                            || ch == '\\'
                            || ch == '*'
                            || ch == '?'
                            || ch == '['
                            || ch == '{'
                        {
                            break;
                        }
                        s.push(ch);
                        self.advance();
                    }
                    if !s.is_empty() {
                        parts.push(WordPart::Literal(s));
                    }
                }
            }
        }
        parts
    }

    pub(super) fn read_double_quoted_parts(&mut self) -> Vec<WordPart> {
        let mut parts = Vec::new();
        let mut literal = String::new();
        loop {
            match self.peek() {
                None | Some('"') => {
                    if !literal.is_empty() {
                        parts.push(WordPart::Literal(literal));
                    }
                    break;
                }
                Some('$') => {
                    if !literal.is_empty() {
                        parts.push(WordPart::Literal(literal.clone()));
                        literal.clear();
                    }
                    if let Some(part) = self.read_dollar() {
                        parts.push(part);
                    }
                }
                Some('`') => {
                    if !literal.is_empty() {
                        parts.push(WordPart::Literal(literal.clone()));
                        literal.clear();
                    }
                    self.advance();
                    let s = self.read_until_char('`');
                    self.advance();
                    parts.push(WordPart::Backtick(s));
                }
                Some('\\') => {
                    self.advance();
                    if let Some(ch) = self.advance() {
                        literal.push(ch);
                    }
                }
                Some(ch) => {
                    literal.push(ch);
                    self.advance();
                }
            }
        }
        parts
    }

    pub(super) fn read_dollar(&mut self) -> Option<WordPart> {
        let dollar_pos = self.byte_pos;
        self.advance(); // skip $
        match self.peek() {
            Some('(') => {
                self.advance(); // skip (
                if self.peek() == Some('(') {
                    // Arithmetic $((expr))
                    self.advance(); // skip second (
                    let (expr, found) = self.read_until_double_paren_checked();
                    if !found {
                        self.diagnostics.push(ParseDiagnostic {
                            span: Span {
                                start: dollar_pos,
                                end: self.byte_pos,
                            },
                            kind: ParseDiagnosticKind::UnterminatedArithmetic,
                            severity: Severity::Error,
                        });
                    }
                    Some(WordPart::Arithmetic(expr))
                } else {
                    // Command substitution $(cmd)
                    let (cmd, found) = self.read_balanced_parens_checked();
                    if !found {
                        self.diagnostics.push(ParseDiagnostic {
                            span: Span {
                                start: dollar_pos,
                                end: self.byte_pos,
                            },
                            kind: ParseDiagnosticKind::UnterminatedCommandSubstitution,
                            severity: Severity::Error,
                        });
                    }
                    // If the command substitution is `cat` fed only by
                    // static heredocs, fold it to a literal — the output
                    // is fully determined at parse time.
                    if let Some(body) = crate::ast::try_fold_static_cat(&cmd) {
                        Some(WordPart::Literal(body))
                    } else {
                        Some(WordPart::CommandSubstitution(cmd))
                    }
                }
            }
            Some('{') => {
                self.advance(); // skip {
                let result = self.read_parameter_expansion();
                // Detect unterminated: if we're at EOF and last char wasn't }, it's unterminated
                if self.peek().is_none() {
                    let input_len = self.input.len();
                    if input_len == 0 || self.input[input_len - 1] != '}' {
                        self.diagnostics.push(ParseDiagnostic {
                            span: Span {
                                start: dollar_pos,
                                end: self.byte_pos,
                            },
                            kind: ParseDiagnosticKind::UnterminatedParameterExpansion,
                            severity: Severity::Error,
                        });
                    }
                }
                result
            }
            Some('\'') => {
                // ANSI-C quoting $'...'
                self.advance(); // skip '
                let s = self.read_ansi_c_string();
                self.advance(); // skip closing '
                Some(WordPart::AnsiCQuoted(s))
            }
            Some(ch)
                if ch.is_ascii_alphanumeric()
                    || ch == '_'
                    || ch == '@'
                    || ch == '#'
                    || ch == '?'
                    || ch == '-'
                    || ch == '!'
                    || ch == '$'
                    || ch == '*' =>
            {
                let mut name = String::new();
                if ch.is_ascii_alphanumeric() || ch == '_' {
                    while let Some(c) = self.peek() {
                        if c.is_ascii_alphanumeric() || c == '_' {
                            name.push(c);
                            self.advance();
                        } else {
                            break;
                        }
                    }
                } else {
                    // Special variables: $@, $#, $?, $-, $!, $$, $*
                    name.push(ch);
                    self.advance();
                }
                Some(WordPart::Parameter(name))
            }
            _ => {
                // Bare $ at end or before non-variable char
                Some(WordPart::Literal("$".to_string()))
            }
        }
    }

    pub(super) fn try_read_brace_expansion(&mut self) -> Option<Vec<String>> {
        // Lookahead to check if this is a brace expansion {a,b,...}
        let saved = self.save_state();
        self.advance(); // skip {
        let mut items = Vec::new();
        let mut current = String::new();
        let mut has_comma = false;
        loop {
            match self.peek() {
                None => {
                    // Unterminated, restore position
                    self.restore_state(saved);
                    return None;
                }
                Some('}') => {
                    self.advance();
                    if has_comma {
                        items.push(current);
                        return Some(items);
                    } else {
                        // No comma means not a brace expansion
                        self.restore_state(saved);
                        return None;
                    }
                }
                Some(',') => {
                    has_comma = true;
                    items.push(current.clone());
                    current.clear();
                    self.advance();
                }
                Some(ch) if super::is_metachar(ch) => {
                    // Not a simple brace expansion
                    self.restore_state(saved);
                    return None;
                }
                Some(ch) => {
                    current.push(ch);
                    self.advance();
                }
            }
        }
    }
}
