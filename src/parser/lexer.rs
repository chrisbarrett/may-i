use super::ast::*;

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Token {
    Word(Word),
    Pipe,           // |
    And,            // &&
    Or,             // ||
    Semi,           // ;
    Amp,            // &
    LParen,         // (
    RParen,         // )
    LBrace,         // {
    RBrace,         // }
    Newline,
    If,
    Then,
    Elif,
    Else,
    Fi,
    For,
    In,
    While,
    Until,
    Do,
    Done,
    Case,
    Esac,
    DoubleSemi,     // ;;
    SemiAmp,        // ;&
    DoubleSemiAmp,  // ;;&
    Function,
    Redirect(Redirection),
    Eof,
}

pub(super) struct Lexer {
    input: Vec<char>,
    pos: usize,
    byte_pos: usize,
}

impl Lexer {
    pub(super) fn new(input: &str) -> Self {
        Lexer {
            input: input.chars().collect(),
            pos: 0,
            byte_pos: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.input.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<char> {
        let ch = self.input.get(self.pos).copied();
        if let Some(c) = ch {
            self.pos += 1;
            self.byte_pos += c.len_utf8();
        }
        ch
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.input.get(self.pos + offset).copied()
    }

    fn save_state(&self) -> (usize, usize) {
        (self.pos, self.byte_pos)
    }

    fn restore_state(&mut self, state: (usize, usize)) {
        self.pos = state.0;
        self.byte_pos = state.1;
    }

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.peek() {
            if ch == ' ' || ch == '\t' {
                self.advance();
            } else if ch == '#' {
                // Skip comment to end of line
                while let Some(c) = self.peek() {
                    if c == '\n' {
                        break;
                    }
                    self.advance();
                }
            } else {
                break;
            }
        }
    }

    pub(super) fn tokenize(&mut self) -> Vec<Token> {
        self.tokenize_with_offsets().into_iter().map(|(tok, _)| tok).collect()
    }

    pub(super) fn tokenize_with_offsets(&mut self) -> Vec<(Token, usize)> {
        let mut tokens = Vec::new();
        loop {
            self.skip_whitespace();
            let start = self.byte_pos;
            match self.peek() {
                None => {
                    tokens.push((Token::Eof, start));
                    break;
                }
                Some('\n') => {
                    self.advance();
                    tokens.push((Token::Newline, start));
                }
                Some(';') => {
                    self.advance();
                    if self.peek() == Some(';') {
                        self.advance();
                        if self.peek() == Some('&') {
                            self.advance();
                            tokens.push((Token::DoubleSemiAmp, start));
                        } else {
                            tokens.push((Token::DoubleSemi, start));
                        }
                    } else if self.peek() == Some('&') {
                        self.advance();
                        tokens.push((Token::SemiAmp, start));
                    } else {
                        tokens.push((Token::Semi, start));
                    }
                }
                Some('&') => {
                    self.advance();
                    if self.peek() == Some('&') {
                        self.advance();
                        tokens.push((Token::And, start));
                    } else {
                        tokens.push((Token::Amp, start));
                    }
                }
                Some('|') => {
                    self.advance();
                    if self.peek() == Some('|') {
                        self.advance();
                        tokens.push((Token::Or, start));
                    } else {
                        tokens.push((Token::Pipe, start));
                    }
                }
                Some('(') => {
                    self.advance();
                    tokens.push((Token::LParen, start));
                }
                Some(')') => {
                    self.advance();
                    tokens.push((Token::RParen, start));
                }
                Some(ch) if is_redirect_start(ch) => {
                    if let Some(tok) = self.try_read_redirect_or_process_sub() {
                        tokens.push((tok, start));
                    }
                }
                _ => {
                    // Try to read a word (may include fd prefix for redirect)
                    if let Some(tok) = self.read_word_or_keyword() {
                        tokens.push((tok, start));
                    }
                }
            }
        }
        tokens
    }

    fn try_read_redirect_or_process_sub(&mut self) -> Option<Token> {
        // Check for process substitution <(cmd) or >(cmd)
        let ch = self.peek()?;
        if (ch == '<' || ch == '>') && self.peek_at(1) == Some('(') {
            let direction = if ch == '<' {
                ProcessDirection::Input
            } else {
                ProcessDirection::Output
            };
            self.advance(); // skip < or >
            self.advance(); // skip (
            let cmd = self.read_balanced_parens();
            let word = Word {
                parts: vec![WordPart::ProcessSubstitution {
                    direction,
                    command: cmd,
                }],
            };
            return Some(Token::Word(word));
        }

        self.read_redirection()
    }

    fn read_redirection(&mut self) -> Option<Token> {
        let ch = self.peek()?;
        let fd = None; // fd prefix handled at word level

        match ch {
            '<' => {
                self.advance();
                let kind = match self.peek() {
                    Some('<') => {
                        self.advance();
                        match self.peek() {
                            Some('<') => {
                                self.advance();
                                RedirectionKind::Herestring
                            }
                            Some('-') => {
                                self.advance();
                                RedirectionKind::HeredocStrip
                            }
                            _ => RedirectionKind::Heredoc,
                        }
                    }
                    Some('&') => {
                        self.advance();
                        RedirectionKind::DupInput
                    }
                    _ => RedirectionKind::Input,
                };
                self.skip_whitespace();
                let target = self.read_redirect_target(&kind);
                Some(Token::Redirect(Redirection { fd, kind, target }))
            }
            '>' => {
                self.advance();
                let kind = match self.peek() {
                    Some('>') => {
                        self.advance();
                        RedirectionKind::Append
                    }
                    Some('|') => {
                        self.advance();
                        RedirectionKind::Clobber
                    }
                    Some('&') => {
                        self.advance();
                        RedirectionKind::DupOutput
                    }
                    _ => RedirectionKind::Output,
                };
                self.skip_whitespace();
                let target = self.read_redirect_target(&kind);
                Some(Token::Redirect(Redirection { fd, kind, target }))
            }
            // All callers guard on `ch == '<' || ch == '>'` before
            // calling read_redirection, so this arm is unreachable.
            _ => unreachable!("read_redirection called with '{ch}'"),
        }
    }

    fn read_redirect_target(&mut self, kind: &RedirectionKind) -> RedirectionTarget {
        match kind {
            RedirectionKind::DupInput | RedirectionKind::DupOutput => {
                // Read fd number or '-'
                let mut s = String::new();
                while let Some(ch) = self.peek() {
                    if ch.is_ascii_digit() || ch == '-' {
                        s.push(ch);
                        self.advance();
                    } else {
                        break;
                    }
                }
                if let Ok(fd) = s.parse::<i32>() {
                    RedirectionTarget::Fd(fd)
                } else {
                    RedirectionTarget::File(Word::literal(&s))
                }
            }
            RedirectionKind::Heredoc | RedirectionKind::HeredocStrip => {
                self.skip_whitespace();
                let strip = matches!(kind, RedirectionKind::HeredocStrip);
                let delim = self.read_heredoc_delimiter();

                // Scan forward line-by-line to collect the heredoc body
                // Move past the current line (skip to the newline after the delimiter word)
                while let Some(ch) = self.peek() {
                    self.advance();
                    if ch == '\n' {
                        break;
                    }
                }

                let mut body = String::new();
                loop {
                    if self.peek().is_none() {
                        break; // EOF before delimiter — graceful degradation
                    }
                    // Read one line
                    let mut line = String::new();
                    while let Some(ch) = self.peek() {
                        self.advance();
                        if ch == '\n' {
                            break;
                        }
                        line.push(ch);
                    }

                    // Check if this line is the delimiter
                    let compare = if strip {
                        line.trim_start_matches('\t').to_string()
                    } else {
                        line.clone()
                    };
                    if compare == delim {
                        break;
                    }

                    // Apply tab-stripping for <<- to the body lines too
                    if strip {
                        body.push_str(line.trim_start_matches('\t'));
                    } else {
                        body.push_str(&line);
                    }
                    body.push('\n');
                }

                RedirectionTarget::Heredoc(body)
            }
            RedirectionKind::Herestring => {
                self.skip_whitespace();
                let word = self.read_word_value();
                RedirectionTarget::File(word)
            }
            _ => {
                self.skip_whitespace();
                let word = self.read_word_value();
                RedirectionTarget::File(word)
            }
        }
    }

    fn read_plain_word_text(&mut self) -> String {
        let mut s = String::new();
        while let Some(ch) = self.peek() {
            if is_word_char(ch) {
                s.push(ch);
                self.advance();
            } else {
                break;
            }
        }
        s
    }

    /// Read a heredoc delimiter, handling quoted (`'EOF'`, `"EOF"`) and
    /// backslash-escaped (`\EOF`) forms by stripping the quoting.
    fn read_heredoc_delimiter(&mut self) -> String {
        match self.peek() {
            Some('\'') => {
                self.advance();
                let s = self.read_until_char('\'');
                self.advance(); // skip closing quote
                s
            }
            Some('"') => {
                self.advance();
                let s = self.read_until_char('"');
                self.advance(); // skip closing quote
                s
            }
            Some('\\') => {
                self.advance(); // skip leading backslash
                self.read_plain_word_text()
            }
            _ => self.read_plain_word_text(),
        }
    }

    fn read_word_value(&mut self) -> Word {
        let parts = self.read_word_parts();
        if parts.is_empty() {
            Word::literal("")
        } else {
            Word { parts }
        }
    }

    fn read_word_parts(&mut self) -> Vec<WordPart> {
        let mut parts = Vec::new();
        loop {
            match self.peek() {
                None => break,
                Some(ch) if is_metachar(ch) => break,
                Some('\'') => {
                    self.advance();
                    let s = self.read_until_char('\'');
                    self.advance(); // skip closing quote (if present)
                    parts.push(WordPart::SingleQuoted(s));
                }
                Some('"') => {
                    self.advance();
                    let inner = self.read_double_quoted_parts();
                    self.advance(); // skip closing quote (if present)
                    parts.push(WordPart::DoubleQuoted(inner));
                }
                Some('$') => {
                    if let Some(part) = self.read_dollar() {
                        parts.push(part);
                    }
                }
                Some('`') => {
                    self.advance();
                    let s = self.read_until_char('`');
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
                        Some(ch) if is_metachar(ch) => {
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
                        if is_metachar(ch)
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

    fn read_double_quoted_parts(&mut self) -> Vec<WordPart> {
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

    fn read_dollar(&mut self) -> Option<WordPart> {
        self.advance(); // skip $
        match self.peek() {
            Some('(') => {
                self.advance(); // skip (
                if self.peek() == Some('(') {
                    // Arithmetic $((expr))
                    self.advance(); // skip second (
                    let expr = self.read_until_double_paren();
                    Some(WordPart::Arithmetic(expr))
                } else {
                    // Command substitution $(cmd)
                    let cmd = self.read_balanced_parens();
                    // If the command substitution is `cat` fed only by
                    // static heredocs, fold it to a literal — the output
                    // is fully determined at parse time.
                    if let Some(body) = try_fold_static_cat(&cmd) {
                        Some(WordPart::Literal(body))
                    } else {
                        Some(WordPart::CommandSubstitution(cmd))
                    }
                }
            }
            Some('{') => {
                self.advance(); // skip {
                self.read_parameter_expansion()
            }
            Some('\'') => {
                // ANSI-C quoting $'...'
                self.advance(); // skip '
                let s = self.read_ansi_c_string();
                self.advance(); // skip closing '
                Some(WordPart::AnsiCQuoted(s))
            }
            Some(ch) if ch.is_ascii_alphanumeric() || ch == '_' || ch == '@' || ch == '#'
                || ch == '?' || ch == '-' || ch == '!' || ch == '$' || ch == '*' =>
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

    /// Parse the content of `${...}` after the opening `{` has been consumed.
    /// Produces either a simple `ParameterExpansion(name)` for `${VAR}` or a
    /// structured `ParameterExpansionOp { name, op }` for operator forms.
    fn read_parameter_expansion(&mut self) -> Option<WordPart> {
        // Special case: ${#VAR} (length operator)
        if self.peek() == Some('#') {
            // Look ahead: if what follows '#' is a valid identifier and then '}',
            // this is the length operator.
            let saved = self.save_state();
            self.advance(); // skip #
            let name = self.read_identifier();
            if !name.is_empty() && self.peek() == Some('}') {
                self.advance(); // skip }
                return Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::Length,
                });
            }
            // Not a length operator; restore and fall through to flat parsing
            self.restore_state(saved);
        }

        // Read the variable name
        let name = self.read_identifier();
        if name.is_empty() {
            // Not a valid identifier; fall back to flat string
            let s = self.read_until_char('}');
            self.advance(); // skip }
            return Some(WordPart::ParameterExpansion(s));
        }

        // Check what follows the name
        match self.peek() {
            Some('}') => {
                self.advance(); // skip }
                Some(WordPart::ParameterExpansion(name))
            }
            Some('#') => {
                self.advance(); // skip #
                let longest = if self.peek() == Some('#') {
                    self.advance();
                    true
                } else {
                    false
                };
                let pattern = self.read_until_char('}');
                self.advance(); // skip }
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::StripPrefix { longest, pattern },
                })
            }
            Some('%') => {
                self.advance(); // skip %
                let longest = if self.peek() == Some('%') {
                    self.advance();
                    true
                } else {
                    false
                };
                let pattern = self.read_until_char('}');
                self.advance(); // skip }
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::StripSuffix { longest, pattern },
                })
            }
            Some('/') => {
                self.advance(); // skip /
                let all = if self.peek() == Some('/') {
                    self.advance();
                    true
                } else {
                    false
                };
                let pattern = self.read_until_either('/', '}');
                let replacement = if self.peek() == Some('/') {
                    self.advance(); // skip separator /
                    self.read_until_char('}')
                } else {
                    String::new()
                };
                self.advance(); // skip }
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::Replace { all, pattern, replacement },
                })
            }
            Some(':') => {
                self.advance(); // skip :
                match self.peek() {
                    Some('-') => {
                        self.advance();
                        let value = self.read_until_char('}');
                        self.advance();
                        Some(WordPart::ParameterExpansionOp {
                            name,
                            op: ParameterOperator::Default { colon: true, value },
                        })
                    }
                    Some('+') => {
                        self.advance();
                        let value = self.read_until_char('}');
                        self.advance();
                        Some(WordPart::ParameterExpansionOp {
                            name,
                            op: ParameterOperator::Alternative { colon: true, value },
                        })
                    }
                    Some('?') => {
                        self.advance();
                        let message = self.read_until_char('}');
                        self.advance();
                        Some(WordPart::ParameterExpansionOp {
                            name,
                            op: ParameterOperator::Error { colon: true, message },
                        })
                    }
                    Some('=') => {
                        self.advance();
                        let value = self.read_until_char('}');
                        self.advance();
                        Some(WordPart::ParameterExpansionOp {
                            name,
                            op: ParameterOperator::Assign { colon: true, value },
                        })
                    }
                    _ => {
                        // Substring: ${VAR:offset} or ${VAR:offset:length}
                        let offset = self.read_until_either(':', '}');
                        let length = if self.peek() == Some(':') {
                            self.advance();
                            Some(self.read_until_char('}'))
                        } else {
                            None
                        };
                        self.advance(); // skip }
                        Some(WordPart::ParameterExpansionOp {
                            name,
                            op: ParameterOperator::Substring { offset, length },
                        })
                    }
                }
            }
            Some('-') => {
                self.advance();
                let value = self.read_until_char('}');
                self.advance();
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::Default { colon: false, value },
                })
            }
            Some('+') => {
                self.advance();
                let value = self.read_until_char('}');
                self.advance();
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::Alternative { colon: false, value },
                })
            }
            Some('?') => {
                self.advance();
                let message = self.read_until_char('}');
                self.advance();
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::Error { colon: false, message },
                })
            }
            Some('=') => {
                self.advance();
                let value = self.read_until_char('}');
                self.advance();
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::Assign { colon: false, value },
                })
            }
            Some('^') => {
                self.advance();
                let all = if self.peek() == Some('^') {
                    self.advance();
                    true
                } else {
                    false
                };
                // Skip to closing }
                self.read_until_char('}');
                self.advance();
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::Uppercase { all },
                })
            }
            Some(',') => {
                self.advance();
                let all = if self.peek() == Some(',') {
                    self.advance();
                    true
                } else {
                    false
                };
                // Skip to closing }
                self.read_until_char('}');
                self.advance();
                Some(WordPart::ParameterExpansionOp {
                    name,
                    op: ParameterOperator::Lowercase { all },
                })
            }
            _ => {
                // Unknown operator; fall back to flat string
                let rest = self.read_until_char('}');
                self.advance(); // skip }
                Some(WordPart::ParameterExpansion(format!("{name}{rest}")))
            }
        }
    }

    /// Read a shell identifier (alphanumeric + underscore).
    fn read_identifier(&mut self) -> String {
        let mut name = String::new();
        while let Some(ch) = self.peek() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                name.push(ch);
                self.advance();
            } else {
                break;
            }
        }
        name
    }

    /// Read until either `a` or `b` is found (or EOF). Does not consume the delimiter.
    fn read_until_either(&mut self, a: char, b: char) -> String {
        let mut s = String::new();
        while let Some(ch) = self.peek() {
            if ch == a || ch == b {
                break;
            }
            s.push(ch);
            self.advance();
        }
        s
    }

    fn read_until_char(&mut self, end: char) -> String {
        let mut s = String::new();
        while let Some(ch) = self.peek() {
            if ch == end {
                break;
            }
            s.push(ch);
            self.advance();
        }
        s
    }

    fn read_ansi_c_string(&mut self) -> String {
        let mut s = String::new();
        while let Some(ch) = self.peek() {
            if ch == '\'' {
                break;
            }
            self.advance();
            if ch == '\\' {
                match self.peek() {
                    None => s.push('\\'),
                    Some(esc) => {
                        self.advance();
                        match esc {
                            '\\' => s.push('\\'),
                            'n' => s.push('\n'),
                            't' => s.push('\t'),
                            'r' => s.push('\r'),
                            'a' => s.push('\x07'),
                            'b' => s.push('\x08'),
                            'e' | 'E' => s.push('\x1B'),
                            'f' => s.push('\x0C'),
                            'v' => s.push('\x0B'),
                            '\'' => s.push('\''),
                            '"' => s.push('"'),
                            '0' => {
                                // Octal: \0NNN (up to 3 octal digits)
                                let mut oct = String::new();
                                for _ in 0..3 {
                                    match self.peek() {
                                        Some(c) if c.is_ascii_digit() && c < '8' => {
                                            oct.push(c);
                                            self.advance();
                                        }
                                        _ => break,
                                    }
                                }
                                if oct.is_empty() {
                                    s.push('\0');
                                } else if let Ok(val) = u32::from_str_radix(&oct, 8)
                                    && let Some(c) = char::from_u32(val)
                                {
                                    s.push(c);
                                }
                            }
                            'x' => {
                                // Hex: \xHH (up to 2 hex digits)
                                let mut hex = String::new();
                                for _ in 0..2 {
                                    match self.peek() {
                                        Some(c) if c.is_ascii_hexdigit() => {
                                            hex.push(c);
                                            self.advance();
                                        }
                                        _ => break,
                                    }
                                }
                                if let Ok(val) = u32::from_str_radix(&hex, 16)
                                    && let Some(c) = char::from_u32(val)
                                {
                                    s.push(c);
                                }
                            }
                            'u' => {
                                // Unicode: \uHHHH (up to 4 hex digits)
                                let mut hex = String::new();
                                for _ in 0..4 {
                                    match self.peek() {
                                        Some(c) if c.is_ascii_hexdigit() => {
                                            hex.push(c);
                                            self.advance();
                                        }
                                        _ => break,
                                    }
                                }
                                if let Ok(val) = u32::from_str_radix(&hex, 16)
                                    && let Some(c) = char::from_u32(val)
                                {
                                    s.push(c);
                                }
                            }
                            'U' => {
                                // Unicode: \UHHHHHHHH (up to 8 hex digits)
                                let mut hex = String::new();
                                for _ in 0..8 {
                                    match self.peek() {
                                        Some(c) if c.is_ascii_hexdigit() => {
                                            hex.push(c);
                                            self.advance();
                                        }
                                        _ => break,
                                    }
                                }
                                if let Ok(val) = u32::from_str_radix(&hex, 16)
                                    && let Some(c) = char::from_u32(val)
                                {
                                    s.push(c);
                                }
                            }
                            'c' => {
                                // Control character: \cX
                                if let Some(ctrl) = self.peek() {
                                    self.advance();
                                    let ctrl_val = (ctrl as u32) & 0x1F;
                                    if let Some(c) = char::from_u32(ctrl_val) {
                                        s.push(c);
                                    }
                                }
                            }
                            other => {
                                // Unknown escape: literal character (bash behavior)
                                s.push(other);
                            }
                        }
                    }
                }
            } else {
                s.push(ch);
            }
        }
        s
    }

    fn read_until_double_paren(&mut self) -> String {
        let mut s = String::new();
        loop {
            match self.peek() {
                None => break,
                Some(')') if self.peek_at(1) == Some(')') => {
                    self.advance();
                    self.advance();
                    break;
                }
                Some(ch) => {
                    s.push(ch);
                    self.advance();
                }
            }
        }
        s
    }

    fn read_balanced_parens(&mut self) -> String {
        let mut s = String::new();
        let mut depth = 1;
        loop {
            match self.peek() {
                None => break,
                Some('(') => {
                    depth += 1;
                    s.push('(');
                    self.advance();
                }
                Some(')') => {
                    depth -= 1;
                    if depth == 0 {
                        self.advance();
                        break;
                    }
                    s.push(')');
                    self.advance();
                }
                Some(ch) => {
                    s.push(ch);
                    self.advance();
                }
            }
        }
        s
    }

    fn try_read_brace_expansion(&mut self) -> Option<Vec<String>> {
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
                Some(ch) if is_metachar(ch) => {
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

    pub(super) fn read_word_or_keyword(&mut self) -> Option<Token> {
        // Check for fd number prefix before redirect
        let saved = self.save_state();
        let mut fd_str = String::new();
        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() {
                fd_str.push(ch);
                self.advance();
            } else {
                break;
            }
        }

        if !fd_str.is_empty() {
            if let Some(ch) = self.peek()
                && (ch == '<' || ch == '>')
            {
                let fd: Option<i32> = fd_str.parse().ok();
                if let Some(mut tok) = self.read_redirection() {
                    if let Token::Redirect(ref mut redir) = tok {
                        redir.fd = fd;
                    }
                    return Some(tok);
                }
            }
            // Not a redirect prefix, restore and read as word
            self.restore_state(saved);
        }

        let parts = self.read_word_parts();
        // The main tokenizer loop only calls read_word_or_keyword for
        // characters that are not metacharacters, so read_word_parts
        // always consumes at least one character here.
        assert!(!parts.is_empty(), "unreachable: read_word_or_keyword called at metachar");

        // Check if this is a keyword (single literal part)
        if parts.len() == 1
            && let WordPart::Literal(ref s) = parts[0]
        {
            match s.as_str() {
                "if" => return Some(Token::If),
                "then" => return Some(Token::Then),
                "elif" => return Some(Token::Elif),
                "else" => return Some(Token::Else),
                "fi" => return Some(Token::Fi),
                "for" => return Some(Token::For),
                "in" => return Some(Token::In),
                "while" => return Some(Token::While),
                "until" => return Some(Token::Until),
                "do" => return Some(Token::Do),
                "done" => return Some(Token::Done),
                "case" => return Some(Token::Case),
                "esac" => return Some(Token::Esac),
                "function" => return Some(Token::Function),
                "{" => return Some(Token::LBrace),
                "}" => return Some(Token::RBrace),
                _ => {}
            }
        }

        Some(Token::Word(Word { parts }))
    }
}

pub(super) fn is_metachar(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\n' | '|' | '&' | ';' | '(' | ')' | '<' | '>' | '#')
}

fn is_word_char(ch: char) -> bool {
    !is_metachar(ch) && ch != '\'' && ch != '"' && ch != '`' && ch != '$' && ch != '\\'
}

pub(super) fn is_redirect_start(ch: char) -> bool {
    ch == '<' || ch == '>'
}
