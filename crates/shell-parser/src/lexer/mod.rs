use super::ast::*;
use super::diagnostic::ParseDiagnostic;

mod param_expansion;
mod string_readers;
mod word_parts;

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Token {
    Word(Word),
    Pipe,   // |
    And,    // &&
    Or,     // ||
    Semi,   // ;
    Amp,    // &
    LParen, // (
    RParen, // )
    LBrace, // {
    RBrace, // }
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
    DoubleSemi,    // ;;
    SemiAmp,       // ;&
    DoubleSemiAmp, // ;;&
    Function,
    Redirect(Redirection),
    Eof,
}

pub(super) struct Lexer {
    pub(super) input: Vec<char>,
    pub(super) pos: usize,
    pub(super) byte_pos: usize,
    pub(super) diagnostics: Vec<ParseDiagnostic>,
}

impl Lexer {
    pub(super) fn new(input: &str) -> Self {
        Lexer {
            input: input.chars().collect(),
            pos: 0,
            byte_pos: 0,
            diagnostics: Vec::new(),
        }
    }

    pub(super) fn take_diagnostics(&mut self) -> Vec<ParseDiagnostic> {
        std::mem::take(&mut self.diagnostics)
    }

    /// Test-only thin wrapper exposing the lexer's `$()` body matcher, used
    /// to compare against the engine's `find_balanced_paren`.
    pub(super) fn debug_read_balanced_parens(&mut self) -> (String, bool) {
        self.read_balanced_parens_checked()
    }

    pub(super) fn peek(&self) -> Option<char> {
        self.input.get(self.pos).copied()
    }

    pub(super) fn advance(&mut self) -> Option<char> {
        let ch = self.input.get(self.pos).copied();
        if let Some(c) = ch {
            self.pos += 1;
            self.byte_pos += c.len_utf8();
        }
        ch
    }

    pub(super) fn peek_at(&self, offset: usize) -> Option<char> {
        self.input.get(self.pos + offset).copied()
    }

    pub(super) fn save_state(&self) -> (usize, usize) {
        (self.pos, self.byte_pos)
    }

    pub(super) fn restore_state(&mut self, state: (usize, usize)) {
        self.pos = state.0;
        self.byte_pos = state.1;
    }

    pub(super) fn skip_whitespace(&mut self) {
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

    #[cfg(test)]
    pub(super) fn tokenize(&mut self) -> Vec<Token> {
        self.tokenize_with_offsets()
            .into_iter()
            .map(|(tok, _)| tok)
            .collect()
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
            let body_start = self.byte_pos;
            let (cmd, found) = self.read_balanced_parens_checked();
            let body_end = if found {
                self.byte_pos - 1
            } else {
                self.byte_pos
            };
            let word = Word {
                parts: vec![WordPart::ProcessSubstitution {
                    direction,
                    command: cmd,
                    span: crate::diagnostic::Span {
                        start: body_start,
                        end: body_end,
                    },
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
        assert!(
            !parts.is_empty(),
            "unreachable: read_word_or_keyword called at metachar"
        );

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
    // `#` is intentionally absent: POSIX 2.3 only treats `#` as a
    // comment-start at a token boundary, and `skip_whitespace` already
    // consumes `# … \n` between tokens. Inside a word, `#` is literal
    // (e.g. `a#cat`, `colour#ff00ff`).
    matches!(
        ch,
        ' ' | '\t' | '\n' | '|' | '&' | ';' | '(' | ')' | '<' | '>'
    )
}

fn is_word_char(ch: char) -> bool {
    !is_metachar(ch) && ch != '\'' && ch != '"' && ch != '`' && ch != '$' && ch != '\\'
}

pub(super) fn is_redirect_start(ch: char) -> bool {
    ch == '<' || ch == '>'
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::{ParseDiagnosticKind, Severity};

    #[test]
    fn lexer_empty_word_from_empty_parts() {
        let mut lex = Lexer::new("");
        let word = lex.read_word_value();
        assert_eq!(word.parts.len(), 1);
        assert!(matches!(&word.parts[0], WordPart::Literal(s) if s.is_empty()));
    }

    #[test]
    fn lexer_bracket_appends_to_literal() {
        let mut lex = Lexer::new("a[");
        let word = lex.read_word_value();
        assert_eq!(word.parts.len(), 1);
        assert!(matches!(&word.parts[0], WordPart::Literal(s) if s == "a["));
    }

    fn tokenize_and_get_diagnostics(input: &str) -> Vec<crate::diagnostic::ParseDiagnostic> {
        let mut lex = Lexer::new(input);
        let _ = lex.tokenize();
        lex.take_diagnostics()
    }

    #[test]
    fn unterminated_single_quote() {
        let diags = tokenize_and_get_diagnostics("echo 'hello");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].kind, ParseDiagnosticKind::UnterminatedSingleQuote);
        assert_eq!(diags[0].severity, Severity::Error);
        assert_eq!(diags[0].span.start, 5); // byte offset of '
        assert_eq!(diags[0].span.end, 11); // EOF
    }

    #[test]
    fn unterminated_double_quote() {
        let diags = tokenize_and_get_diagnostics("echo \"hello");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].kind, ParseDiagnosticKind::UnterminatedDoubleQuote);
        assert_eq!(diags[0].severity, Severity::Error);
        assert_eq!(diags[0].span.start, 5);
        assert_eq!(diags[0].span.end, 11);
    }

    #[test]
    fn unterminated_backtick() {
        let diags = tokenize_and_get_diagnostics("echo `hello");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].kind, ParseDiagnosticKind::UnterminatedBacktick);
        assert_eq!(diags[0].severity, Severity::Error);
        assert_eq!(diags[0].span.start, 5);
        assert_eq!(diags[0].span.end, 11);
    }

    #[test]
    fn unterminated_command_substitution() {
        let diags = tokenize_and_get_diagnostics("echo $(rm -rf /");
        assert_eq!(diags.len(), 1);
        assert_eq!(
            diags[0].kind,
            ParseDiagnosticKind::UnterminatedCommandSubstitution
        );
        assert_eq!(diags[0].severity, Severity::Error);
        assert_eq!(diags[0].span.start, 5); // byte offset of $
    }

    #[test]
    fn unterminated_arithmetic() {
        let diags = tokenize_and_get_diagnostics("echo $((1+2");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].kind, ParseDiagnosticKind::UnterminatedArithmetic);
        assert_eq!(diags[0].severity, Severity::Error);
        assert_eq!(diags[0].span.start, 5);
    }

    #[test]
    fn unterminated_parameter_expansion() {
        let diags = tokenize_and_get_diagnostics("echo ${VAR");
        assert_eq!(diags.len(), 1);
        assert_eq!(
            diags[0].kind,
            ParseDiagnosticKind::UnterminatedParameterExpansion
        );
        assert_eq!(diags[0].severity, Severity::Error);
        assert_eq!(diags[0].span.start, 5);
    }

    #[test]
    fn well_formed_has_no_diagnostics() {
        let diags =
            tokenize_and_get_diagnostics("echo 'hello' \"world\" `date` $(ls) $((1+2)) ${VAR}");
        assert!(diags.is_empty(), "expected no diagnostics, got: {diags:?}");
    }

    #[test]
    fn double_quote_with_semicolon_shows_ambiguity() {
        // This is the security-critical case: echo "hello; rm -rf /
        let diags = tokenize_and_get_diagnostics("echo \"hello; rm -rf /");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].kind, ParseDiagnosticKind::UnterminatedDoubleQuote);
    }
}
