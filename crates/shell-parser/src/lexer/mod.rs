use super::ast::*;
use super::diagnostic::{ParseDiagnostic, ParseDiagnosticKind, Severity, Span};

/// Scan the byte region `input[start..end]` (an unquoted heredoc body)
/// for the expansions bash performs there that embed a command: command
/// substitution (`$(…)`, `` `…` ``) and arithmetic (`$((…))`). Returns
/// the found substitutions with inner-spans into `input`.
///
/// Bash quoting rules inside a heredoc body differ from word context:
/// quote characters are NOT special (a `'$(cmd)'` in the body still
/// runs), while a backslash escapes `$`, `` ` ``, and `\`. Process
/// substitution and globs are not performed in a body, so they are not
/// extracted. An unterminated substitution swallows the rest of the body
/// in real bash; it is not extracted — an Error-severity diagnostic is
/// emitted instead, and the parse-error floor owns the outcome.
fn scan_heredoc_substitutions(
    input: &str,
    start: usize,
    end: usize,
    diagnostics: &mut Vec<ParseDiagnostic>,
) -> Vec<WordPart> {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut i = start;
    while i < end {
        match bytes[i] {
            b'\\' => {
                // Backslash escapes the next character (in particular a
                // `$` or backtick sigil). Skipping one byte past a
                // multi-byte char is safe: continuation bytes match no
                // ASCII sigil, and slicing only happens at sigils.
                i += 2;
            }
            b'$' if i + 1 < end && bytes[i + 1] == b'(' => {
                if i + 2 < end && bytes[i + 2] == b'(' {
                    // Arithmetic $((…)) — find the closing `))`.
                    let body_start = i + 3;
                    match find_double_paren_close(bytes, body_start, end) {
                        Some(close) => {
                            out.push(WordPart::Arithmetic {
                                source: input[body_start..close].to_string(),
                                span: Span {
                                    start: body_start,
                                    end: close,
                                },
                            });
                            i = close + 2;
                        }
                        None => {
                            diagnostics.push(ParseDiagnostic {
                                span: Span { start: i, end },
                                kind: ParseDiagnosticKind::UnterminatedArithmetic,
                                severity: Severity::Error,
                            });
                            return out;
                        }
                    }
                } else {
                    // Command substitution $(…) — balanced parens, same
                    // fidelity as the word lexer's reader.
                    let body_start = i + 2;
                    match find_balanced_paren_close(bytes, body_start, end) {
                        Some(close) => {
                            out.push(WordPart::CommandSubstitution {
                                source: input[body_start..close].to_string(),
                                span: Span {
                                    start: body_start,
                                    end: close,
                                },
                            });
                            i = close + 1;
                        }
                        None => {
                            diagnostics.push(ParseDiagnostic {
                                span: Span { start: i, end },
                                kind: ParseDiagnosticKind::UnterminatedCommandSubstitution,
                                severity: Severity::Error,
                            });
                            return out;
                        }
                    }
                }
            }
            b'`' => {
                let body_start = i + 1;
                let mut j = body_start;
                let mut close = None;
                while j < end {
                    match bytes[j] {
                        b'\\' => j += 2,
                        b'`' => {
                            close = Some(j);
                            break;
                        }
                        _ => j += 1,
                    }
                }
                match close {
                    Some(close) => {
                        out.push(WordPart::Backtick {
                            source: input[body_start..close].to_string(),
                            span: Span {
                                start: body_start,
                                end: close,
                            },
                        });
                        i = close + 1;
                    }
                    None => {
                        diagnostics.push(ParseDiagnostic {
                            span: Span { start: i, end },
                            kind: ParseDiagnosticKind::UnterminatedBacktick,
                            severity: Severity::Error,
                        });
                        return out;
                    }
                }
            }
            _ => i += 1,
        }
    }
    out
}

/// Index of the `)` that closes a `$(`-opened region starting at `from`,
/// counting nested parens. `None` when the region ends first.
fn find_balanced_paren_close(bytes: &[u8], from: usize, end: usize) -> Option<usize> {
    let mut depth = 1usize;
    let mut i = from;
    while i < end {
        match bytes[i] {
            b'\\' => i += 1,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Index of the first `)` of the `))` that closes a `$((`-opened region
/// starting at `from`. `None` when the region ends first.
fn find_double_paren_close(bytes: &[u8], from: usize, end: usize) -> Option<usize> {
    let mut i = from;
    while i + 1 < end {
        if bytes[i] == b')' && bytes[i + 1] == b')' {
            return Some(i);
        }
        i += 1;
    }
    None
}

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
    While,
    Until,
    Do,
    Done,
    Case,
    Esac,
    // Note: `in` has no token. POSIX places it after an argument-position word
    // (`for NAME in …`, `case WORD in`), so a command-position flag cannot
    // recognise it; the lexer always emits it as a `Word` and `parse_for` /
    // `parse_case` consume the literal where the grammar expects it.
    DoubleSemi,    // ;;
    SemiAmp,       // ;&
    DoubleSemiAmp, // ;;&
    Function,
    Redirect(Redirection),
    Eof,
}

pub(super) struct Lexer {
    pub(super) input: Vec<char>,
    /// The original input text, kept for byte-addressed region scans
    /// (heredoc bodies) whose spans must index the source string.
    input_str: String,
    pub(super) pos: usize,
    pub(super) byte_pos: usize,
    pub(super) diagnostics: Vec<ParseDiagnostic>,
    /// Whether the next word is in command-word position. POSIX recognises
    /// reserved words only here; elsewhere a keyword spelling is a literal
    /// argument. True at start of input, after a command separator/operator,
    /// and after a list-introducing keyword. See `command_position_after`.
    at_command_position: bool,
    /// Set immediately after a `function` keyword: the word that follows is a
    /// function name, and the construct that follows *it* (typically `{`) is
    /// again in command position even though a name is not a separator.
    expect_function_name: bool,
}

impl Lexer {
    pub(super) fn new(input: &str) -> Self {
        Lexer {
            input: input.chars().collect(),
            input_str: input.to_string(),
            pos: 0,
            byte_pos: 0,
            diagnostics: Vec::new(),
            at_command_position: true,
            expect_function_name: false,
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
            let len_before = tokens.len();
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
            // Update command-word position for the next token. A line
            // continuation can push no token (`read_word_or_keyword` returns
            // `None`); in that case the flag is left unchanged.
            if tokens.len() > len_before {
                let (tok, _) = &tokens[tokens.len() - 1];
                self.at_command_position = self.command_position_after(tok);
            }
        }
        tokens
    }

    /// Given the token just emitted, decide whether the *next* word is in
    /// command-word position. Reserved words and separators/operators
    /// introduce a new command; an ordinary `Word` (an argument) does not,
    /// unless it is a leading assignment, which leaves the following command
    /// word eligible.
    fn command_position_after(&mut self, tok: &Token) -> bool {
        let was_command_position = self.at_command_position;
        let expecting_function_name = self.expect_function_name;
        self.expect_function_name = false;
        match tok {
            Token::Function => {
                self.expect_function_name = true;
                true
            }
            Token::Eof | Token::Redirect(_) => false,
            Token::Word(w) => {
                // The body of `function NAME { … }` follows the name directly,
                // so the word after the name is still command position.
                expecting_function_name || (was_command_position && is_assignment_word(w))
            }
            // Separators, operators, and all reserved-word tokens allow a
            // reserved word to follow.
            Token::Pipe
            | Token::And
            | Token::Or
            | Token::Semi
            | Token::Amp
            | Token::LParen
            | Token::RParen
            | Token::LBrace
            | Token::RBrace
            | Token::Newline
            | Token::If
            | Token::Then
            | Token::Elif
            | Token::Else
            | Token::Fi
            | Token::For
            | Token::While
            | Token::Until
            | Token::Do
            | Token::Done
            | Token::Case
            | Token::Esac
            | Token::DoubleSemi
            | Token::SemiAmp
            | Token::DoubleSemiAmp => true,
        }
    }

    fn try_read_redirect_or_process_sub(&mut self) -> Option<Token> {
        // Check for process substitution <(cmd) or >(cmd)
        if self.at_process_substitution() {
            let part = self.read_process_substitution();
            return Some(Token::Word(Word { parts: vec![part] }));
        }

        self.read_redirection()
    }

    /// True when the cursor is at the `<`/`>` sigil of a process
    /// substitution — i.e. `<(` or `>(` with the paren adjacent (no
    /// space). `< (` (a redirect of a subshell) is *not* a process
    /// substitution and returns false.
    fn at_process_substitution(&self) -> bool {
        matches!(self.peek(), Some('<') | Some('>')) && self.peek_at(1) == Some('(')
    }

    /// Read a `<( … )` / `>( … )` process substitution. The cursor must be
    /// at the sigil (see [`Self::at_process_substitution`]). Terminates at
    /// the matching `)` via a balanced-paren scan over the inner command, so
    /// lexing resumes cleanly at the token after `)`.
    fn read_process_substitution(&mut self) -> WordPart {
        let direction = if self.peek() == Some('<') {
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
        WordPart::ProcessSubstitution {
            direction,
            command: cmd,
            span: crate::diagnostic::Span {
                start: body_start,
                end: body_end,
            },
        }
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
                let (delim, quoted) = self.read_heredoc_delimiter();

                // Scan forward line-by-line to collect the heredoc body
                // Move past the current line (skip to the newline after the delimiter word)
                while let Some(ch) = self.peek() {
                    self.advance();
                    if ch == '\n' {
                        break;
                    }
                }

                // Byte region of the raw body in the original input — the
                // substitution scan needs spans that index the source, not
                // the tab-stripped copy.
                let body_start = self.byte_pos;
                let body_end;

                let mut body = String::new();
                loop {
                    if self.peek().is_none() {
                        body_end = self.byte_pos;
                        break; // EOF before delimiter — graceful degradation
                    }
                    let line_start = self.byte_pos;
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
                        body_end = line_start;
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

                // An unquoted body is live — bash performs parameter,
                // command, and arithmetic expansion in it — so extract the
                // embedded commands for evaluation. A quoted body is
                // inviolable and stays opaque.
                let substitutions = if quoted {
                    Vec::new()
                } else {
                    scan_heredoc_substitutions(
                        &self.input_str,
                        body_start,
                        body_end,
                        &mut self.diagnostics,
                    )
                };

                RedirectionTarget::Heredoc {
                    body,
                    quoted,
                    substitutions,
                }
            }
            // Input/Output/Append/Clobber and Herestring all take a word
            // target and share the process-substitution handling below.
            RedirectionKind::Input
            | RedirectionKind::Output
            | RedirectionKind::Append
            | RedirectionKind::Clobber
            | RedirectionKind::Herestring => {
                self.skip_whitespace();
                // A process-substitution target (`… < <(cmd)`): consume the
                // whole `<( … )` as the target so the inner command is
                // captured and lexing resumes after the matching `)`. Without
                // this, `read_word_value` stops at the leading `<`, the target
                // is empty, and the `<(cmd)` re-lexes as a stray word that
                // desyncs the enclosing compound.
                if self.at_process_substitution() {
                    let part = self.read_process_substitution();
                    return RedirectionTarget::File(Word { parts: vec![part] });
                }
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
    /// Read a heredoc delimiter, returning `(delimiter, quoted)`. Any
    /// quoting of the delimiter (`'EOF'`, `"EOF"`, `\EOF`) suppresses
    /// expansion in the body, so the flag is recorded rather than
    /// discarded.
    fn read_heredoc_delimiter(&mut self) -> (String, bool) {
        match self.peek() {
            Some('\'') => {
                self.advance();
                let s = self.read_until_char('\'');
                self.advance(); // skip closing quote
                (s, true)
            }
            Some('"') => {
                self.advance();
                let s = self.read_until_char('"');
                self.advance(); // skip closing quote
                (s, true)
            }
            Some('\\') => {
                self.advance(); // skip leading backslash
                (self.read_plain_word_text(), true)
            }
            _ => (self.read_plain_word_text(), false),
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
        // Empty parts only occurs when the entire "word" was an unquoted
        // `\<newline>` line continuation (POSIX 2.2.1). The cursor has
        // advanced past both bytes, so the outer tokenizer loop will make
        // progress; we simply emit no token for this position.
        if parts.is_empty() {
            return None;
        }

        // Classify reserved words only in command-word position (POSIX
        // 2.10.2). As an ordinary argument a keyword spelling is a literal
        // `Word`. `in` is never classified here — see the `Token` enum note
        // and `parse_for` / `parse_case`.
        if self.at_command_position
            && parts.len() == 1
            && let WordPart::Literal(ref s) = parts[0]
        {
            match s.as_str() {
                "if" => return Some(Token::If),
                "then" => return Some(Token::Then),
                "elif" => return Some(Token::Elif),
                "else" => return Some(Token::Else),
                "fi" => return Some(Token::Fi),
                "for" => return Some(Token::For),
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

/// Whether a word has the shape of a leading assignment (`NAME=value`). Used
/// to keep command-word position across assignment prefixes (`FOO=1 cmd`).
/// Mirrors the name validation in `parse::Parser::try_parse_assignment`.
fn is_assignment_word(w: &Word) -> bool {
    if let Some(WordPart::Literal(s)) = w.parts.first()
        && let Some(eq) = s.find('=')
    {
        let name = &s[..eq];
        return !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !name.chars().next().unwrap().is_ascii_digit();
    }
    false
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
