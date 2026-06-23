use super::ast::*;
use super::diagnostic::{ParseDiagnostic, ParseDiagnosticKind, Severity, Span};
use super::lexer::{Lexer, Token};

pub(super) struct Parser {
    input: String,
    tokens: Vec<(Token, usize)>,
    pos: usize,
    input_len: usize,
    pub(super) diagnostics: Vec<ParseDiagnostic>,
}

impl Parser {
    pub(super) fn new(input: &str) -> Self {
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize_with_offsets();
        let diagnostics = lexer.take_diagnostics();
        Parser {
            input: input.to_string(),
            tokens,
            pos: 0,
            input_len: input.len(),
            diagnostics,
        }
    }

    fn peek(&self) -> &Token {
        self.tokens
            .get(self.pos)
            .map(|(t, _)| t)
            .unwrap_or(&Token::Eof)
    }

    fn current_offset(&self) -> usize {
        self.tokens
            .get(self.pos)
            .map(|(_, off)| *off)
            .unwrap_or(self.input_len)
    }

    fn advance(&mut self) -> Token {
        let tok = self
            .tokens
            .get(self.pos)
            .map(|(t, _)| t.clone())
            .unwrap_or(Token::Eof);
        if self.pos < self.tokens.len() {
            self.pos += 1;
        }
        tok
    }

    fn at_eof(&self) -> bool {
        matches!(self.peek(), Token::Eof)
    }

    fn expect(&mut self, expected: &Token) -> bool {
        if self.peek() == expected {
            self.advance();
            true
        } else {
            false
        }
    }

    fn skip_newlines(&mut self) {
        while matches!(self.peek(), Token::Newline) {
            self.advance();
        }
    }

    /// Whether the current token is a literal `Word` spelling exactly `lit`.
    /// Used to recognise `in` in `for`/`case`, where the lexer (which gates
    /// keywords on command-word position) emits it as an ordinary `Word`.
    fn peek_word_is(&self, lit: &str) -> bool {
        matches!(self.peek(), Token::Word(w)
            if w.parts.len() == 1
                && matches!(&w.parts[0], WordPart::Literal(s) if s == lit))
    }

    pub(super) fn parse_complete(&mut self) -> Command {
        self.skip_newlines();
        if self.at_eof() {
            return Command::Simple(SimpleCommand {
                assignments: vec![],
                words: vec![],
                redirections: vec![],
                span: Span { start: 0, end: 0 },
            });
        }
        let command = self.parse_list();
        // No silent token loss: well-formed input is consumed up to EOF. A
        // leftover token (e.g. a stray `done` with no opening `do`, or an
        // unbalanced `)`) is one the grammar could not place. Surface an
        // Error-severity diagnostic so the decision floors to ask rather than
        // discarding the token. Backstops any position the command-word rule
        // does not cover.
        if !self.at_eof() {
            self.diagnostics.push(ParseDiagnostic {
                span: Span {
                    start: self.current_offset(),
                    end: self.current_offset(),
                },
                kind: ParseDiagnosticKind::UnexpectedToken,
                severity: Severity::Error,
            });
        }
        command
    }

    fn parse_list(&mut self) -> Command {
        let mut commands = Vec::new();
        let first = self.parse_and_or();
        commands.push(first);

        loop {
            match self.peek().clone() {
                Token::Semi => {
                    self.advance();
                    self.skip_newlines();
                    if self.is_list_terminator() {
                        break;
                    }
                    let next = self.parse_and_or();
                    commands.push(next);
                }
                Token::Amp => {
                    self.advance();
                    let last = commands.pop().unwrap();
                    commands.push(Command::Background(Box::new(last)));
                    self.skip_newlines();
                    if self.is_list_terminator() {
                        break;
                    }
                    let next = self.parse_and_or();
                    commands.push(next);
                }
                Token::Newline => {
                    self.advance();
                    self.skip_newlines();
                    if self.is_list_terminator() {
                        break;
                    }
                    let next = self.parse_and_or();
                    commands.push(next);
                }
                _ => break,
            }
        }

        if commands.len() == 1 {
            commands.pop().unwrap()
        } else {
            Command::Sequence(commands)
        }
    }

    fn is_list_terminator(&self) -> bool {
        matches!(
            self.peek(),
            Token::Eof
                | Token::RParen
                | Token::RBrace
                | Token::Fi
                | Token::Done
                | Token::Esac
                | Token::Else
                | Token::Elif
                | Token::Then
                | Token::Do
                | Token::DoubleSemi
                | Token::SemiAmp
                | Token::DoubleSemiAmp
        )
    }

    fn parse_and_or(&mut self) -> Command {
        let mut left = self.parse_pipeline();

        loop {
            match self.peek().clone() {
                Token::And => {
                    self.advance();
                    self.skip_newlines();
                    let right = self.parse_pipeline();
                    left = Command::And(Box::new(left), Box::new(right));
                }
                Token::Or => {
                    self.advance();
                    self.skip_newlines();
                    let right = self.parse_pipeline();
                    left = Command::Or(Box::new(left), Box::new(right));
                }
                _ => break,
            }
        }

        left
    }

    fn parse_pipeline(&mut self) -> Command {
        // POSIX grammar: `pipeline ::= ["!"] pipe_sequence`. A leading bare
        // `!` negates the pipeline's exit status — it is a reserved word, not
        // a program. `may-i` decides on command structure, not exit status,
        // so negation is authorisation-transparent: consume the `!` and parse
        // the inner pipeline unchanged (no `Negate` AST node). Only the exact
        // single-char `!` at pipeline-start is negation; `!foo` stays a
        // command word, and `!` as an argument is untouched because this
        // function is only entered at pipeline-start position. A second `!`
        // (`! ! cmd`) falls through to the command word, as documented.
        if self.peek_word_is("!") {
            self.advance();
        }

        let mut commands = Vec::new();
        commands.push(self.parse_command());

        while matches!(self.peek(), Token::Pipe) {
            self.advance();
            self.skip_newlines();
            commands.push(self.parse_command());
        }

        if commands.len() == 1 {
            commands.pop().unwrap()
        } else {
            Command::Pipeline(commands)
        }
    }

    fn parse_command(&mut self) -> Command {
        let cmd = match self.peek().clone() {
            Token::If => self.parse_if(),
            Token::For => self.parse_for(),
            Token::While => self.parse_while(),
            Token::Until => self.parse_until(),
            Token::Case => self.parse_case(),
            Token::Function => self.parse_function_def(),
            Token::LParen => self.parse_subshell(),
            Token::LBrace => self.parse_brace_group(),
            _ => return self.parse_simple_command(),
        };
        self.maybe_wrap_redirections(cmd)
    }

    fn maybe_wrap_redirections(&mut self, cmd: Command) -> Command {
        let mut redirections = Vec::new();
        while let Token::Redirect(ref r) = self.peek().clone() {
            redirections.push(r.clone());
            self.advance();
        }
        if redirections.is_empty() {
            cmd
        } else {
            Command::Redirected {
                command: Box::new(cmd),
                redirections,
            }
        }
    }

    fn parse_simple_command(&mut self) -> Command {
        let mut assignments = Vec::new();
        let mut words = Vec::new();
        let mut redirections = Vec::new();
        let span_start = self.current_offset();

        loop {
            match self.peek().clone() {
                Token::Word(ref w) => {
                    // Check for assignment (VAR=value) before any command words
                    if words.is_empty()
                        && let Some(assignment) = self.try_parse_assignment()
                    {
                        assignments.push(assignment);
                        continue;
                    }
                    // A declaration builtin (`declare`/`typeset`/`local`/
                    // `export`/`readonly`) takes `name=(…)` array arguments. The
                    // kind comes from a `-A` flag (associative) vs the default
                    // `-a`/indexed. Capture these as assignments so the kind is
                    // recorded and nothing truncates; the builtin name word
                    // stays in `words`.
                    if let Some(kind) = declaration_array_kind(&words)
                        && let Some(assignment) = self.try_parse_named_array_literal(kind)
                    {
                        assignments.push(assignment);
                        continue;
                    }
                    let word = w.clone();
                    self.advance();
                    words.push(word);

                    // Check for POSIX function definition: name() { body }
                    if words.len() == 1
                        && assignments.is_empty()
                        && matches!(self.peek(), Token::LParen)
                    {
                        // Peek further for RParen
                        if self
                            .tokens
                            .get(self.pos + 1)
                            .is_some_and(|(t, _)| matches!(t, Token::RParen))
                        {
                            let name = words.pop().unwrap().to_str();
                            self.advance(); // skip LParen
                            self.advance(); // skip RParen
                            self.skip_newlines();
                            let body = self.parse_command();
                            return Command::FunctionDef {
                                name,
                                body: Box::new(body),
                            };
                        }
                    }
                }
                Token::Redirect(ref r) => {
                    let redir = r.clone();
                    self.advance();
                    redirections.push(redir);
                }
                _ => break,
            }
        }

        // If only assignments and no words, return as assignment command
        if !assignments.is_empty() && words.is_empty() && assignments.len() == 1 {
            return Command::Assignment(assignments.pop().unwrap());
        }

        if assignments.is_empty() && words.is_empty() && redirections.is_empty() {
            self.diagnostics.push(ParseDiagnostic {
                span: Span {
                    start: self.current_offset(),
                    end: self.current_offset(),
                },
                kind: ParseDiagnosticKind::EmptyCommand,
                severity: Severity::Warning,
            });
        }

        let span_end = self.trimmed_end_offset(span_start);
        Command::Simple(SimpleCommand {
            assignments,
            words,
            redirections,
            span: Span {
                start: span_start,
                end: span_end,
            },
        })
    }

    /// Compute the byte offset that ends a simple command starting at
    /// `span_start`, trimmed of trailing whitespace before the next operator
    /// or end-of-input. Mirrors the trimming done by `segment::segment` so
    /// segment ranges align across the two passes.
    fn trimmed_end_offset(&self, span_start: usize) -> usize {
        let stop = self.current_offset();
        let between = &self.input[span_start..stop];
        span_start + between.trim_end().len()
    }

    fn try_parse_assignment(&mut self) -> Option<Assignment> {
        if let Token::Word(ref w) = self.peek().clone()
            && !w.parts.is_empty()
            && let WordPart::Literal(ref s) = w.parts[0]
            && let Some(eq_pos) = s.find('=')
        {
            // The lexical name is everything before the first `=`. It may carry
            // an append `+` (`arr+=…`) and/or an indexed-element subscript
            // (`arr[5]=…`); strip both to recover the bare variable name and
            // validate it. `arr[5]=v` is a scalar assignment to one element —
            // not an array literal — but we keep the bare name so const_env and
            // taint see a normal assignment rather than dropping the token.
            let lexical = &s[..eq_pos];
            let lexical = lexical.strip_suffix('+').unwrap_or(lexical);
            let bare = match lexical.find('[') {
                Some(open) => &lexical[..open],
                None => lexical,
            };
            if !bare.is_empty()
                && bare.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && bare.chars().next().is_some_and(|c| !c.is_ascii_digit())
            {
                // `name=(…)` / `name+=(…)`: the RHS is an array literal when the
                // value text is empty and a `(` follows immediately (no space).
                // bash treats an adjacent `(` after `=` as an array literal; a
                // space (`x= (sub)`) is an env-prefix + subshell, which the
                // byte-offset adjacency check below preserves.
                let value_text = &s[eq_pos + 1..];
                if value_text.is_empty()
                    && w.parts.len() == 1
                    && matches!(self.peek(), Token::Word(_))
                    && let Some(array) = self.try_parse_array_literal(s)
                {
                    return Some(Assignment {
                        name: bare.to_string(),
                        value: array,
                    });
                }

                let mut value_parts = Vec::new();
                if !value_text.is_empty() {
                    value_parts.push(WordPart::Literal(value_text.to_string()));
                }
                // Include additional word parts
                for part in &w.parts[1..] {
                    value_parts.push(part.clone());
                }
                let value = if value_parts.is_empty() {
                    Word::literal("")
                } else {
                    Word { parts: value_parts }
                };
                self.advance();
                return Some(Assignment {
                    name: bare.to_string(),
                    value: AssignmentValue::Scalar(value),
                });
            }
        }
        None
    }

    /// Parse an array literal `(word…)` whose opening `(` immediately follows
    /// the assignment word `assign_word` (the `name=` / `name+=` prefix). The
    /// cursor is on the `name=` Word token; on success it is advanced past the
    /// closing `)`. Returns `None` (leaving the cursor unmoved) when the `(`
    /// is not adjacent (a space — `x= (sub)`), so the caller falls back to the
    /// scalar/env-prefix interpretation. An unterminated `(` consumes to EOF
    /// and emits no extra diagnostic here — the trailing `RParen` absence is
    /// caught by `parse_complete`'s leftover-token check, never silently
    /// dropping tokens.
    fn try_parse_array_literal(&mut self, assign_word: &str) -> Option<AssignmentValue> {
        let assign_offset = self.current_offset();
        // The next token must be a `(` adjacent to the end of `name=`.
        let (lparen_tok, lparen_off) = self.tokens.get(self.pos + 1)?.clone();
        if !matches!(lparen_tok, Token::LParen) {
            return None;
        }
        if lparen_off != assign_offset + assign_word.len() {
            // A space separates `name=` from `(`: not an array literal.
            return None;
        }

        self.advance(); // consume `name=` word
        self.advance(); // consume `(`

        let mut elements = Vec::new();
        loop {
            self.skip_newlines();
            match self.peek().clone() {
                Token::RParen => {
                    self.advance();
                    break;
                }
                Token::Eof => {
                    // Unterminated `(`: stop here. `parse_complete` does not
                    // fire (we consumed to EOF), but no tokens are dropped —
                    // the elements seen so far are preserved.
                    break;
                }
                Token::Word(w) => {
                    self.advance();
                    elements.push(w);
                }
                // Any other token inside `(…)` (operators, redirects) is not a
                // plain element word. Consume it without dropping it from the
                // stream so nothing is silently lost; it contributes no
                // element. This keeps malformed arrays panic-free and
                // non-truncating.
                _ => {
                    self.advance();
                }
            }
        }

        Some(AssignmentValue::Array {
            array_kind: ArrayKind::Indexed,
            elements,
        })
    }

    /// Parse a declaration-builtin array argument `name=(…)` (with the given
    /// `kind` from the builtin's flags) in argument position. The cursor is on
    /// the `name=` Word token. Returns `None` (cursor unmoved) when the word is
    /// not a `name=` shape or the `(` is not adjacent — the caller then treats
    /// it as an ordinary argument word. A `name=scalar` (no array) also returns
    /// `None`: only the array-literal form is captured here, since the kind is
    /// meaningful only for arrays.
    fn try_parse_named_array_literal(&mut self, kind: ArrayKind) -> Option<Assignment> {
        let Token::Word(w) = self.peek().clone() else {
            return None;
        };
        if w.parts.len() != 1 {
            return None;
        }
        let WordPart::Literal(ref s) = w.parts[0] else {
            return None;
        };
        let eq_pos = s.find('=')?;
        if eq_pos + 1 != s.len() {
            return None; // `name=value` scalar, not an array literal
        }
        let lexical = &s[..eq_pos];
        let lexical = lexical.strip_suffix('+').unwrap_or(lexical);
        let bare = match lexical.find('[') {
            Some(open) => &lexical[..open],
            None => lexical,
        };
        if bare.is_empty()
            || !bare.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || bare.chars().next().is_some_and(|c| c.is_ascii_digit())
        {
            return None;
        }
        match self.try_parse_array_literal(s)? {
            AssignmentValue::Array { elements, .. } => Some(Assignment {
                name: bare.to_string(),
                value: AssignmentValue::Array {
                    array_kind: kind,
                    elements,
                },
            }),
            AssignmentValue::Scalar(_) => None,
        }
    }

    fn parse_if(&mut self) -> Command {
        self.advance(); // skip 'if'
        self.skip_newlines();
        let condition = self.parse_list();
        self.skip_newlines();
        self.expect(&Token::Then);
        self.skip_newlines();
        let then_branch = self.parse_list();

        let mut elif_branches = Vec::new();
        let mut else_branch = None;

        loop {
            self.skip_newlines();
            match self.peek().clone() {
                Token::Elif => {
                    self.advance();
                    self.skip_newlines();
                    let cond = self.parse_list();
                    self.skip_newlines();
                    self.expect(&Token::Then);
                    self.skip_newlines();
                    let body = self.parse_list();
                    elif_branches.push((cond, body));
                }
                Token::Else => {
                    self.advance();
                    self.skip_newlines();
                    let body = self.parse_list();
                    else_branch = Some(Box::new(body));
                    break;
                }
                _ => break,
            }
        }

        self.skip_newlines();
        if !self.expect(&Token::Fi) {
            self.diagnostics.push(ParseDiagnostic {
                span: Span {
                    start: self.current_offset(),
                    end: self.current_offset(),
                },
                kind: ParseDiagnosticKind::MissingClosingKeyword { expected: "fi" },
                severity: Severity::Warning,
            });
        }

        Command::If {
            condition: Box::new(condition),
            then_branch: Box::new(then_branch),
            elif_branches,
            else_branch,
        }
    }

    fn parse_for(&mut self) -> Command {
        self.advance(); // skip 'for'
        self.skip_newlines();

        let var = if let Token::Word(w) = self.advance() {
            w.to_str()
        } else {
            String::new()
        };

        self.skip_newlines();
        let mut words = Vec::new();

        if self.peek_word_is("in") {
            self.advance(); // skip 'in'
            while let Token::Word(w) = self.peek().clone() {
                words.push(w.clone());
                self.advance();
            }
        }

        // Skip separator (;  or newline)
        if matches!(self.peek(), Token::Semi | Token::Newline) {
            self.advance();
        }
        self.skip_newlines();
        self.expect(&Token::Do);
        self.skip_newlines();
        let body = self.parse_list();
        self.skip_newlines();
        if !self.expect(&Token::Done) {
            self.diagnostics.push(ParseDiagnostic {
                span: Span {
                    start: self.current_offset(),
                    end: self.current_offset(),
                },
                kind: ParseDiagnosticKind::MissingClosingKeyword { expected: "done" },
                severity: Severity::Warning,
            });
        }

        Command::For {
            var,
            words,
            body: Box::new(body),
        }
    }

    fn parse_while(&mut self) -> Command {
        self.advance(); // skip 'while'
        self.skip_newlines();
        let condition = self.parse_list();
        self.skip_newlines();
        self.expect(&Token::Do);
        self.skip_newlines();
        let body = self.parse_list();
        self.skip_newlines();
        if !self.expect(&Token::Done) {
            self.diagnostics.push(ParseDiagnostic {
                span: Span {
                    start: self.current_offset(),
                    end: self.current_offset(),
                },
                kind: ParseDiagnosticKind::MissingClosingKeyword { expected: "done" },
                severity: Severity::Warning,
            });
        }

        Command::Loop {
            kind: LoopKind::While,
            condition: Box::new(condition),
            body: Box::new(body),
        }
    }

    fn parse_until(&mut self) -> Command {
        self.advance(); // skip 'until'
        self.skip_newlines();
        let condition = self.parse_list();
        self.skip_newlines();
        self.expect(&Token::Do);
        self.skip_newlines();
        let body = self.parse_list();
        self.skip_newlines();
        if !self.expect(&Token::Done) {
            self.diagnostics.push(ParseDiagnostic {
                span: Span {
                    start: self.current_offset(),
                    end: self.current_offset(),
                },
                kind: ParseDiagnosticKind::MissingClosingKeyword { expected: "done" },
                severity: Severity::Warning,
            });
        }

        Command::Loop {
            kind: LoopKind::Until,
            condition: Box::new(condition),
            body: Box::new(body),
        }
    }

    fn parse_case(&mut self) -> Command {
        self.advance(); // skip 'case'
        self.skip_newlines();

        let word = if let Token::Word(w) = self.advance() {
            w
        } else {
            Word::literal("")
        };

        self.skip_newlines();
        if self.peek_word_is("in") {
            self.advance(); // skip 'in'
        }
        self.skip_newlines();

        let mut arms = Vec::new();

        while !matches!(self.peek(), Token::Esac | Token::Eof) {
            // Skip optional (
            if matches!(self.peek(), Token::LParen) {
                self.advance();
            }

            // Read patterns separated by |
            let mut patterns = Vec::new();
            while let Token::Word(w) = self.peek().clone() {
                patterns.push(w.clone());
                self.advance();
                if matches!(self.peek(), Token::Pipe) {
                    self.advance();
                } else {
                    break;
                }
            }

            // Expect )
            self.expect(&Token::RParen);
            self.skip_newlines();

            // Parse body until ;; or ;& or ;;& or esac
            let body = if matches!(
                self.peek(),
                Token::DoubleSemi | Token::SemiAmp | Token::DoubleSemiAmp | Token::Esac
            ) {
                None
            } else {
                Some(self.parse_list())
            };

            let terminator = match self.peek().clone() {
                Token::DoubleSemi => {
                    self.advance();
                    CaseTerminator::Break
                }
                Token::SemiAmp => {
                    self.advance();
                    CaseTerminator::Fallthrough
                }
                Token::DoubleSemiAmp => {
                    self.advance();
                    CaseTerminator::Continue
                }
                _ => CaseTerminator::Break,
            };

            self.skip_newlines();
            arms.push(CaseArm {
                patterns,
                body,
                terminator,
            });
        }

        if !self.expect(&Token::Esac) {
            self.diagnostics.push(ParseDiagnostic {
                span: Span {
                    start: self.current_offset(),
                    end: self.current_offset(),
                },
                kind: ParseDiagnosticKind::MissingClosingKeyword { expected: "esac" },
                severity: Severity::Warning,
            });
        }

        Command::Case { word, arms }
    }

    fn parse_function_def(&mut self) -> Command {
        self.advance(); // skip 'function'
        self.skip_newlines();

        let name = if let Token::Word(w) = self.advance() {
            w.to_str()
        } else {
            String::new()
        };

        // Optional ()
        if matches!(self.peek(), Token::LParen) {
            self.advance();
            self.expect(&Token::RParen);
        }

        self.skip_newlines();
        let body = self.parse_command();

        Command::FunctionDef {
            name,
            body: Box::new(body),
        }
    }

    fn parse_subshell(&mut self) -> Command {
        self.advance(); // skip (
        self.skip_newlines();
        let body = self.parse_list();
        self.skip_newlines();
        if !self.expect(&Token::RParen) {
            self.diagnostics.push(ParseDiagnostic {
                span: Span {
                    start: self.current_offset(),
                    end: self.current_offset(),
                },
                kind: ParseDiagnosticKind::MissingClosingKeyword { expected: ")" },
                severity: Severity::Warning,
            });
        }

        Command::Subshell(Box::new(body))
    }

    fn parse_brace_group(&mut self) -> Command {
        self.advance(); // skip {
        self.skip_newlines();
        let body = self.parse_list();
        self.skip_newlines();
        if !self.expect(&Token::RBrace) {
            self.diagnostics.push(ParseDiagnostic {
                span: Span {
                    start: self.current_offset(),
                    end: self.current_offset(),
                },
                kind: ParseDiagnosticKind::MissingClosingKeyword { expected: "}" },
                severity: Severity::Warning,
            });
        }

        Command::BraceGroup(Box::new(body))
    }
}

/// If `words` names a declaration builtin (`declare`/`typeset`/`local`/
/// `export`/`readonly`), return the array kind its flags so far imply: a `-A`
/// flag anywhere in the flag words makes a following `name=(…)` associative;
/// otherwise it is indexed (`-a` or no flag). Returns `None` when the first
/// word is not a declaration builtin, so a plain command's `name=(…)` argument
/// is left as an ordinary word.
fn declaration_array_kind(words: &[Word]) -> Option<ArrayKind> {
    let head = words.first()?;
    if head.parts.len() != 1 {
        return None;
    }
    let WordPart::Literal(name) = &head.parts[0] else {
        return None;
    };
    if !matches!(
        name.as_str(),
        "declare" | "typeset" | "local" | "export" | "readonly"
    ) {
        return None;
    }
    // Scan the flag words for `-A` (associative). A combined flag like `-Ax`
    // or `-gA` still selects associative, so look for the letter inside any
    // single-dash flag word.
    let associative = words[1..].iter().any(|w| {
        matches!(&w.parts[..], [WordPart::Literal(s)]
            if s.starts_with('-') && !s.starts_with("--") && s.contains('A'))
    });
    Some(if associative {
        ArrayKind::Associative
    } else {
        ArrayKind::Indexed
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::{ParseDiagnosticKind, Severity};

    fn parse_diagnostics(input: &str) -> Vec<ParseDiagnostic> {
        let mut parser = Parser::new(input);
        let _ = parser.parse_complete();
        parser.diagnostics
    }

    #[test]
    fn missing_fi() {
        let diags = parse_diagnostics("if true; then echo hello");
        assert!(
            diags.iter().any(|d| d.kind
                == ParseDiagnosticKind::MissingClosingKeyword { expected: "fi" }
                && d.severity == Severity::Warning),
            "expected MissingClosingKeyword(fi), got: {diags:?}"
        );
    }

    #[test]
    fn missing_done_for() {
        let diags = parse_diagnostics("for x in a b; do echo $x");
        assert!(
            diags.iter().any(|d| d.kind
                == ParseDiagnosticKind::MissingClosingKeyword { expected: "done" }
                && d.severity == Severity::Warning),
            "expected MissingClosingKeyword(done), got: {diags:?}"
        );
    }

    #[test]
    fn missing_done_while() {
        let diags = parse_diagnostics("while true; do echo hello");
        assert!(
            diags
                .iter()
                .any(|d| d.kind == ParseDiagnosticKind::MissingClosingKeyword { expected: "done" }),
            "expected MissingClosingKeyword(done), got: {diags:?}"
        );
    }

    #[test]
    fn missing_done_until() {
        let diags = parse_diagnostics("until false; do echo hello");
        assert!(
            diags
                .iter()
                .any(|d| d.kind == ParseDiagnosticKind::MissingClosingKeyword { expected: "done" }),
            "expected MissingClosingKeyword(done), got: {diags:?}"
        );
    }

    #[test]
    fn missing_esac() {
        let diags = parse_diagnostics("case $x in a) echo hi;;");
        assert!(
            diags
                .iter()
                .any(|d| d.kind == ParseDiagnosticKind::MissingClosingKeyword { expected: "esac" }),
            "expected MissingClosingKeyword(esac), got: {diags:?}"
        );
    }

    #[test]
    fn well_formed_if_no_diagnostic() {
        let diags = parse_diagnostics("if true; then echo hello; fi");
        assert!(
            !diags
                .iter()
                .any(|d| matches!(&d.kind, ParseDiagnosticKind::MissingClosingKeyword { .. })),
            "unexpected diagnostics: {diags:?}"
        );
    }

    #[test]
    fn well_formed_for_no_diagnostic() {
        let diags = parse_diagnostics("for x in a b; do echo $x; done");
        assert!(
            !diags
                .iter()
                .any(|d| matches!(&d.kind, ParseDiagnosticKind::MissingClosingKeyword { .. })),
            "unexpected diagnostics: {diags:?}"
        );
    }

    #[test]
    fn well_formed_case_no_diagnostic() {
        let diags = parse_diagnostics("case $x in a) echo hi;; esac");
        assert!(
            !diags
                .iter()
                .any(|d| matches!(&d.kind, ParseDiagnosticKind::MissingClosingKeyword { .. })),
            "unexpected diagnostics: {diags:?}"
        );
    }

    #[test]
    fn simple_command_no_empty_diagnostic() {
        let diags = parse_diagnostics("echo hello");
        assert!(
            !diags
                .iter()
                .any(|d| d.kind == ParseDiagnosticKind::EmptyCommand),
            "unexpected EmptyCommand: {diags:?}"
        );
    }

    fn first_simple(cmd: &crate::ast::Command) -> &crate::ast::SimpleCommand {
        fn walk(cmd: &crate::ast::Command) -> Option<&crate::ast::SimpleCommand> {
            if let crate::ast::Command::Simple(sc) = cmd {
                return Some(sc);
            }
            for child in cmd.children() {
                if let Some(sc) = walk(child) {
                    return Some(sc);
                }
            }
            None
        }
        walk(cmd).expect("expected at least one simple command")
    }

    fn parse_complete(input: &str) -> crate::ast::Command {
        let mut p = Parser::new(input);
        p.parse_complete()
    }

    #[test]
    fn simple_command_span_single() {
        let cmd = parse_complete("echo hi");
        let sc = first_simple(&cmd);
        assert_eq!(sc.span, Span { start: 0, end: 7 });
    }

    #[test]
    fn simple_command_span_strips_trailing_whitespace() {
        let cmd = parse_complete("echo a   ");
        let sc = first_simple(&cmd);
        assert_eq!(sc.span, Span { start: 0, end: 6 });
    }

    #[test]
    fn simple_command_span_split_by_and() {
        // "echo a && rm -rf /" — two simple commands; spans for "echo a" and
        // "rm -rf /" — exclude operator and surrounding whitespace.
        let cmd = parse_complete("echo a && rm -rf /");
        let mut spans = Vec::new();
        fn collect(c: &crate::ast::Command, out: &mut Vec<Span>) {
            if let crate::ast::Command::Simple(sc) = c {
                out.push(sc.span);
            }
            for child in c.children() {
                collect(child, out);
            }
        }
        collect(&cmd, &mut spans);
        assert_eq!(
            spans,
            vec![Span { start: 0, end: 6 }, Span { start: 10, end: 18 }]
        );
    }

    // ── Command-position reserved-word recognition ──────────────────────

    fn simple_words(input: &str) -> Vec<String> {
        let cmd = parse_complete(input);
        first_simple(&cmd)
            .words
            .iter()
            .map(|w| w.to_str())
            .collect()
    }

    fn has_error_diagnostic(input: &str) -> bool {
        parse_diagnostics(input)
            .iter()
            .any(|d| d.severity == Severity::Error)
    }

    #[test]
    fn keyword_spelling_as_trailing_arg_is_literal() {
        assert_eq!(
            simple_words("find . -name done"),
            ["find", ".", "-name", "done"]
        );
        assert!(parse_diagnostics("find . -name done").is_empty());
    }

    #[test]
    fn multiple_keyword_spelled_arguments_are_preserved() {
        assert_eq!(
            simple_words("echo do done fi"),
            ["echo", "do", "done", "fi"]
        );
        assert!(parse_diagnostics("echo do done fi").is_empty());
    }

    #[test]
    fn keyword_spelling_as_flag_value_is_literal() {
        assert_eq!(
            simple_words("kubectl get pods in default"),
            ["kubectl", "get", "pods", "in", "default"]
        );
        assert!(parse_diagnostics("kubectl get pods in default").is_empty());
    }

    #[test]
    fn keyword_spelling_mid_args_is_literal() {
        assert_eq!(simple_words("grep -r fi src"), ["grep", "-r", "fi", "src"]);
        assert_eq!(simple_words("ls then"), ["ls", "then"]);
    }

    #[test]
    fn decision_sees_full_command_for_rm_rf_done() {
        assert_eq!(simple_words("rm -rf done"), ["rm", "-rf", "done"]);
        assert!(parse_diagnostics("rm -rf done").is_empty());
    }

    #[test]
    fn assignment_prefix_keeps_command_word_eligible() {
        // FOO=1 is an assignment prefix; do_thing is still the command word.
        let cmd = parse_complete("FOO=1 do_thing");
        let sc = first_simple(&cmd);
        assert_eq!(sc.assignments.len(), 1);
        assert_eq!(
            sc.words.iter().map(|w| w.to_str()).collect::<Vec<_>>(),
            ["do_thing"]
        );
    }

    // ── Compound commands must parse identically ────────────────────────

    #[test]
    fn while_loop_still_parses() {
        let cmd = parse_complete("while true; do echo hi; done");
        assert!(matches!(
            cmd,
            Command::Loop {
                kind: LoopKind::While,
                ..
            }
        ));
        assert!(parse_diagnostics("while true; do echo hi; done").is_empty());
    }

    #[test]
    fn if_then_fi_still_parses() {
        let cmd = parse_complete("if true; then echo a; fi");
        assert!(matches!(cmd, Command::If { .. }));
        assert!(parse_diagnostics("if true; then echo a; fi").is_empty());
    }

    #[test]
    fn brace_group_still_parses() {
        let cmd = parse_complete("{ echo a; }");
        assert!(matches!(cmd, Command::BraceGroup(_)));
        assert!(parse_diagnostics("{ echo a; }").is_empty());
    }

    #[test]
    fn closing_brace_as_argument_is_literal() {
        assert_eq!(simple_words("echo }"), ["echo", "}"]);
    }

    #[test]
    fn function_no_parens_still_parses() {
        let cmd = parse_complete("function greet { echo hello; }");
        assert!(matches!(cmd, Command::FunctionDef { .. }));
        assert!(parse_diagnostics("function greet { echo hello; }").is_empty());
    }

    // ── `in` resolved in the parser ─────────────────────────────────────

    #[test]
    fn for_loop_still_parses() {
        let cmd = parse_complete("for x in a b; do echo $x; done");
        match cmd {
            Command::For { var, words, .. } => {
                assert_eq!(var, "x");
                assert_eq!(
                    words.iter().map(|w| w.to_str()).collect::<Vec<_>>(),
                    ["a", "b"]
                );
            }
            other => panic!("expected For, got {other:?}"),
        }
        assert!(parse_diagnostics("for x in a b; do echo $x; done").is_empty());
    }

    #[test]
    fn case_still_parses() {
        let cmd = parse_complete("case $x in a) echo a;; *) echo other;; esac");
        assert!(matches!(cmd, Command::Case { .. }));
        assert!(parse_diagnostics("case $x in a) echo a;; *) echo other;; esac").is_empty());
    }

    // ── Leading `!` is pipeline negation ────────────────────────────────

    #[test]
    fn leading_bang_consumed_as_negation() {
        // `! kill -0 %1` is pipeline negation: the `!` is consumed and the
        // inner pipeline parses exactly as the un-negated command would.
        // `! ` and two leading spaces are both two bytes, so `kill` lands at
        // the same offset and the ASTs — spans included — are identical.
        assert_eq!(
            parse_complete("! kill -0 %1"),
            parse_complete("  kill -0 %1")
        );
    }

    #[test]
    fn leading_bang_not_a_command_word() {
        assert_eq!(simple_words("! kill -0 %1"), ["kill", "-0", "%1"]);
        assert!(parse_diagnostics("! kill -0 %1").is_empty());
    }

    #[test]
    fn negation_inside_pipeline_branch() {
        // Negation is recognised at each pipeline-start, including after
        // `&&`. The right branch parses as `rm -rf /`, not a command `!`.
        let cmd = parse_complete("echo a && ! rm -rf /");
        match cmd {
            Command::And(_, right) => {
                assert_eq!(
                    first_simple(&right)
                        .words
                        .iter()
                        .map(|w| w.to_str())
                        .collect::<Vec<_>>(),
                    ["rm", "-rf", "/"]
                );
            }
            other => panic!("expected And, got {other:?}"),
        }
    }

    #[test]
    fn bang_as_argument_is_literal() {
        // `!` not at pipeline-start stays a literal argument.
        assert_eq!(
            simple_words("find . ! -name foo"),
            ["find", ".", "!", "-name", "foo"]
        );
        assert_eq!(simple_words("[ ! -f x ]"), ["[", "!", "-f", "x", "]"]);
        assert!(parse_diagnostics("find . ! -name foo").is_empty());
    }

    #[test]
    fn bang_prefixed_word_is_not_negation() {
        // Only the exact single-char `!` is negation; `!foo` is a command word.
        assert_eq!(simple_words("!foo bar"), ["!foo", "bar"]);
    }

    // ── No silent token loss ────────────────────────────────────────────

    #[test]
    fn stray_done_floors_with_error_diagnostic() {
        // A `done` with no opening `do` cannot be placed; rather than being
        // silently dropped it must surface an Error-severity diagnostic.
        assert!(has_error_diagnostic("done"));
    }

    #[test]
    fn stray_closing_keyword_floors() {
        assert!(has_error_diagnostic("echo hi; fi"));
    }
}
