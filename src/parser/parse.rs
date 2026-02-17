use super::ast::*;
use super::lexer::{Lexer, Token};

pub(super) struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    pub(super) fn new(input: &str) -> Self {
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize();
        Parser { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> Token {
        let tok = self.tokens.get(self.pos).cloned().unwrap_or(Token::Eof);
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

    pub(super) fn parse_complete(&mut self) -> Command {
        self.skip_newlines();
        if self.at_eof() {
            return Command::Simple(SimpleCommand {
                assignments: vec![],
                words: vec![],
                redirections: vec![],
            });
        }
        self.parse_list()
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
                    let word = w.clone();
                    self.advance();
                    words.push(word);

                    // Check for POSIX function definition: name() { body }
                    if words.len() == 1
                        && assignments.is_empty()
                        && matches!(self.peek(), Token::LParen)
                    {
                        // Peek further for RParen
                        if self.tokens.get(self.pos + 1).is_some_and(|t| matches!(t, Token::RParen)) {
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

        if assignments.is_empty() && words.is_empty() && redirections.is_empty() {
            // Empty command, return empty simple
        }

        // If only assignments and no words, return as assignment command
        if !assignments.is_empty() && words.is_empty()
            && assignments.len() == 1
        {
            return Command::Assignment(assignments.pop().unwrap());
        }

        Command::Simple(SimpleCommand {
            assignments,
            words,
            redirections,
        })
    }

    fn try_parse_assignment(&mut self) -> Option<Assignment> {
        if let Token::Word(ref w) = self.peek().clone()
            && !w.parts.is_empty()
            && let WordPart::Literal(ref s) = w.parts[0]
            && let Some(eq_pos) = s.find('=')
        {
            let name = &s[..eq_pos];
            if !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                && name
                    .chars()
                    .next()
                    .is_some_and(|c| !c.is_ascii_digit())
            {
                let value_start = &s[eq_pos + 1..];
                let mut value_parts = Vec::new();
                if !value_start.is_empty() {
                    value_parts
                        .push(WordPart::Literal(value_start.to_string()));
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
                let name = name.to_string();
                self.advance();
                return Some(Assignment { name, value });
            }
        }
        None
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
        self.expect(&Token::Fi);

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

        if matches!(self.peek(), Token::In) {
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
        self.expect(&Token::Done);

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
        self.expect(&Token::Done);

        Command::While {
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
        self.expect(&Token::Done);

        Command::Until {
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
        self.expect(&Token::In);
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

        self.expect(&Token::Esac);

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
        self.expect(&Token::RParen);

        Command::Subshell(Box::new(body))
    }

    fn parse_brace_group(&mut self) -> Command {
        self.advance(); // skip {
        self.skip_newlines();
        let body = self.parse_list();
        self.skip_newlines();
        self.expect(&Token::RBrace);

        Command::BraceGroup(Box::new(body))
    }
}
