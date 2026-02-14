// Shell parser — R5, R6
// Recursive descent parser producing a typed AST for shell commands.

/// A complete parsed shell command (may contain compound structures).
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    Simple(SimpleCommand),
    Pipeline(Vec<Command>),
    And(Box<Command>, Box<Command>),
    Or(Box<Command>, Box<Command>),
    Sequence(Vec<Command>),
    Background(Box<Command>),
    Subshell(Box<Command>),
    BraceGroup(Box<Command>),
    If {
        condition: Box<Command>,
        then_branch: Box<Command>,
        elif_branches: Vec<(Command, Command)>,
        else_branch: Option<Box<Command>>,
    },
    For {
        var: String,
        words: Vec<Word>,
        body: Box<Command>,
    },
    While {
        condition: Box<Command>,
        body: Box<Command>,
    },
    Until {
        condition: Box<Command>,
        body: Box<Command>,
    },
    Case {
        word: Word,
        arms: Vec<CaseArm>,
    },
    FunctionDef {
        name: String,
        body: Box<Command>,
    },
    Assignment(Assignment),
}

#[derive(Debug, Clone, PartialEq)]
pub struct CaseArm {
    pub patterns: Vec<Word>,
    pub body: Option<Command>,
    pub terminator: CaseTerminator,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CaseTerminator {
    Break,      // ;;
    Fallthrough, // ;&
    Continue,   // ;;&
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimpleCommand {
    pub assignments: Vec<Assignment>,
    pub words: Vec<Word>,
    pub redirections: Vec<Redirection>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Assignment {
    pub name: String,
    pub value: Word,
}

/// A word is a sequence of word parts that get concatenated.
#[derive(Debug, Clone, PartialEq)]
pub struct Word {
    pub parts: Vec<WordPart>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WordPart {
    Literal(String),
    SingleQuoted(String),
    DoubleQuoted(Vec<WordPart>),
    AnsiCQuoted(String),
    Parameter(String),
    ParameterExpansion(String),
    CommandSubstitution(String),
    Backtick(String),
    Arithmetic(String),
    BraceExpansion(Vec<String>),
    Glob(String),
    ProcessSubstitution { direction: ProcessDirection, command: String },
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProcessDirection {
    Input,  // <(cmd)
    Output, // >(cmd)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Redirection {
    pub fd: Option<i32>,
    pub kind: RedirectionKind,
    pub target: RedirectionTarget,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RedirectionKind {
    Input,       // <
    Output,      // >
    Append,      // >>
    Clobber,     // >|
    DupInput,    // <&
    DupOutput,   // >&
    Heredoc,     // <<
    HeredocStrip, // <<-
    Herestring,  // <<<
}

#[derive(Debug, Clone, PartialEq)]
pub enum RedirectionTarget {
    File(Word),
    Fd(i32),
    Heredoc(String),
}

impl Word {
    pub fn literal(s: &str) -> Self {
        Word {
            parts: vec![WordPart::Literal(s.to_string())],
        }
    }

    /// Returns true if this word contains dynamic shell constructs whose runtime
    /// value cannot be determined by static analysis.
    pub fn has_dynamic_parts(&self) -> bool {
        self.parts.iter().any(|part| match part {
            WordPart::CommandSubstitution(_)
            | WordPart::Backtick(_)
            | WordPart::Parameter(_)
            | WordPart::ParameterExpansion(_)
            | WordPart::Arithmetic(_)
            | WordPart::ProcessSubstitution { .. } => true,
            WordPart::DoubleQuoted(inner) => {
                let w = Word { parts: inner.clone() };
                w.has_dynamic_parts()
            }
            _ => false,
        })
    }

    /// Flatten this word to a plain string for matching purposes.
    pub fn to_str(&self) -> String {
        let mut out = String::new();
        for part in &self.parts {
            match part {
                WordPart::Literal(s)
                | WordPart::SingleQuoted(s)
                | WordPart::AnsiCQuoted(s)
                | WordPart::Parameter(s)
                | WordPart::ParameterExpansion(s)
                | WordPart::CommandSubstitution(s)
                | WordPart::Backtick(s)
                | WordPart::Arithmetic(s)
                | WordPart::Glob(s) => out.push_str(s),
                WordPart::DoubleQuoted(parts) => {
                    let w = Word { parts: parts.clone() };
                    out.push_str(&w.to_str());
                }
                WordPart::BraceExpansion(items) => {
                    out.push_str(&items.join(","));
                }
                WordPart::ProcessSubstitution { command, .. } => {
                    out.push_str(command);
                }
            }
        }
        out
    }
}

impl SimpleCommand {
    /// The command name (first word), if any.
    pub fn command_name(&self) -> Option<&str> {
        self.words.first().map(|w| {
            // Return a reference to the first literal part
            if let Some(WordPart::Literal(s)) = w.parts.first() {
                s.as_str()
            } else {
                ""
            }
        })
    }

    /// The arguments (all words after the first).
    pub fn args(&self) -> &[Word] {
        if self.words.len() > 1 {
            &self.words[1..]
        } else {
            &[]
        }
    }
}

/// Parse a shell command string into an AST.
/// Returns a partial AST on malformed input (never panics).
pub fn parse(input: &str) -> Command {
    let mut parser = Parser::new(input);
    parser.parse_complete()
}

/// Extract all simple commands from a compound command AST.
pub fn extract_simple_commands(cmd: &Command) -> Vec<&SimpleCommand> {
    let mut result = Vec::new();
    collect_simple_commands(cmd, &mut result);
    result
}

fn collect_simple_commands<'a>(cmd: &'a Command, out: &mut Vec<&'a SimpleCommand>) {
    match cmd {
        Command::Simple(sc) => out.push(sc),
        Command::Pipeline(cmds) | Command::Sequence(cmds) => {
            for c in cmds {
                collect_simple_commands(c, out);
            }
        }
        Command::And(a, b) | Command::Or(a, b) => {
            collect_simple_commands(a, out);
            collect_simple_commands(b, out);
        }
        Command::Background(c) | Command::Subshell(c) | Command::BraceGroup(c) => {
            collect_simple_commands(c, out);
        }
        Command::If { condition, then_branch, elif_branches, else_branch } => {
            collect_simple_commands(condition, out);
            collect_simple_commands(then_branch, out);
            for (cond, body) in elif_branches {
                collect_simple_commands(cond, out);
                collect_simple_commands(body, out);
            }
            if let Some(eb) = else_branch {
                collect_simple_commands(eb, out);
            }
        }
        Command::For { body, .. } | Command::While { body, .. } | Command::Until { body, .. } => {
            collect_simple_commands(body, out);
        }
        Command::Case { arms, .. } => {
            for arm in arms {
                if let Some(body) = &arm.body {
                    collect_simple_commands(body, out);
                }
            }
        }
        Command::FunctionDef { body, .. } => {
            collect_simple_commands(body, out);
        }
        Command::Assignment(_) => {}
    }
}

/// Extract all words from all positions in the AST (for security scanning).
/// Includes arguments, redirect targets, for-loop words, assignment values, etc.
pub fn extract_all_words(cmd: &Command) -> Vec<&Word> {
    let mut result = Vec::new();
    collect_all_words(cmd, &mut result);
    result
}

fn collect_all_words<'a>(cmd: &'a Command, out: &mut Vec<&'a Word>) {
    match cmd {
        Command::Simple(sc) => {
            for w in &sc.words {
                out.push(w);
            }
            for a in &sc.assignments {
                out.push(&a.value);
            }
            for r in &sc.redirections {
                match &r.target {
                    RedirectionTarget::File(w) => out.push(w),
                    RedirectionTarget::Heredoc(_) => {
                        // Treat heredoc content as a synthetic word for scanning
                        // (handled separately since it's a String, not Word)
                    }
                    RedirectionTarget::Fd(_) => {}
                }
            }
        }
        Command::Pipeline(cmds) | Command::Sequence(cmds) => {
            for c in cmds {
                collect_all_words(c, out);
            }
        }
        Command::And(a, b) | Command::Or(a, b) => {
            collect_all_words(a, out);
            collect_all_words(b, out);
        }
        Command::Background(c) | Command::Subshell(c) | Command::BraceGroup(c) => {
            collect_all_words(c, out);
        }
        Command::If { condition, then_branch, elif_branches, else_branch } => {
            collect_all_words(condition, out);
            collect_all_words(then_branch, out);
            for (cond, body) in elif_branches {
                collect_all_words(cond, out);
                collect_all_words(body, out);
            }
            if let Some(eb) = else_branch {
                collect_all_words(eb, out);
            }
        }
        Command::For { words, body, .. } => {
            for w in words {
                out.push(w);
            }
            collect_all_words(body, out);
        }
        Command::While { condition, body } | Command::Until { condition, body } => {
            collect_all_words(condition, out);
            collect_all_words(body, out);
        }
        Command::Case { word, arms } => {
            out.push(word);
            for arm in arms {
                for p in &arm.patterns {
                    out.push(p);
                }
                if let Some(body) = &arm.body {
                    collect_all_words(body, out);
                }
            }
        }
        Command::FunctionDef { body, .. } => {
            collect_all_words(body, out);
        }
        Command::Assignment(a) => {
            out.push(&a.value);
        }
    }
}

// --- Tokenizer ---

#[derive(Debug, Clone, PartialEq)]
enum Token {
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

struct Lexer {
    input: Vec<char>,
    pos: usize,
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Lexer {
    fn new(input: &str) -> Self {
        Lexer {
            input: input.chars().collect(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.input.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<char> {
        let ch = self.input.get(self.pos).copied();
        if ch.is_some() {
            self.pos += 1;
        }
        ch
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.input.get(self.pos + offset).copied()
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

    fn tokenize(&mut self) -> Vec<Token> {
        let mut tokens = Vec::new();
        loop {
            self.skip_whitespace();
            match self.peek() {
                None => {
                    tokens.push(Token::Eof);
                    break;
                }
                Some('\n') => {
                    self.advance();
                    tokens.push(Token::Newline);
                }
                Some(';') => {
                    self.advance();
                    if self.peek() == Some(';') {
                        self.advance();
                        if self.peek() == Some('&') {
                            self.advance();
                            tokens.push(Token::DoubleSemiAmp);
                        } else {
                            tokens.push(Token::DoubleSemi);
                        }
                    } else if self.peek() == Some('&') {
                        self.advance();
                        tokens.push(Token::SemiAmp);
                    } else {
                        tokens.push(Token::Semi);
                    }
                }
                Some('&') => {
                    self.advance();
                    if self.peek() == Some('&') {
                        self.advance();
                        tokens.push(Token::And);
                    } else {
                        tokens.push(Token::Amp);
                    }
                }
                Some('|') => {
                    self.advance();
                    if self.peek() == Some('|') {
                        self.advance();
                        tokens.push(Token::Or);
                    } else {
                        tokens.push(Token::Pipe);
                    }
                }
                Some('(') => {
                    self.advance();
                    tokens.push(Token::LParen);
                }
                Some(')') => {
                    self.advance();
                    tokens.push(Token::RParen);
                }
                Some(ch) if is_redirect_start(ch) => {
                    if let Some(tok) = self.try_read_redirect_or_process_sub() {
                        tokens.push(tok);
                    }
                }
                _ => {
                    // Try to read a word (may include fd prefix for redirect)
                    if let Some(tok) = self.read_word_or_keyword() {
                        tokens.push(tok);
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
            _ => None,
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
                // Read delimiter word, then heredoc body until delimiter on its own line
                self.skip_whitespace();
                let _delim = self.read_plain_word_text();
                // For simplicity, treat heredoc body as empty in tokenizer
                // (full heredoc parsing requires multi-line lookahead)
                RedirectionTarget::Heredoc(String::new())
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
                    // Glob bracket expression
                    let mut glob = String::new();
                    glob.push(self.advance().unwrap()); // [
                    while let Some(ch) = self.peek() {
                        glob.push(ch);
                        self.advance();
                        if ch == ']' {
                            break;
                        }
                    }
                    parts.push(WordPart::Glob(glob));
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
                    Some(WordPart::CommandSubstitution(cmd))
                }
            }
            Some('{') => {
                self.advance(); // skip {
                let s = self.read_until_char('}');
                self.advance(); // skip }
                Some(WordPart::ParameterExpansion(s))
            }
            Some('\'') => {
                // ANSI-C quoting $'...'
                self.advance(); // skip '
                let s = self.read_until_char('\'');
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
        let start = self.pos;
        self.advance(); // skip {
        let mut items = Vec::new();
        let mut current = String::new();
        let mut has_comma = false;
        loop {
            match self.peek() {
                None => {
                    // Unterminated, restore position
                    self.pos = start;
                    return None;
                }
                Some('}') => {
                    self.advance();
                    if has_comma {
                        items.push(current);
                        return Some(items);
                    } else {
                        // No comma means not a brace expansion
                        self.pos = start;
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
                    self.pos = start;
                    return None;
                }
                Some(ch) => {
                    current.push(ch);
                    self.advance();
                }
            }
        }
    }

    fn read_word_or_keyword(&mut self) -> Option<Token> {
        // Check for fd number prefix before redirect
        let start = self.pos;
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
            self.pos = start;
        }

        let parts = self.read_word_parts();
        if parts.is_empty() {
            return None;
        }

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

        // Check for assignment (NAME=VALUE in the first literal part)
        if !parts.is_empty()
            && let WordPart::Literal(ref s) = parts[0]
            && let Some(_eq_pos) = s.find('=')
        {
            let name = &s[.._eq_pos];
            if !name.is_empty()
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && name.chars().next().is_some_and(|c| !c.is_ascii_digit())
            {
                // It's an assignment — detected at the parser level.
                // Just return the whole thing as a word token.
            }
        }

        Some(Token::Word(Word { parts }))
    }
}

fn is_metachar(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\n' | '|' | '&' | ';' | '(' | ')' | '<' | '>' | '#')
}

fn is_word_char(ch: char) -> bool {
    !is_metachar(ch) && ch != '\'' && ch != '"' && ch != '`' && ch != '$' && ch != '\\'
}

fn is_redirect_start(ch: char) -> bool {
    ch == '<' || ch == '>'
}

// --- Parser ---

impl Parser {
    fn new(input: &str) -> Self {
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

    fn parse_complete(&mut self) -> Command {
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
            self.skip_newlines();
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
        match self.peek().clone() {
            Token::If => self.parse_if(),
            Token::For => self.parse_for(),
            Token::While => self.parse_while(),
            Token::Until => self.parse_until(),
            Token::Case => self.parse_case(),
            Token::Function => self.parse_function_def(),
            Token::LParen => self.parse_subshell(),
            Token::LBrace => self.parse_brace_group(),
            _ => self.parse_simple_command(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_command() {
        let cmd = parse("echo hello world");
        match &cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.command_name(), Some("echo"));
                assert_eq!(sc.args().len(), 2);
            }
            _ => panic!("Expected simple command"),
        }
    }
}
