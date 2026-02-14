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

    #[test]
    fn test_empty_input() {
        let cmd = parse("");
        match &cmd {
            Command::Simple(sc) => {
                assert!(sc.words.is_empty());
                assert!(sc.assignments.is_empty());
                assert!(sc.redirections.is_empty());
            }
            _ => panic!("Expected empty simple command"),
        }
    }

    #[test]
    fn test_whitespace_only() {
        let cmd = parse("   \t  ");
        match &cmd {
            Command::Simple(sc) => {
                assert!(sc.words.is_empty());
            }
            _ => panic!("Expected empty simple command"),
        }
    }

    // --- Pipelines ---

    #[test]
    fn test_pipeline() {
        let cmd = parse("echo foo | grep bar");
        match &cmd {
            Command::Pipeline(cmds) => {
                assert_eq!(cmds.len(), 2);
                match &cmds[0] {
                    Command::Simple(sc) => assert_eq!(sc.command_name(), Some("echo")),
                    _ => panic!("Expected simple command in pipeline"),
                }
                match &cmds[1] {
                    Command::Simple(sc) => assert_eq!(sc.command_name(), Some("grep")),
                    _ => panic!("Expected simple command in pipeline"),
                }
            }
            _ => panic!("Expected pipeline"),
        }
    }

    #[test]
    fn test_pipeline_three_commands() {
        let cmd = parse("cat file | sort | uniq");
        match &cmd {
            Command::Pipeline(cmds) => assert_eq!(cmds.len(), 3),
            _ => panic!("Expected pipeline"),
        }
    }

    // --- And / Or ---

    #[test]
    fn test_and() {
        let cmd = parse("cmd1 && cmd2");
        match &cmd {
            Command::And(left, right) => {
                match left.as_ref() {
                    Command::Simple(sc) => assert_eq!(sc.command_name(), Some("cmd1")),
                    _ => panic!("Expected simple command"),
                }
                match right.as_ref() {
                    Command::Simple(sc) => assert_eq!(sc.command_name(), Some("cmd2")),
                    _ => panic!("Expected simple command"),
                }
            }
            _ => panic!("Expected And command"),
        }
    }

    #[test]
    fn test_or() {
        let cmd = parse("cmd1 || cmd2");
        match &cmd {
            Command::Or(left, right) => {
                match left.as_ref() {
                    Command::Simple(sc) => assert_eq!(sc.command_name(), Some("cmd1")),
                    _ => panic!("Expected simple command"),
                }
                match right.as_ref() {
                    Command::Simple(sc) => assert_eq!(sc.command_name(), Some("cmd2")),
                    _ => panic!("Expected simple command"),
                }
            }
            _ => panic!("Expected Or command"),
        }
    }

    #[test]
    fn test_and_or_chained() {
        let cmd = parse("a && b || c");
        match &cmd {
            Command::Or(left, _) => {
                match left.as_ref() {
                    Command::And(_, _) => {}
                    _ => panic!("Expected And inside Or"),
                }
            }
            _ => panic!("Expected Or command"),
        }
    }

    // --- Sequences ---

    #[test]
    fn test_sequence() {
        let cmd = parse("cmd1; cmd2; cmd3");
        match &cmd {
            Command::Sequence(cmds) => {
                assert_eq!(cmds.len(), 3);
            }
            _ => panic!("Expected sequence, got {:?}", cmd),
        }
    }

    #[test]
    fn test_sequence_trailing_semi() {
        let cmd = parse("cmd1; cmd2;");
        match &cmd {
            Command::Sequence(cmds) => assert_eq!(cmds.len(), 2),
            _ => panic!("Expected sequence"),
        }
    }

    // --- Background ---

    #[test]
    fn test_background() {
        let cmd = parse("sleep 10 &");
        match &cmd {
            Command::Background(inner) => {
                match inner.as_ref() {
                    Command::Simple(sc) => assert_eq!(sc.command_name(), Some("sleep")),
                    _ => panic!("Expected simple command"),
                }
            }
            _ => panic!("Expected background command"),
        }
    }

    #[test]
    fn test_background_in_sequence() {
        let cmd = parse("cmd1 & cmd2");
        match &cmd {
            Command::Sequence(cmds) => {
                assert_eq!(cmds.len(), 2);
                match &cmds[0] {
                    Command::Background(_) => {}
                    _ => panic!("Expected background"),
                }
            }
            _ => panic!("Expected sequence"),
        }
    }

    // --- Subshell ---

    #[test]
    fn test_subshell() {
        let cmd = parse("(cmd1; cmd2)");
        match &cmd {
            Command::Subshell(inner) => {
                match inner.as_ref() {
                    Command::Sequence(cmds) => assert_eq!(cmds.len(), 2),
                    _ => panic!("Expected sequence inside subshell"),
                }
            }
            _ => panic!("Expected subshell"),
        }
    }

    #[test]
    fn test_subshell_single_command() {
        let cmd = parse("(echo hello)");
        match &cmd {
            Command::Subshell(inner) => {
                match inner.as_ref() {
                    Command::Simple(sc) => assert_eq!(sc.command_name(), Some("echo")),
                    _ => panic!("Expected simple command"),
                }
            }
            _ => panic!("Expected subshell"),
        }
    }

    // --- Brace group ---

    #[test]
    fn test_brace_group() {
        let cmd = parse("{ cmd1; cmd2; }");
        match &cmd {
            Command::BraceGroup(inner) => {
                match inner.as_ref() {
                    Command::Sequence(cmds) => assert_eq!(cmds.len(), 2),
                    _ => panic!("Expected sequence inside brace group"),
                }
            }
            _ => panic!("Expected brace group"),
        }
    }

    // --- If / elif / else ---

    #[test]
    fn test_if_then_fi() {
        let cmd = parse("if true; then echo yes; fi");
        match &cmd {
            Command::If { condition, then_branch, elif_branches, else_branch } => {
                match condition.as_ref() {
                    Command::Simple(sc) => assert_eq!(sc.command_name(), Some("true")),
                    _ => panic!("Expected simple condition"),
                }
                match then_branch.as_ref() {
                    Command::Simple(sc) => assert_eq!(sc.command_name(), Some("echo")),
                    _ => panic!("Expected simple then branch"),
                }
                assert!(elif_branches.is_empty());
                assert!(else_branch.is_none());
            }
            _ => panic!("Expected if command"),
        }
    }

    #[test]
    fn test_if_else() {
        let cmd = parse("if true; then echo yes; else echo no; fi");
        match &cmd {
            Command::If { else_branch, .. } => {
                assert!(else_branch.is_some());
            }
            _ => panic!("Expected if command"),
        }
    }

    #[test]
    fn test_if_elif_else() {
        let cmd = parse("if a; then b; elif c; then d; elif e; then f; else g; fi");
        match &cmd {
            Command::If { elif_branches, else_branch, .. } => {
                assert_eq!(elif_branches.len(), 2);
                assert!(else_branch.is_some());
            }
            _ => panic!("Expected if command"),
        }
    }

    // --- For loop ---

    #[test]
    fn test_for_loop() {
        let cmd = parse("for x in a b c; do echo $x; done");
        match &cmd {
            Command::For { var, words, body } => {
                assert_eq!(var, "x");
                assert_eq!(words.len(), 3);
                assert_eq!(words[0].to_str(), "a");
                assert_eq!(words[1].to_str(), "b");
                assert_eq!(words[2].to_str(), "c");
                match body.as_ref() {
                    Command::Simple(sc) => assert_eq!(sc.command_name(), Some("echo")),
                    _ => panic!("Expected simple body"),
                }
            }
            _ => panic!("Expected for command"),
        }
    }

    // --- While loop ---

    #[test]
    fn test_while_loop() {
        let cmd = parse("while true; do echo loop; done");
        match &cmd {
            Command::While { condition, body } => {
                match condition.as_ref() {
                    Command::Simple(sc) => assert_eq!(sc.command_name(), Some("true")),
                    _ => panic!("Expected simple condition"),
                }
                match body.as_ref() {
                    Command::Simple(sc) => assert_eq!(sc.command_name(), Some("echo")),
                    _ => panic!("Expected simple body"),
                }
            }
            _ => panic!("Expected while command"),
        }
    }

    // --- Until loop ---

    #[test]
    fn test_until_loop() {
        let cmd = parse("until false; do echo loop; done");
        match &cmd {
            Command::Until { condition, body } => {
                match condition.as_ref() {
                    Command::Simple(sc) => assert_eq!(sc.command_name(), Some("false")),
                    _ => panic!("Expected simple condition"),
                }
                match body.as_ref() {
                    Command::Simple(sc) => assert_eq!(sc.command_name(), Some("echo")),
                    _ => panic!("Expected simple body"),
                }
            }
            _ => panic!("Expected until command"),
        }
    }

    // --- Case statement ---

    #[test]
    fn test_case_basic() {
        let cmd = parse("case $x in a) echo a;; b) echo b;; esac");
        match &cmd {
            Command::Case { word, arms } => {
                assert!(word.has_dynamic_parts()); // $x is dynamic
                assert_eq!(arms.len(), 2);
                assert_eq!(arms[0].patterns[0].to_str(), "a");
                assert_eq!(arms[0].terminator, CaseTerminator::Break);
                assert_eq!(arms[1].patterns[0].to_str(), "b");
            }
            _ => panic!("Expected case command"),
        }
    }

    #[test]
    fn test_case_multiple_patterns() {
        let cmd = parse("case $x in a|b) echo ab;; esac");
        match &cmd {
            Command::Case { arms, .. } => {
                assert_eq!(arms[0].patterns.len(), 2);
                assert_eq!(arms[0].patterns[0].to_str(), "a");
                assert_eq!(arms[0].patterns[1].to_str(), "b");
            }
            _ => panic!("Expected case command"),
        }
    }

    #[test]
    fn test_case_fallthrough() {
        let cmd = parse("case $x in a) echo a;& b) echo b;; esac");
        match &cmd {
            Command::Case { arms, .. } => {
                assert_eq!(arms[0].terminator, CaseTerminator::Fallthrough);
                assert_eq!(arms[1].terminator, CaseTerminator::Break);
            }
            _ => panic!("Expected case command"),
        }
    }

    #[test]
    fn test_case_continue() {
        let cmd = parse("case $x in a) echo a;;& b) echo b;; esac");
        match &cmd {
            Command::Case { arms, .. } => {
                assert_eq!(arms[0].terminator, CaseTerminator::Continue);
            }
            _ => panic!("Expected case command"),
        }
    }

    #[test]
    fn test_case_glob_pattern() {
        let cmd = parse("case $x in *) echo default;; esac");
        match &cmd {
            Command::Case { arms, .. } => {
                assert_eq!(arms.len(), 1);
                // The * is parsed as a glob
                assert!(arms[0].patterns[0].parts.iter().any(|p| matches!(p, WordPart::Glob(_))));
            }
            _ => panic!("Expected case command"),
        }
    }

    #[test]
    fn test_case_empty_body() {
        let cmd = parse("case $x in a) ;; esac");
        match &cmd {
            Command::Case { arms, .. } => {
                assert!(arms[0].body.is_none());
            }
            _ => panic!("Expected case command"),
        }
    }

    // --- Function definitions ---

    #[test]
    fn test_function_def() {
        let cmd = parse("function foo() { echo hello; }");
        match &cmd {
            Command::FunctionDef { name, body } => {
                assert_eq!(name, "foo");
                match body.as_ref() {
                    Command::BraceGroup(_) => {}
                    _ => panic!("Expected brace group body"),
                }
            }
            _ => panic!("Expected function def"),
        }
    }

    #[test]
    fn test_function_def_no_parens() {
        let cmd = parse("function bar { echo hi; }");
        match &cmd {
            Command::FunctionDef { name, .. } => {
                assert_eq!(name, "bar");
            }
            _ => panic!("Expected function def"),
        }
    }

    // --- Assignments ---

    #[test]
    fn test_assignment_standalone() {
        let cmd = parse("VAR=value");
        match &cmd {
            Command::Assignment(a) => {
                assert_eq!(a.name, "VAR");
                assert_eq!(a.value.to_str(), "value");
            }
            _ => panic!("Expected assignment, got {:?}", cmd),
        }
    }

    #[test]
    fn test_assignment_empty_value() {
        let cmd = parse("VAR=");
        match &cmd {
            Command::Assignment(a) => {
                assert_eq!(a.name, "VAR");
                assert_eq!(a.value.to_str(), "");
            }
            _ => panic!("Expected assignment"),
        }
    }

    #[test]
    fn test_assignment_with_command() {
        let cmd = parse("VAR=value cmd arg");
        match &cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.assignments.len(), 1);
                assert_eq!(sc.assignments[0].name, "VAR");
                assert_eq!(sc.assignments[0].value.to_str(), "value");
                assert_eq!(sc.command_name(), Some("cmd"));
                assert_eq!(sc.args().len(), 1);
            }
            _ => panic!("Expected simple command with assignment"),
        }
    }

    // --- Redirections ---

    #[test]
    fn test_redirect_output() {
        let cmd = parse("echo hello > file.txt");
        match &cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.redirections.len(), 1);
                assert_eq!(sc.redirections[0].kind, RedirectionKind::Output);
                assert!(sc.redirections[0].fd.is_none());
                match &sc.redirections[0].target {
                    RedirectionTarget::File(w) => assert_eq!(w.to_str(), "file.txt"),
                    _ => panic!("Expected file target"),
                }
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_redirect_input() {
        let cmd = parse("cat < input.txt");
        match &cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.redirections.len(), 1);
                assert_eq!(sc.redirections[0].kind, RedirectionKind::Input);
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_redirect_append() {
        let cmd = parse("echo hello >> file.txt");
        match &cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.redirections.len(), 1);
                assert_eq!(sc.redirections[0].kind, RedirectionKind::Append);
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_redirect_clobber() {
        let cmd = parse("echo hello >| file.txt");
        match &cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.redirections.len(), 1);
                assert_eq!(sc.redirections[0].kind, RedirectionKind::Clobber);
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_redirect_dup_output() {
        let cmd = parse("cmd >&2");
        match &cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.redirections.len(), 1);
                assert_eq!(sc.redirections[0].kind, RedirectionKind::DupOutput);
                match &sc.redirections[0].target {
                    RedirectionTarget::Fd(fd) => assert_eq!(*fd, 2),
                    _ => panic!("Expected Fd target"),
                }
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_redirect_dup_input() {
        let cmd = parse("cmd <&3");
        match &cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.redirections.len(), 1);
                assert_eq!(sc.redirections[0].kind, RedirectionKind::DupInput);
                match &sc.redirections[0].target {
                    RedirectionTarget::Fd(fd) => assert_eq!(*fd, 3),
                    _ => panic!("Expected Fd target"),
                }
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_redirect_fd_prefix() {
        let cmd = parse("cmd 2>errors.txt");
        match &cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.redirections.len(), 1);
                assert_eq!(sc.redirections[0].fd, Some(2));
                assert_eq!(sc.redirections[0].kind, RedirectionKind::Output);
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_redirect_herestring() {
        let cmd = parse("cat <<< hello");
        match &cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.redirections.len(), 1);
                assert_eq!(sc.redirections[0].kind, RedirectionKind::Herestring);
            }
            _ => panic!("Expected simple command"),
        }
    }

    // --- Quoting ---

    #[test]
    fn test_single_quotes() {
        let cmd = parse("echo 'hello world'");
        match &cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.words.len(), 2);
                match &sc.words[1].parts[0] {
                    WordPart::SingleQuoted(s) => assert_eq!(s, "hello world"),
                    _ => panic!("Expected single quoted"),
                }
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_double_quotes_literal() {
        let cmd = parse(r#"echo "hello world""#);
        match &cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.words.len(), 2);
                match &sc.words[1].parts[0] {
                    WordPart::DoubleQuoted(parts) => {
                        assert_eq!(parts.len(), 1);
                        match &parts[0] {
                            WordPart::Literal(s) => assert_eq!(s, "hello world"),
                            _ => panic!("Expected literal inside double quotes"),
                        }
                    }
                    _ => panic!("Expected double quoted"),
                }
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_double_quotes_with_variable() {
        let cmd = parse(r#"echo "hello $name""#);
        match &cmd {
            Command::Simple(sc) => {
                match &sc.words[1].parts[0] {
                    WordPart::DoubleQuoted(parts) => {
                        assert_eq!(parts.len(), 2);
                        assert!(matches!(&parts[0], WordPart::Literal(s) if s == "hello "));
                        assert!(matches!(&parts[1], WordPart::Parameter(s) if s == "name"));
                    }
                    _ => panic!("Expected double quoted"),
                }
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_double_quotes_with_command_sub() {
        let cmd = parse(r#"echo "today is $(date)""#);
        match &cmd {
            Command::Simple(sc) => {
                match &sc.words[1].parts[0] {
                    WordPart::DoubleQuoted(parts) => {
                        assert!(parts.iter().any(|p| matches!(p, WordPart::CommandSubstitution(s) if s == "date")));
                    }
                    _ => panic!("Expected double quoted"),
                }
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_double_quotes_with_backtick() {
        let cmd = parse(r#"echo "today is `date`""#);
        match &cmd {
            Command::Simple(sc) => {
                match &sc.words[1].parts[0] {
                    WordPart::DoubleQuoted(parts) => {
                        assert!(parts.iter().any(|p| matches!(p, WordPart::Backtick(s) if s == "date")));
                    }
                    _ => panic!("Expected double quoted"),
                }
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_ansi_c_quoting() {
        let cmd = parse("echo $'hello\\nworld'");
        match &cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.words.len(), 2);
                assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::AnsiCQuoted(s) if s == "hello\\nworld")));
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_backslash_escape() {
        let cmd = parse("echo hello\\ world");
        match &cmd {
            Command::Simple(sc) => {
                // backslash-space joins "hello" and "world" into a single word
                assert_eq!(sc.words.len(), 2);
                let text = sc.words[1].to_str();
                assert_eq!(text, "hello world");
            }
            _ => panic!("Expected simple command"),
        }
    }

    // --- Variable expansion ---

    #[test]
    fn test_parameter() {
        let cmd = parse("echo $VAR");
        match &cmd {
            Command::Simple(sc) => {
                assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::Parameter(s) if s == "VAR")));
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_parameter_expansion() {
        let cmd = parse("echo ${VAR}");
        match &cmd {
            Command::Simple(sc) => {
                assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::ParameterExpansion(s) if s == "VAR")));
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_special_variables() {
        for var in &["$@", "$?", "$$", "$!", "$#", "$*", "$-"] {
            let input = format!("echo {}", var);
            let cmd = parse(&input);
            match &cmd {
                Command::Simple(sc) => {
                    assert!(sc.words[1].has_dynamic_parts(), "Expected dynamic for {}", var);
                }
                _ => panic!("Expected simple command for {}", var),
            }
        }
    }

    // --- Command substitution ---

    #[test]
    fn test_command_substitution() {
        let cmd = parse("echo $(whoami)");
        match &cmd {
            Command::Simple(sc) => {
                assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::CommandSubstitution(s) if s == "whoami")));
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_backtick_substitution() {
        let cmd = parse("echo `whoami`");
        match &cmd {
            Command::Simple(sc) => {
                assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::Backtick(s) if s == "whoami")));
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_nested_command_substitution() {
        let cmd = parse("echo $(echo $(whoami))");
        match &cmd {
            Command::Simple(sc) => {
                match &sc.words[1].parts[0] {
                    WordPart::CommandSubstitution(s) => assert_eq!(s, "echo $(whoami)"),
                    _ => panic!("Expected command substitution"),
                }
            }
            _ => panic!("Expected simple command"),
        }
    }

    // --- Arithmetic ---

    #[test]
    fn test_arithmetic_expansion() {
        let cmd = parse("echo $((1 + 2))");
        match &cmd {
            Command::Simple(sc) => {
                assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::Arithmetic(s) if s == "1 + 2")));
            }
            _ => panic!("Expected simple command"),
        }
    }

    // --- Globs ---

    #[test]
    fn test_glob_star() {
        let cmd = parse("echo *.txt");
        match &cmd {
            Command::Simple(sc) => {
                let word = &sc.words[1];
                assert!(word.parts.iter().any(|p| matches!(p, WordPart::Glob(s) if s == "*")));
                assert!(word.parts.iter().any(|p| matches!(p, WordPart::Literal(s) if s == ".txt")));
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_glob_question() {
        let cmd = parse("echo file?.txt");
        match &cmd {
            Command::Simple(sc) => {
                assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::Glob(s) if s == "?")));
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_glob_bracket() {
        let cmd = parse("echo [abc].txt");
        match &cmd {
            Command::Simple(sc) => {
                assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::Glob(s) if s == "[abc]")));
            }
            _ => panic!("Expected simple command"),
        }
    }

    // --- Brace expansion ---

    #[test]
    fn test_brace_expansion() {
        let cmd = parse("echo {a,b,c}");
        match &cmd {
            Command::Simple(sc) => {
                match &sc.words[1].parts[0] {
                    WordPart::BraceExpansion(items) => {
                        assert_eq!(items, &["a", "b", "c"]);
                    }
                    _ => panic!("Expected brace expansion"),
                }
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_brace_no_comma_is_literal() {
        let cmd = parse("echo {foo}");
        match &cmd {
            Command::Simple(sc) => {
                // Without comma, should be literal { and }
                let text = sc.words[1].to_str();
                assert_eq!(text, "{foo}");
            }
            _ => panic!("Expected simple command"),
        }
    }

    // --- Process substitution ---

    #[test]
    fn test_process_substitution_input() {
        let cmd = parse("diff <(sort a) <(sort b)");
        match &cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.words.len(), 3); // diff, <(sort a), <(sort b)
                match &sc.words[1].parts[0] {
                    WordPart::ProcessSubstitution { direction, command } => {
                        assert_eq!(*direction, ProcessDirection::Input);
                        assert_eq!(command, "sort a");
                    }
                    _ => panic!("Expected process substitution"),
                }
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_process_substitution_output() {
        let cmd = parse("tee >(grep error)");
        match &cmd {
            Command::Simple(sc) => {
                match &sc.words[1].parts[0] {
                    WordPart::ProcessSubstitution { direction, command } => {
                        assert_eq!(*direction, ProcessDirection::Output);
                        assert_eq!(command, "grep error");
                    }
                    _ => panic!("Expected process substitution"),
                }
            }
            _ => panic!("Expected simple command"),
        }
    }

    // --- Comments ---

    #[test]
    fn test_comment() {
        let cmd = parse("echo foo # this is a comment");
        match &cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.command_name(), Some("echo"));
                assert_eq!(sc.args().len(), 1);
                assert_eq!(sc.args()[0].to_str(), "foo");
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_comment_only() {
        let cmd = parse("# just a comment");
        match &cmd {
            Command::Simple(sc) => {
                assert!(sc.words.is_empty());
            }
            _ => panic!("Expected empty simple command"),
        }
    }

    // --- Word helper methods ---

    #[test]
    fn test_word_literal() {
        let w = Word::literal("hello");
        assert_eq!(w.parts.len(), 1);
        assert_eq!(w.to_str(), "hello");
        assert!(!w.has_dynamic_parts());
    }

    #[test]
    fn test_word_to_str_various_parts() {
        let w = Word {
            parts: vec![
                WordPart::Literal("hello".to_string()),
                WordPart::SingleQuoted("world".to_string()),
            ],
        };
        assert_eq!(w.to_str(), "helloworld");
    }

    #[test]
    fn test_word_to_str_brace_expansion() {
        let w = Word {
            parts: vec![WordPart::BraceExpansion(vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
            ])],
        };
        assert_eq!(w.to_str(), "a,b,c");
    }

    #[test]
    fn test_word_to_str_process_substitution() {
        let w = Word {
            parts: vec![WordPart::ProcessSubstitution {
                direction: ProcessDirection::Input,
                command: "sort file".to_string(),
            }],
        };
        assert_eq!(w.to_str(), "sort file");
    }

    #[test]
    fn test_word_has_dynamic_parts_parameter() {
        let w = Word {
            parts: vec![WordPart::Parameter("HOME".to_string())],
        };
        assert!(w.has_dynamic_parts());
    }

    #[test]
    fn test_word_has_dynamic_parts_command_sub() {
        let w = Word {
            parts: vec![WordPart::CommandSubstitution("date".to_string())],
        };
        assert!(w.has_dynamic_parts());
    }

    #[test]
    fn test_word_has_dynamic_parts_backtick() {
        let w = Word {
            parts: vec![WordPart::Backtick("date".to_string())],
        };
        assert!(w.has_dynamic_parts());
    }

    #[test]
    fn test_word_has_dynamic_parts_arithmetic() {
        let w = Word {
            parts: vec![WordPart::Arithmetic("1+1".to_string())],
        };
        assert!(w.has_dynamic_parts());
    }

    #[test]
    fn test_word_has_dynamic_parts_process_sub() {
        let w = Word {
            parts: vec![WordPart::ProcessSubstitution {
                direction: ProcessDirection::Input,
                command: "cmd".to_string(),
            }],
        };
        assert!(w.has_dynamic_parts());
    }

    #[test]
    fn test_word_has_dynamic_parts_parameter_expansion() {
        let w = Word {
            parts: vec![WordPart::ParameterExpansion("HOME".to_string())],
        };
        assert!(w.has_dynamic_parts());
    }

    #[test]
    fn test_word_has_dynamic_parts_in_double_quotes() {
        let w = Word {
            parts: vec![WordPart::DoubleQuoted(vec![
                WordPart::Literal("hello ".to_string()),
                WordPart::Parameter("name".to_string()),
            ])],
        };
        assert!(w.has_dynamic_parts());
    }

    #[test]
    fn test_word_no_dynamic_parts_static() {
        let w = Word {
            parts: vec![
                WordPart::Literal("hello".to_string()),
                WordPart::SingleQuoted("world".to_string()),
                WordPart::Glob("*".to_string()),
                WordPart::BraceExpansion(vec!["a".to_string()]),
            ],
        };
        assert!(!w.has_dynamic_parts());
    }

    #[test]
    fn test_word_to_str_double_quoted() {
        let w = Word {
            parts: vec![WordPart::DoubleQuoted(vec![
                WordPart::Literal("hello ".to_string()),
                WordPart::Parameter("name".to_string()),
            ])],
        };
        assert_eq!(w.to_str(), "hello name");
    }

    // --- SimpleCommand helpers ---

    #[test]
    fn test_simple_command_name_none() {
        let sc = SimpleCommand {
            assignments: vec![],
            words: vec![],
            redirections: vec![],
        };
        assert_eq!(sc.command_name(), None);
    }

    #[test]
    fn test_simple_command_args_empty() {
        let sc = SimpleCommand {
            assignments: vec![],
            words: vec![Word::literal("echo")],
            redirections: vec![],
        };
        assert!(sc.args().is_empty());
    }

    #[test]
    fn test_simple_command_args_multiple() {
        let cmd = parse("echo a b c");
        match &cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.command_name(), Some("echo"));
                assert_eq!(sc.args().len(), 3);
                assert_eq!(sc.args()[0].to_str(), "a");
                assert_eq!(sc.args()[1].to_str(), "b");
                assert_eq!(sc.args()[2].to_str(), "c");
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_simple_command_name_non_literal() {
        let sc = SimpleCommand {
            assignments: vec![],
            words: vec![Word {
                parts: vec![WordPart::Parameter("cmd".to_string())],
            }],
            redirections: vec![],
        };
        // command_name returns "" for non-literal first part
        assert_eq!(sc.command_name(), Some(""));
    }

    // --- extract_simple_commands ---

    #[test]
    fn test_extract_simple_commands_from_pipeline() {
        let cmd = parse("echo foo | grep bar | wc -l");
        let scs = extract_simple_commands(&cmd);
        assert_eq!(scs.len(), 3);
        assert_eq!(scs[0].command_name(), Some("echo"));
        assert_eq!(scs[1].command_name(), Some("grep"));
        assert_eq!(scs[2].command_name(), Some("wc"));
    }

    #[test]
    fn test_extract_simple_commands_from_and_or() {
        let cmd = parse("a && b || c");
        let scs = extract_simple_commands(&cmd);
        assert_eq!(scs.len(), 3);
    }

    #[test]
    fn test_extract_simple_commands_from_sequence() {
        let cmd = parse("a; b; c");
        let scs = extract_simple_commands(&cmd);
        assert_eq!(scs.len(), 3);
    }

    #[test]
    fn test_extract_simple_commands_from_if() {
        let cmd = parse("if a; then b; elif c; then d; else e; fi");
        let scs = extract_simple_commands(&cmd);
        assert_eq!(scs.len(), 5); // a, b, c, d, e
    }

    #[test]
    fn test_extract_simple_commands_from_for() {
        let cmd = parse("for x in a b; do echo $x; done");
        let scs = extract_simple_commands(&cmd);
        assert_eq!(scs.len(), 1); // just the echo
    }

    #[test]
    fn test_extract_simple_commands_from_while() {
        let cmd = parse("while true; do echo loop; done");
        let scs = extract_simple_commands(&cmd);
        // While only collects from body, not condition
        assert_eq!(scs.len(), 1);
        assert_eq!(scs[0].command_name(), Some("echo"));
    }

    #[test]
    fn test_extract_simple_commands_from_until() {
        let cmd = parse("until false; do echo loop; done");
        let scs = extract_simple_commands(&cmd);
        // Until only collects from body, not condition
        assert_eq!(scs.len(), 1);
        assert_eq!(scs[0].command_name(), Some("echo"));
    }

    #[test]
    fn test_extract_simple_commands_from_case() {
        let cmd = parse("case $x in a) echo a;; b) echo b;; esac");
        let scs = extract_simple_commands(&cmd);
        assert_eq!(scs.len(), 2);
    }

    #[test]
    fn test_extract_simple_commands_from_function() {
        let cmd = parse("function foo() { echo hello; }");
        let scs = extract_simple_commands(&cmd);
        assert_eq!(scs.len(), 1);
        assert_eq!(scs[0].command_name(), Some("echo"));
    }

    #[test]
    fn test_extract_simple_commands_from_background() {
        let cmd = parse("sleep 10 &");
        let scs = extract_simple_commands(&cmd);
        assert_eq!(scs.len(), 1);
        assert_eq!(scs[0].command_name(), Some("sleep"));
    }

    #[test]
    fn test_extract_simple_commands_from_subshell() {
        let cmd = parse("(echo hello)");
        let scs = extract_simple_commands(&cmd);
        assert_eq!(scs.len(), 1);
    }

    #[test]
    fn test_extract_simple_commands_from_brace_group() {
        let cmd = parse("{ echo hello; }");
        let scs = extract_simple_commands(&cmd);
        assert_eq!(scs.len(), 1);
    }

    #[test]
    fn test_extract_simple_commands_from_assignment() {
        let cmd = parse("FOO=bar");
        let scs = extract_simple_commands(&cmd);
        assert_eq!(scs.len(), 0); // assignments don't contain simple commands
    }

    // --- extract_all_words ---

    #[test]
    fn test_extract_all_words_simple() {
        let cmd = parse("echo hello world");
        let words = extract_all_words(&cmd);
        assert_eq!(words.len(), 3);
    }

    #[test]
    fn test_extract_all_words_with_redirections() {
        let cmd = parse("echo hello > file.txt");
        let words = extract_all_words(&cmd);
        // echo, hello, file.txt (redirect target)
        assert_eq!(words.len(), 3);
    }

    #[test]
    fn test_extract_all_words_with_assignment() {
        let cmd = parse("VAR=value cmd arg");
        let words = extract_all_words(&cmd);
        // assignment value + cmd + arg
        assert_eq!(words.len(), 3);
    }

    #[test]
    fn test_extract_all_words_standalone_assignment() {
        let cmd = parse("VAR=value");
        let words = extract_all_words(&cmd);
        assert_eq!(words.len(), 1); // just the assignment value
    }

    #[test]
    fn test_extract_all_words_from_for() {
        let cmd = parse("for x in a b c; do echo $x; done");
        let words = extract_all_words(&cmd);
        // a, b, c (for-loop words) + echo, $x (body words)
        assert_eq!(words.len(), 5);
    }

    #[test]
    fn test_extract_all_words_from_case() {
        let cmd = parse("case $x in a) echo hello;; esac");
        let words = extract_all_words(&cmd);
        // $x (case word) + a (pattern) + echo, hello (body words)
        assert_eq!(words.len(), 4);
    }

    #[test]
    fn test_extract_all_words_from_pipeline() {
        let cmd = parse("echo a | grep b");
        let words = extract_all_words(&cmd);
        assert_eq!(words.len(), 4); // echo, a, grep, b
    }

    #[test]
    fn test_extract_all_words_from_and_or() {
        let cmd = parse("cmd1 arg1 && cmd2 arg2");
        let words = extract_all_words(&cmd);
        assert_eq!(words.len(), 4);
    }

    #[test]
    fn test_extract_all_words_from_background() {
        let cmd = parse("echo hello &");
        let words = extract_all_words(&cmd);
        assert_eq!(words.len(), 2);
    }

    #[test]
    fn test_extract_all_words_from_subshell() {
        let cmd = parse("(echo hello)");
        let words = extract_all_words(&cmd);
        assert_eq!(words.len(), 2);
    }

    #[test]
    fn test_extract_all_words_from_if() {
        let cmd = parse("if true; then echo yes; else echo no; fi");
        let words = extract_all_words(&cmd);
        // true, echo, yes, echo, no
        assert_eq!(words.len(), 5);
    }

    #[test]
    fn test_extract_all_words_from_while() {
        let cmd = parse("while true; do echo x; done");
        let words = extract_all_words(&cmd);
        // true, echo, x
        assert_eq!(words.len(), 3);
    }

    #[test]
    fn test_extract_all_words_from_function() {
        let cmd = parse("function foo() { echo bar; }");
        let words = extract_all_words(&cmd);
        assert_eq!(words.len(), 2); // echo, bar
    }

    // --- Complex / combined constructs ---

    #[test]
    fn test_pipeline_with_redirections() {
        let cmd = parse("cat < input.txt | sort > output.txt");
        match &cmd {
            Command::Pipeline(cmds) => {
                assert_eq!(cmds.len(), 2);
                match &cmds[0] {
                    Command::Simple(sc) => {
                        assert_eq!(sc.command_name(), Some("cat"));
                        assert_eq!(sc.redirections.len(), 1);
                        assert_eq!(sc.redirections[0].kind, RedirectionKind::Input);
                    }
                    _ => panic!("Expected simple command"),
                }
                match &cmds[1] {
                    Command::Simple(sc) => {
                        assert_eq!(sc.command_name(), Some("sort"));
                        assert_eq!(sc.redirections.len(), 1);
                        assert_eq!(sc.redirections[0].kind, RedirectionKind::Output);
                    }
                    _ => panic!("Expected simple command"),
                }
            }
            _ => panic!("Expected pipeline"),
        }
    }

    #[test]
    fn test_complex_nested_structure() {
        let cmd = parse("if true; then for x in a b; do echo $x; done; fi");
        match &cmd {
            Command::If { then_branch, .. } => {
                match then_branch.as_ref() {
                    Command::For { var, words, .. } => {
                        assert_eq!(var, "x");
                        assert_eq!(words.len(), 2);
                    }
                    _ => panic!("Expected for loop in then branch"),
                }
            }
            _ => panic!("Expected if command"),
        }
    }

    #[test]
    fn test_newline_separated_commands() {
        // Multiple commands separated by semicolons produce a sequence
        let cmd = parse("echo a; echo b; echo c");
        match &cmd {
            Command::Sequence(cmds) => {
                assert_eq!(cmds.len(), 3);
                for c in cmds {
                    match c {
                        Command::Simple(sc) => assert_eq!(sc.command_name(), Some("echo")),
                        _ => panic!("Expected simple command in sequence"),
                    }
                }
            }
            _ => panic!("Expected sequence"),
        }
    }

    #[test]
    fn test_mixed_word_parts() {
        let cmd = parse("echo prefix${VAR}suffix");
        match &cmd {
            Command::Simple(sc) => {
                let word = &sc.words[1];
                assert!(word.parts.len() >= 3);
                assert!(matches!(&word.parts[0], WordPart::Literal(s) if s == "prefix"));
                assert!(matches!(&word.parts[1], WordPart::ParameterExpansion(s) if s == "VAR"));
                assert!(matches!(&word.parts[2], WordPart::Literal(s) if s == "suffix"));
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_bare_dollar() {
        let cmd = parse("echo $");
        match &cmd {
            Command::Simple(sc) => {
                assert!(sc.words[1].parts.iter().any(|p| matches!(p, WordPart::Literal(s) if s == "$")));
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_multiple_redirections() {
        let cmd = parse("cmd > out.txt 2>&1");
        match &cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.redirections.len(), 2);
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_heredoc() {
        let cmd = parse("cat << EOF");
        match &cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.redirections.len(), 1);
                assert_eq!(sc.redirections[0].kind, RedirectionKind::Heredoc);
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_heredoc_strip() {
        let cmd = parse("cat <<- EOF");
        match &cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.redirections.len(), 1);
                assert_eq!(sc.redirections[0].kind, RedirectionKind::HeredocStrip);
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_double_quotes_with_escape() {
        let cmd = parse(r#"echo "hello\"world""#);
        match &cmd {
            Command::Simple(sc) => {
                match &sc.words[1].parts[0] {
                    WordPart::DoubleQuoted(parts) => {
                        // Should have literal containing the escaped quote
                        let text: String = parts.iter().map(|p| match p {
                            WordPart::Literal(s) => s.clone(),
                            _ => String::new(),
                        }).collect();
                        assert!(text.contains("hello"));
                        assert!(text.contains("\""));
                        assert!(text.contains("world"));
                    }
                    _ => panic!("Expected double quoted"),
                }
            }
            _ => panic!("Expected simple command"),
        }
    }

    #[test]
    fn test_word_to_str_ansi_c() {
        let w = Word {
            parts: vec![WordPart::AnsiCQuoted("hello".to_string())],
        };
        assert_eq!(w.to_str(), "hello");
    }

    #[test]
    fn test_word_to_str_glob() {
        let w = Word {
            parts: vec![WordPart::Glob("*".to_string())],
        };
        assert_eq!(w.to_str(), "*");
    }

    #[test]
    fn test_has_dynamic_parts_double_quoted_static() {
        let w = Word {
            parts: vec![WordPart::DoubleQuoted(vec![
                WordPart::Literal("static".to_string()),
            ])],
        };
        assert!(!w.has_dynamic_parts());
    }

    #[test]
    fn test_has_dynamic_parts_ansi_c_is_static() {
        let w = Word {
            parts: vec![WordPart::AnsiCQuoted("hello".to_string())],
        };
        assert!(!w.has_dynamic_parts());
    }

    #[test]
    fn test_extract_all_words_redirect_fd_target() {
        let cmd = parse("cmd >&2");
        let words = extract_all_words(&cmd);
        // cmd word only; Fd(2) is not a File target so not collected
        assert_eq!(words.len(), 1);
    }

    #[test]
    fn test_case_with_empty_body_arm() {
        let cmd = parse("case $x in a) ;; b) echo b;; esac");
        match &cmd {
            Command::Case { arms, .. } => {
                assert_eq!(arms.len(), 2);
                assert!(arms[0].body.is_none());
                assert!(arms[1].body.is_some());
            }
            _ => panic!("Expected case"),
        }
    }

    #[test]
    fn test_extract_simple_commands_case_empty_body() {
        let cmd = parse("case $x in a) ;; esac");
        let scs = extract_simple_commands(&cmd);
        assert_eq!(scs.len(), 0);
    }

    #[test]
    fn test_if_without_else() {
        let cmd = parse("if true; then echo yes; fi");
        let scs = extract_simple_commands(&cmd);
        assert_eq!(scs.len(), 2); // true + echo
    }

    #[test]
    fn test_extract_all_words_elif() {
        let cmd = parse("if a; then b; elif c; then d; fi");
        let words = extract_all_words(&cmd);
        // a, b, c, d
        assert_eq!(words.len(), 4);
    }

    #[test]
    fn test_extract_all_words_until() {
        let cmd = parse("until false; do echo x; done");
        let words = extract_all_words(&cmd);
        // false, echo, x
        assert_eq!(words.len(), 3);
    }
}
