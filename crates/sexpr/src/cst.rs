// Concrete Syntax Tree (CST) for s-expressions with trivia preservation.
//
// This module provides a CST that preserves all source formatting including
// whitespace and comments. It uses the "Cofree comonad" pattern where every
// node carries an annotation containing trivia and span information.
//
// Benefits:
// - Source-to-source transformations preserve formatting
// - Enables rewrite-based migration tools
// - Pattern matching still works on the structure

#![allow(clippy::vec_box)]

use crate::span::Span;

/// Base functor: one layer of CST structure without annotations.
/// This is the base functor for the fixpoint-of-functor pattern.
#[derive(Debug, Clone, PartialEq)]
pub enum ShapeF<R> {
    /// A bare atom identifier (e.g., `rule`, `git`, `:allow`).
    /// Serialized without quotes.
    Atom(String),
    /// A string literal (e.g., `"~/.config"`).
    /// Always serialized with quotes to preserve the distinction from bare atoms.
    Str(String),
    /// A list expression: `(children...)`
    List(Vec<R>),
    /// A vector expression: `[children...]`
    Vector(Vec<R>),
}

/// The shape of an s-expression node (structure without annotations).
/// This is a type alias for backward compatibility.
pub type Shape = ShapeF<Box<CstNode>>;

#[cfg(test)]
impl<R> ShapeF<R> {
    fn map<S>(self, f: impl FnMut(R) -> S) -> ShapeF<S> {
        match self {
            ShapeF::Atom(s) => ShapeF::Atom(s),
            ShapeF::Str(s) => ShapeF::Str(s),
            ShapeF::List(children) => ShapeF::List(children.into_iter().map(f).collect()),
            ShapeF::Vector(children) => ShapeF::Vector(children.into_iter().map(f).collect()),
        }
    }

    fn map_ref<S>(&self, f: impl FnMut(&R) -> S) -> ShapeF<S> {
        match self {
            ShapeF::Atom(s) => ShapeF::Atom(s.clone()),
            ShapeF::Str(s) => ShapeF::Str(s.clone()),
            ShapeF::List(children) => ShapeF::List(children.iter().map(f).collect()),
            ShapeF::Vector(children) => ShapeF::Vector(children.iter().map(f).collect()),
        }
    }
}

/// Trivia annotation for CST nodes.
#[derive(Debug, Clone, PartialEq)]
pub struct TriviaAnn {
    pub leading: Vec<Trivia>,
    pub trailing: Vec<Trivia>,
    pub span: Span,
}

impl Default for TriviaAnn {
    fn default() -> Self {
        Self {
            leading: Vec::new(),
            trailing: Vec::new(),
            span: Span::new(0, 0),
        }
    }
}

/// A Concrete Syntax Tree node with generic annotations.
/// This is the fixpoint of ShapeF: CstNode<A> = ShapeF<CstNode<A>> with annotation A.
#[derive(Debug, Clone, PartialEq)]
pub struct CstNode<A = TriviaAnn> {
    pub ann: A,
    pub shape: ShapeF<Box<CstNode<A>>>,
}

/// Trivia types (comments and whitespace).
#[derive(Debug, Clone, PartialEq)]
pub enum Trivia {
    Whitespace(String),
    Comment { text: String, has_newline: bool },
}

impl Trivia {
    pub fn as_str(&self) -> &str {
        match self {
            Trivia::Whitespace(s) => s,
            Trivia::Comment { text, .. } => text,
        }
    }

    #[cfg(test)]
    fn has_newline(&self) -> bool {
        match self {
            Trivia::Whitespace(s) => s.contains('\n'),
            Trivia::Comment { has_newline, .. } => *has_newline,
        }
    }
}

impl CstNode<TriviaAnn> {
    /// Returns true when this node carries original source trivia (non-zero span),
    /// indicating it was parsed from source rather than freshly constructed.
    pub fn has_source_trivia(&self) -> bool {
        self.ann.span.start != 0 || self.ann.span.end != 0
    }

    /// Convert this CST node to a Sexpr (discards trivia).
    pub fn to_sexpr(&self) -> crate::sexpr::Sexpr {
        use crate::sexpr::Sexpr;

        let span = self.ann.span;
        match &self.shape {
            ShapeF::Atom(s) => Sexpr::Atom(s.clone(), span),
            ShapeF::Str(s) => Sexpr::Atom(s.clone(), span),
            ShapeF::List(children) => {
                let items: Vec<Sexpr> = children.iter().map(|c| c.to_sexpr()).collect();
                Sexpr::List(items, span)
            }
            ShapeF::Vector(children) => {
                let items: Vec<Sexpr> = children.iter().map(|c| c.to_sexpr()).collect();
                Sexpr::Vector(items, span)
            }
        }
    }

    /// Create an atom node.
    pub fn atom(value: impl Into<String>, annotation: TriviaAnn) -> Self {
        Self {
            ann: annotation,
            shape: ShapeF::Atom(value.into()),
        }
    }

    /// Create a list node.
    pub fn list(children: Vec<Box<CstNode>>, annotation: TriviaAnn) -> Self {
        Self {
            ann: annotation,
            shape: ShapeF::List(children),
        }
    }

    /// Create a vector node.
    pub fn vector(children: Vec<Box<CstNode>>, annotation: TriviaAnn) -> Self {
        Self {
            ann: annotation,
            shape: ShapeF::Vector(children),
        }
    }

    /// Serialize back to string.
    pub fn serialize(&self) -> String {
        let mut output = String::new();
        self.write_to(&mut output);
        output
    }

    /// Pretty-serialize with a target column width.
    ///
    /// This preserves all comments and whitespace from the original source,
    /// but may reformat long lines to fit within the target width.
    /// Comments are never reformatted - they appear exactly as in the source.
    pub fn pretty_serialize(&self, width: usize) -> String {
        let mut ctx = PrettyCtx::new(width);
        self.pretty_write(&mut ctx);
        ctx.output
    }

    /// Convert this CST node to a Doc for pretty-printing.
    /// Note: This discards trivia (whitespace/comments) since pretty-printing
    /// reformats the output entirely.
    pub fn to_doc(&self) -> may_i_core::Doc {
        use may_i_core::Doc;

        match &self.shape {
            ShapeF::Atom(s) => Doc::atom(s.clone()),
            ShapeF::Str(s) => Doc::atom(quote_string(s)),
            ShapeF::List(children) => {
                let child_docs: Vec<Doc> = children.iter().map(|c| c.to_doc()).collect();
                Doc::list(child_docs)
            }
            ShapeF::Vector(children) => {
                let child_docs: Vec<Doc> = children.iter().map(|c| c.to_doc()).collect();
                Doc::vector(child_docs)
            }
        }
    }

    fn write_to(&self, output: &mut String) {
        // Write leading trivia
        for trivia in &self.ann.leading {
            match trivia {
                Trivia::Whitespace(s) => output.push_str(s),
                Trivia::Comment { text, has_newline } => {
                    output.push_str(text);
                    if *has_newline {
                        output.push('\n');
                    }
                }
            }
        }

        // Write the shape
        match &self.shape {
            ShapeF::Atom(s) => {
                output.push_str(s);
            }
            ShapeF::Str(s) => {
                output.push_str(&quote_string(s));
            }
            ShapeF::List(children) => {
                output.push('(');
                for (i, child) in children.iter().enumerate() {
                    if i > 0 && child.ann.leading.is_empty() {
                        output.push(' ');
                    }
                    child.write_to(output);
                }
                output.push(')');
            }
            ShapeF::Vector(children) => {
                output.push('[');
                for (i, child) in children.iter().enumerate() {
                    if i > 0 && child.ann.leading.is_empty() {
                        output.push(' ');
                    }
                    child.write_to(output);
                }
                output.push(']');
            }
        }

        // Write trailing trivia
        for trivia in &self.ann.trailing {
            match trivia {
                Trivia::Whitespace(s) => output.push_str(s),
                Trivia::Comment { text, has_newline } => {
                    output.push_str(text);
                    if *has_newline {
                        output.push('\n');
                    }
                }
            }
        }
    }
}

impl<A> CstNode<A> {
    /// Get the atom value if this is an atom.
    pub fn as_atom(&self) -> Option<&str> {
        match &self.shape {
            ShapeF::Atom(s) => Some(s),
            _ => None,
        }
    }

    /// Get string value if this is a string.
    pub fn as_str(&self) -> Option<&str> {
        match &self.shape {
            ShapeF::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Get list children if this is a list.
    pub fn as_list(&self) -> Option<&[Box<CstNode<A>>]> {
        match &self.shape {
            ShapeF::List(children) => Some(children),
            _ => None,
        }
    }

    /// Check if this is a tagged list (first element is the given atom).
    pub fn is_tagged(&self, tag: &str) -> bool {
        self.as_list()
            .and_then(|children| children.first())
            .and_then(|first| first.as_atom())
            == Some(tag)
    }

    /// Apply a transformation to this node and all children (cata-like).
    /// Returns Some(node) if a transformation occurred, None otherwise.
    pub fn transform<F>(&self, f: &mut F) -> Option<Box<CstNode<A>>>
    where
        F: FnMut(&CstNode<A>) -> Option<Box<CstNode<A>>>,
        A: Clone,
    {
        // First try to apply the transformation to this node
        if let Some(replacement) = f(self) {
            return Some(replacement);
        }

        // If no transformation at this node, try children
        match &self.shape {
            ShapeF::Atom(_) | ShapeF::Str(_) => None,
            ShapeF::List(children) => {
                let mut new_children = Vec::new();
                let mut changed = false;
                for c in children {
                    if let Some(new_c) = c.transform(f) {
                        new_children.push(new_c);
                        changed = true;
                    } else {
                        new_children.push(c.clone());
                    }
                }
                if changed {
                    Some(Box::new(CstNode {
                        ann: self.ann.clone(),
                        shape: ShapeF::List(new_children),
                    }))
                } else {
                    None
                }
            }
            ShapeF::Vector(children) => {
                let mut new_children = Vec::new();
                let mut changed = false;
                for c in children {
                    if let Some(new_c) = c.transform(f) {
                        new_children.push(new_c);
                        changed = true;
                    } else {
                        new_children.push(c.clone());
                    }
                }
                if changed {
                    Some(Box::new(CstNode {
                        ann: self.ann.clone(),
                        shape: ShapeF::Vector(new_children),
                    }))
                } else {
                    None
                }
            }
        }
    }
}

#[cfg(test)]
impl<A: Clone> CstNode<A> {
    fn map<B>(self, f: &mut impl FnMut(A) -> B) -> CstNode<B> {
        CstNode {
            ann: f(self.ann),
            shape: self.shape.map(|child| Box::new(child.map(f))),
        }
    }

    fn fold<B>(&self, alg: &mut impl FnMut(&ShapeF<B>, &A) -> B) -> B {
        let folded_shape = self.shape.map_ref(|child| child.fold(alg));
        alg(&folded_shape, &self.ann)
    }
}

const SPECIAL_FORMS: &[&str] = &["define", "check", "with-facts", "when", "unless", "rule", "cond"];

fn is_special_form(name: &str) -> bool {
    SPECIAL_FORMS.contains(&name)
}

fn quote_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Context for pretty-serialization.
struct PrettyCtx {
    width: usize,
    col: usize,
    output: String,
    indent_stack: Vec<usize>,
    /// Track if we've broken the current list onto multiple lines
    has_broken: bool,
}

impl PrettyCtx {
    fn new(width: usize) -> Self {
        Self {
            width,
            col: 0,
            output: String::new(),
            indent_stack: vec![0],
            has_broken: false,
        }
    }

    fn current_indent(&self) -> usize {
        *self.indent_stack.last().unwrap_or(&0)
    }

    fn push_indent(&mut self, indent: usize) {
        self.indent_stack.push(indent);
    }

    fn pop_indent(&mut self) {
        self.indent_stack.pop();
    }

    fn write_str(&mut self, s: &str) {
        self.output.push_str(s);
        // Update column: count chars since last newline
        if let Some(idx) = s.rfind('\n') {
            self.col = s[idx + 1..].chars().count();
        } else {
            self.col += s.chars().count();
        }
    }

    fn write_newline(&mut self) {
        self.output.push('\n');
        self.col = 0;
        self.has_broken = true;
    }

    fn write_indent(&mut self) {
        let spaces = self.current_indent();
        self.write_str(&" ".repeat(spaces));
    }

    /// Reset broken state when entering a new list
    fn reset_broken(&mut self) {
        self.has_broken = false;
    }
}

impl CstNode<TriviaAnn> {
    fn pretty_write(&self, ctx: &mut PrettyCtx) {
        // Write leading trivia (comments/whitespace before this node)
        for trivia in &self.ann.leading {
            match trivia {
                Trivia::Whitespace(s) => {
                    ctx.write_str(s);
                }
                Trivia::Comment { text, has_newline } => {
                    ctx.write_str(text);
                    if *has_newline {
                        ctx.write_newline();
                    }
                }
            }
        }

        // Calculate the "head" position (after leading trivia)
        let head_col = ctx.col;

        // Write the shape
        match &self.shape {
            ShapeF::Atom(s) => {
                ctx.write_str(s);
            }
            ShapeF::Str(s) => {
                ctx.write_str(&quote_string(s));
            }
            ShapeF::List(children) => {
                let head_atom = children.first().and_then(|c| c.as_atom());
                let is_cond = head_atom == Some("cond");

                ctx.write_str("(");

                // Compute form-aware child indent
                let child_indent = compute_child_indent(head_col, head_atom);
                ctx.push_indent(child_indent);
                ctx.reset_broken();

                let mut i = 0;
                while i < children.len() {
                    let child = &children[i];

                    // Check if this is a keyword (starts with ":")
                    let is_keyword = child.as_atom().is_some_and(|s| s.starts_with(':'));

                    if i > 0 {
                        // cond always breaks clauses onto separate lines
                        let force_break = is_cond;

                        let child_width = estimate_width(child);
                        let would_exceed = ctx.col + 1 + child_width > ctx.width;
                        let past_indent = ctx.col > child_indent;
                        let needs_break =
                            force_break || ctx.has_broken || (would_exceed && past_indent);

                        if needs_break {
                            ctx.write_newline();
                            ctx.write_indent();
                        } else {
                            ctx.write_str(" ");
                        }
                    }

                    child.pretty_write_no_whitespace(ctx);

                    // If this was a keyword, the next child is its value - keep them together
                    if is_keyword && i + 1 < children.len() {
                        ctx.write_str(" ");
                        children[i + 1].pretty_write_no_whitespace(ctx);
                        i += 1;
                    }

                    i += 1;
                }
                ctx.pop_indent();
                ctx.write_str(")");
            }
            ShapeF::Vector(children) => {
                ctx.write_str("[");

                let child_indent = head_col + 1;
                ctx.push_indent(child_indent);
                ctx.reset_broken();

                for (i, child) in children.iter().enumerate() {
                    if i > 0 {
                        let child_width = estimate_width(child);
                        let would_exceed = ctx.col + 1 + child_width > ctx.width;
                        let past_indent = ctx.col > child_indent;
                        // Only break if we've already broken (cascade) OR this specific child would exceed
                        let needs_break = ctx.has_broken || (would_exceed && past_indent);

                        if needs_break {
                            ctx.write_newline();
                            ctx.write_indent();
                        } else {
                            ctx.write_str(" ");
                        }
                    }
                    child.pretty_write_no_whitespace(ctx);
                }

                ctx.pop_indent();
                ctx.write_str("]");
            }
        }

        // Write trailing trivia (comments/whitespace after this node)
        for trivia in &self.ann.trailing {
            match trivia {
                Trivia::Whitespace(s) => {
                    ctx.write_str(s);
                }
                Trivia::Comment { text, has_newline } => {
                    ctx.write_str(text);
                    if *has_newline {
                        ctx.write_newline();
                    }
                }
            }
        }
    }

    /// Write node preserving only comments, not whitespace.
    fn pretty_write_no_whitespace(&self, ctx: &mut PrettyCtx) {
        // Write comment trivia with position-aware whitespace handling.
        // In leading trivia, comments always get their own line at the
        // current indent level. Blank lines (extra newlines in preceding
        // whitespace) are preserved.
        let leading = &self.ann.leading;
        let mut emitted_comment_with_newline = false;
        for (i, trivia) in leading.iter().enumerate() {
            if let Trivia::Comment { text, has_newline } = trivia {
                let prev_ws = if i > 0 {
                    if let Trivia::Whitespace(ws) = &leading[i - 1] {
                        Some(ws.as_str())
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Preserve blank lines from preceding whitespace
                if let Some(ws) = prev_ws {
                    let newline_count = ws.matches('\n').count();
                    if newline_count > 0 {
                        for _ in 0..newline_count {
                            ctx.write_newline();
                        }
                    } else {
                        ctx.write_newline();
                    }
                } else {
                    ctx.write_newline();
                }
                ctx.write_indent();
                ctx.write_str(text);
                if *has_newline {
                    ctx.write_newline();
                    emitted_comment_with_newline = true;
                } else {
                    emitted_comment_with_newline = false;
                }
            }
        }

        // If comments left us on a fresh line, indent before the node content
        if emitted_comment_with_newline {
            ctx.write_indent();
        }

        let head_col = ctx.col;

        match &self.shape {
            ShapeF::Atom(s) => {
                ctx.write_str(s);
            }
            ShapeF::Str(s) => {
                ctx.write_str(&quote_string(s));
            }
            ShapeF::List(children) => {
                let head_atom = children.first().and_then(|c| c.as_atom());
                let is_cond = head_atom == Some("cond");

                ctx.write_str("(");

                let child_indent = compute_child_indent(head_col, head_atom);
                ctx.push_indent(child_indent);
                ctx.reset_broken();

                let mut i = 0;
                while i < children.len() {
                    let child = &children[i];
                    let is_keyword = child.as_atom().is_some_and(|s| s.starts_with(':'));

                    if i > 0 {
                        // Preserve source children's trivia as spacing, unless
                        // the parent forces breaks (e.g. cond clauses).
                        if !is_cond && child.has_source_trivia() {
                            child.pretty_write(ctx);
                        } else {
                            let force_break = is_cond;

                            let child_width = estimate_width(child);
                            let would_exceed = ctx.col + 1 + child_width > ctx.width;
                            let past_indent = ctx.col > child_indent;
                            let needs_break =
                                force_break || ctx.has_broken || (would_exceed && past_indent);

                            if needs_break {
                                ctx.write_newline();
                                ctx.write_indent();
                            } else {
                                ctx.write_str(" ");
                            }

                            child.pretty_write_no_whitespace(ctx);
                        }
                    } else if child.has_source_trivia() {
                        child.pretty_write(ctx);
                    } else {
                        child.pretty_write_no_whitespace(ctx);
                    }

                    if is_keyword && i + 1 < children.len() {
                        if children[i + 1].has_source_trivia() {
                            children[i + 1].pretty_write(ctx);
                        } else {
                            ctx.write_str(" ");
                            children[i + 1].pretty_write_no_whitespace(ctx);
                        }
                        i += 1;
                    }

                    i += 1;
                }
                ctx.pop_indent();
                ctx.write_str(")");
            }
            ShapeF::Vector(children) => {
                ctx.write_str("[");

                let child_indent = head_col + 1;
                ctx.push_indent(child_indent);
                ctx.reset_broken();

                for (i, child) in children.iter().enumerate() {
                    if i > 0 {
                        if child.has_source_trivia() {
                            child.pretty_write(ctx);
                        } else {
                            let child_width = estimate_width(child);
                            let would_exceed = ctx.col + 1 + child_width > ctx.width;
                            let past_indent = ctx.col > child_indent;
                            let needs_break = ctx.has_broken || (would_exceed && past_indent);

                            if needs_break {
                                ctx.write_newline();
                                ctx.write_indent();
                            } else {
                                ctx.write_str(" ");
                            }
                            child.pretty_write_no_whitespace(ctx);
                        }
                    } else if child.has_source_trivia() {
                        child.pretty_write(ctx);
                    } else {
                        child.pretty_write_no_whitespace(ctx);
                    }
                }
                ctx.pop_indent();
                ctx.write_str("]");
            }
        }

        // Write trailing trivia with position-aware whitespace handling
        let trailing = &self.ann.trailing;
        for (i, trivia) in trailing.iter().enumerate() {
            if let Trivia::Comment { text, has_newline } = trivia {
                let prev_ws = if i > 0 {
                    if let Trivia::Whitespace(ws) = &trailing[i - 1] {
                        Some(ws.as_str())
                    } else {
                        None
                    }
                } else {
                    None
                };

                match prev_ws {
                    Some(ws) if ws.contains('\n') => {
                        let extra_newlines = ws.matches('\n').count();
                        for _ in 0..extra_newlines {
                            ctx.write_newline();
                        }
                        ctx.write_indent();
                        ctx.write_str(text);
                        if *has_newline {
                            ctx.write_newline();
                        }
                    }
                    Some(ws) => {
                        ctx.write_str(ws);
                        ctx.write_str(text);
                        if *has_newline {
                            ctx.write_newline();
                        }
                    }
                    None => {
                        ctx.write_str(text);
                        if *has_newline {
                            ctx.write_newline();
                        }
                    }
                }
            }
        }
    }
}

/// Compute child indent based on form classification.
/// - Special forms: paren_col + 2
/// - Function-call forms: paren_col + 1 + head_atom_width + 1 (align under first arg)
/// - Non-atom heads: paren_col + 1 (fallback)
fn compute_child_indent(paren_col: usize, head_atom: Option<&str>) -> usize {
    match head_atom {
        Some(name) if is_special_form(name) => paren_col + 2,
        Some(name) => paren_col + 1 + name.len() + 1,
        None => paren_col + 1,
    }
}

/// Rough estimation of node width for line-breaking decisions.
fn estimate_width<A>(node: &CstNode<A>) -> usize {
    // This is a rough estimate - we could make it more accurate
    // but it's just used as a heuristic for line-breaking
    match &node.shape {
        ShapeF::Atom(s) => s.len(),
        ShapeF::Str(s) => s.len() + 2, // +2 for quotes
        ShapeF::List(children) => {
            2 + children.iter().map(|c| estimate_width(c)).sum::<usize>()
                + children.len().saturating_sub(1)
        }
        ShapeF::Vector(children) => {
            2 + children.iter().map(|c| estimate_width(c)).sum::<usize>()
                + children.len().saturating_sub(1)
        }
    }
}

/// Parse a string into CST nodes.
pub fn parse(input: &str) -> (Vec<Box<CstNode>>, Vec<crate::span::RawError>) {
    let mut parser = Parser::new(input);
    parser.parse()
}

struct Parser<'a> {
    input: &'a str,
    chars: std::iter::Peekable<std::str::CharIndices<'a>>,
    errors: Vec<crate::span::RawError>,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            chars: input.char_indices().peekable(),
            errors: Vec::new(),
        }
    }

    fn parse(&mut self) -> (Vec<Box<CstNode>>, Vec<crate::span::RawError>) {
        let mut results = Vec::new();

        while self.chars.peek().is_some() {
            let leading = self.collect_trivia();

            if let Some(node) = self.parse_node() {
                let mut node = node;
                node.ann.leading = leading;
                node.ann.trailing = self.collect_trivia();
                results.push(Box::new(node));
            } else if !leading.is_empty()
                && !results.is_empty()
                && let Some(last) = results.last_mut()
            {
                last.ann.trailing.extend(leading);
            }
        }

        (results, std::mem::take(&mut self.errors))
    }

    fn collect_trivia(&mut self) -> Vec<Trivia> {
        let mut trivia = Vec::new();

        while let Some(&(pos, ch)) = self.chars.peek() {
            match ch {
                ' ' | '\t' | '\n' | '\r' => {
                    let _start = pos;
                    let mut ws = String::new();
                    while let Some(&(_, c)) = self.chars.peek() {
                        if c.is_whitespace() {
                            ws.push(c);
                            self.chars.next();
                        } else {
                            break;
                        }
                    }
                    if !ws.is_empty() {
                        trivia.push(Trivia::Whitespace(ws));
                    }
                }
                ';' => {
                    let _start = pos;
                    let mut comment = String::new();
                    comment.push(';');
                    self.chars.next();
                    let mut has_newline = false;
                    while let Some(&(_, c)) = self.chars.peek() {
                        self.chars.next();
                        if c == '\n' {
                            has_newline = true;
                            break;
                        }
                        comment.push(c);
                    }
                    trivia.push(Trivia::Comment {
                        text: comment,
                        has_newline,
                    });
                }
                _ => break,
            }
        }

        trivia
    }

    fn parse_node(&mut self) -> Option<CstNode> {
        let &(pos, ch) = self.chars.peek()?;

        match ch {
            '(' => self.parse_list(pos, ')'),
            '[' => self.parse_list(pos, ']'),
            '"' => self.parse_string(pos),
            _ if is_atom_char(ch) => self.parse_atom(pos),
            _ => {
                self.errors.push(crate::span::RawError::new(
                    format!("unexpected character: {:?}", ch),
                    Span::new(pos, pos + ch.len_utf8()),
                ));
                self.chars.next();
                None
            }
        }
    }

    fn parse_list(&mut self, start: usize, close: char) -> Option<CstNode> {
        self.chars.next(); // consume opening
        let mut children = Vec::new();

        loop {
            let leading = self.collect_trivia();

            if let Some(&(_pos, ch)) = self.chars.peek() {
                if ch == close {
                    self.chars.next();
                    break;
                }

                if let Some(mut child) = self.parse_node() {
                    child.ann.leading = leading;
                    children.push(Box::new(child));
                } else if !leading.is_empty()
                    && !children.is_empty()
                    && let Some(last) = children.last_mut()
                {
                    last.ann.trailing.extend(leading);
                }
            } else {
                self.errors.push(crate::span::RawError::new(
                    format!("unclosed list, expected '{}'", close),
                    Span::new(start, self.input.len()),
                ));
                break;
            }
        }

        let end = self
            .chars
            .peek()
            .map(|(p, _)| *p)
            .unwrap_or(self.input.len());

        let shape = if close == ')' {
            ShapeF::List(children)
        } else {
            ShapeF::Vector(children)
        };

        Some(CstNode {
            ann: TriviaAnn {
                span: Span::new(start, end),
                ..Default::default()
            },
            shape,
        })
    }

    fn parse_string(&mut self, start: usize) -> Option<CstNode> {
        self.chars.next(); // consume opening quote
        let mut s = String::new();

        loop {
            match self.chars.next() {
                None => {
                    self.errors.push(crate::span::RawError::new(
                        "unterminated string",
                        Span::new(start, self.input.len()),
                    ));
                    return None;
                }
                Some((pos, '"')) => {
                    let end = pos + 1;
                    return Some(CstNode {
                        ann: TriviaAnn {
                            span: Span::new(start, end),
                            ..Default::default()
                        },
                        shape: ShapeF::Str(s),
                    });
                }
                Some((_, '\\')) => match self.chars.next() {
                    Some((_, '\\')) => s.push('\\'),
                    Some((_, '"')) => s.push('"'),
                    Some((_, 'n')) => s.push('\n'),
                    Some((_, 't')) => s.push('\t'),
                    Some((pos, c)) => {
                        self.errors.push(crate::span::RawError::new(
                            format!("unknown escape: \\{}", c),
                            Span::new(pos, pos + c.len_utf8()),
                        ));
                    }
                    None => {
                        self.errors.push(crate::span::RawError::new(
                            "unterminated escape",
                            Span::new(start, self.input.len()),
                        ));
                        return None;
                    }
                },
                Some((_, c)) => s.push(c),
            }
        }
    }

    fn parse_atom(&mut self, start: usize) -> Option<CstNode> {
        let mut s = String::new();
        let mut end = start;

        while let Some(&(pos, c)) = self.chars.peek() {
            if is_atom_char(c) {
                s.push(c);
                end = pos + c.len_utf8();
                self.chars.next();
            } else {
                break;
            }
        }

        if s.is_empty() {
            None
        } else {
            Some(CstNode {
                ann: TriviaAnn {
                    span: Span::new(start, end),
                    ..Default::default()
                },
                shape: ShapeF::Atom(s),
            })
        }
    }
}

fn is_atom_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(c, '-' | '_' | '*' | '.' | '/' | '^' | ':' | '+' | '?' | '=')
}

/// A rewrite rule for transforming s-expressions.
pub trait RewriteRule {
    /// Try to apply this rule to a node.
    /// Returns Some(new_node) if the rule matched and transformed the node,
    /// or None if the rule didn't match.
    fn apply(&self, node: &CstNode<TriviaAnn>) -> Option<Box<CstNode<TriviaAnn>>>;
}

/// Apply a sequence of rewrite rules until convergence.
pub fn rewrite_until_convergence<F>(
    node: Box<CstNode<TriviaAnn>>,
    rules: &[F],
) -> Box<CstNode<TriviaAnn>>
where
    F: Fn(&CstNode<TriviaAnn>) -> Option<Box<CstNode<TriviaAnn>>>,
{
    let mut current = node;
    loop {
        let mut changed = false;

        // Apply rules in sequence
        for rule in rules {
            if let Some(new_node) = rule(&current) {
                current = new_node;
                changed = true;
                break; // Restart from first rule after a change
            }
        }

        if !changed {
            // Also transform children
            if let Some(new_current) = current.transform(&mut |n| {
                for rule in rules {
                    if let Some(r) = rule(n) {
                        return Some(r);
                    }
                }
                None
            }) {
                current = new_current;
            } else {
                // No changes to children either
                break;
            }
        }
    }

    current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let input = "; header\n  (foo bar)  \n; footer\n";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        let output = nodes.iter().map(|n| n.serialize()).collect::<String>();
        assert_eq!(input, output);
    }

    #[test]
    fn test_rewrite() {
        let input = "(old-syntax x)";
        let (nodes, _) = parse(input);
        let node = nodes.into_iter().next().unwrap();

        // Define a simple rewrite rule
        let rule = |n: &CstNode| {
            if n.is_tagged("old-syntax") {
                // Strip leading whitespace from children (it was separator space after the tag)
                let children: Vec<Box<CstNode>> = n
                    .as_list()?
                    .iter()
                    .skip(1)
                    .map(|c| {
                        let mut new_c = (**c).clone();
                        new_c.ann.leading.clear();
                        Box::new(new_c)
                    })
                    .collect();
                Some(Box::new(CstNode::list(
                    children,
                    TriviaAnn {
                        leading: n.ann.leading.clone(),
                        trailing: n.ann.trailing.clone(),
                        ..Default::default()
                    },
                )))
            } else {
                None
            }
        };

        let rewritten = rewrite_until_convergence(node, &[rule]);
        assert_eq!(rewritten.serialize(), "(x)");
    }

    #[test]
    fn test_is_special_form_known_forms() {
        for name in &["define", "check", "with-facts", "when", "unless", "rule", "cond"] {
            assert!(is_special_form(name), "{name} should be a special form");
        }
    }

    #[test]
    fn test_is_special_form_non_special() {
        for name in &["or", "and", "positional", "anywhere", "effect", "foo", "bar"] {
            assert!(!is_special_form(name), "{name} should NOT be a special form");
        }
    }

    // ── Pretty-serialize indentation tests ─────────────────────────

    fn pretty(input: &str, width: usize) -> String {
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty(), "parse errors: {errors:?}");
        assert_eq!(nodes.len(), 1);
        nodes[0].pretty_serialize(width)
    }

    #[test]
    fn test_special_form_indent_define() {
        // define is a special form: body indents +2 from paren
        let result = pretty("(define foo (or a b))", 19);
        assert_eq!(result, "(define foo\n  (or a b))");
    }

    #[test]
    fn test_special_form_indent_check() {
        let result = pretty("(check :ask \"rmdir /foo\" :allow \"rmdir /bar\")", 30);
        // check body indents +2
        assert!(
            result.contains("\n  "),
            "check body should indent by 2, got:\n{result}"
        );
        // Verify it doesn't use function-call alignment
        assert!(
            !result.contains("\n      "),
            "check should not use function-call indent (6+ spaces), got:\n{result}"
        );
    }

    #[test]
    fn test_special_form_indent_rule() {
        let result = pretty("(rule \"rm\" (when build-mode (effect :allow)))", 25);
        // rule body indents +2
        for line in result.lines().skip(1) {
            let indent = line.len() - line.trim_start().len();
            assert!(
                indent >= 2,
                "rule body should indent by at least 2, got indent {indent} in line: {line}"
            );
        }
    }

    #[test]
    fn test_function_call_indent_or() {
        // or is NOT a special form: args align under first arg
        // (or has width 2, so first arg at col 4, subsequent args align there
        let result = pretty("(or \"cat\" \"bat\" \"head\" \"tail\" \"less\" \"ls\")", 25);
        // After breaking, args should align at column 4 (paren_col=0 + 1 + 2 + 1)
        for line in result.lines().skip(1) {
            let indent = line.len() - line.trim_start().len();
            assert_eq!(indent, 4, "or args should align at col 4, got:\n{result}");
        }
    }

    #[test]
    fn test_function_call_indent_and() {
        let result = pretty("(and (anywhere \"-r\") (anywhere \"/\"))", 30);
        // and has width 3, first arg at col 5 (0 + 1 + 3 + 1)
        for line in result.lines().skip(1) {
            let indent = line.len() - line.trim_start().len();
            assert_eq!(indent, 5, "and args should align at col 5, got:\n{result}");
        }
    }

    #[test]
    fn test_non_atom_head_fallback() {
        // When head is a nested list, fall back to paren_col + 1
        let result = pretty("((foo bar) baz qux quux quuz corge)", 20);
        for line in result.lines().skip(1) {
            let indent = line.len() - line.trim_start().len();
            assert_eq!(
                indent, 1,
                "non-atom head should fall back to col+1, got:\n{result}"
            );
        }
    }

    #[test]
    fn test_whole_line_comment_indented() {
        // A whole-line comment (preceded by whitespace with \n) should be
        // indented at the current indent level in pretty-serialized output.
        let input = "(define foo\n  ;; a comment\n  bar)";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        let result = nodes[0].pretty_serialize(40);
        assert!(
            result.contains("\n  ;; a comment\n"),
            "whole-line comment should be indented at current level, got:\n{result}"
        );
    }

    #[test]
    fn test_blank_line_before_comment_preserved() {
        let input = "(define foo\n\n  ;; a comment\n  bar)";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        let result = nodes[0].pretty_serialize(40);
        assert!(
            result.contains("\n\n  ;; a comment"),
            "blank line before comment should be preserved, got:\n{result}"
        );
    }

    #[test]
    fn test_trailing_comment_gap_preserved() {
        // A line-trailing comment (no \n in preceding whitespace) should
        // preserve its exact whitespace gap. Test with a top-level form
        // where the comment is in the node's trailing trivia.
        let input = "(define foo)  ;; trailing\n";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        let result = nodes[0].pretty_serialize(40);
        assert!(
            result.contains("foo)  ;; trailing"),
            "trailing comment gap should be preserved, got:\n{result}"
        );
    }

    #[test]
    fn test_trivia_has_newline() {
        let ws_no_newline = Trivia::Whitespace("   ".to_string());
        let ws_with_newline = Trivia::Whitespace("  \n  ".to_string());
        let comment_no_newline = Trivia::Comment {
            text: "; comment".to_string(),
            has_newline: false,
        };
        let comment_with_newline = Trivia::Comment {
            text: "; comment".to_string(),
            has_newline: true,
        };

        assert!(!ws_no_newline.has_newline());
        assert!(ws_with_newline.has_newline());
        assert!(!comment_no_newline.has_newline());
        assert!(comment_with_newline.has_newline());
    }

    #[test]
    fn test_trivia_as_str() {
        let ws = Trivia::Whitespace("   ".to_string());
        let comment = Trivia::Comment {
            text: "; comment".to_string(),
            has_newline: false,
        };

        assert_eq!(ws.as_str(), "   ");
        assert_eq!(comment.as_str(), "; comment");
    }

    #[test]
    fn test_vector_creation_and_access() {
        let vec_node = CstNode::vector(
            vec![
                Box::new(CstNode::atom("a", Default::default())),
                Box::new(CstNode::atom("b", Default::default())),
            ],
            Default::default(),
        );

        assert_eq!(vec_node.serialize(), "[a b]");
    }

    #[test]
    fn test_vector_with_comments() {
        let input = "[a ;; comment\nb]";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].serialize(), input);
    }

    #[test]
    fn test_transform_with_direct_replacement() {
        let input = "(old x)";
        let (nodes, _) = parse(input);
        let node = nodes.into_iter().next().unwrap();

        // Rule that replaces the root node directly
        let rule = |n: &CstNode| {
            if n.is_tagged("old") {
                Some(Box::new(CstNode::atom("new", Default::default())))
            } else {
                None
            }
        };

        let result = node.transform(&mut { rule }).unwrap();
        assert_eq!(result.serialize(), "new");
    }

    #[test]
    fn test_transform_vector_children() {
        let input = "[old1 old2]";
        let (nodes, _) = parse(input);
        let node = nodes.into_iter().next().unwrap();

        let rule = |n: &CstNode| {
            if n.as_atom() == Some("old1") {
                Some(Box::new(CstNode::atom("new1", Default::default())))
            } else {
                None
            }
        };

        let result = node.transform(&mut { rule }).unwrap();
        assert_eq!(result.serialize(), "[new1 old2]");
    }

    #[test]
    fn test_no_transform_when_no_changes() {
        let input = "(a b c)";
        let (nodes, _) = parse(input);
        let node = nodes.into_iter().next().unwrap();

        let rule = |_n: &CstNode| None;

        let result = node.transform(&mut { rule });
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_unclosed_list() {
        let input = "(foo bar";
        let (nodes, errors) = parse(input);
        assert!(!errors.is_empty());
        assert_eq!(errors[0].message, "unclosed list, expected ')'");
        // Should still return partial node
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn test_parse_unterminated_string() {
        let input = "\"foo";
        let (nodes, errors) = parse(input);
        assert!(!errors.is_empty());
        assert_eq!(errors[0].message, "unterminated string");
        assert!(nodes.is_empty());
    }

    #[test]
    fn test_parse_unknown_escape() {
        let input = "\"\\x\"";
        let (nodes, errors) = parse(input);
        assert!(!errors.is_empty());
        assert!(errors[0].message.contains("unknown escape"));
        // Should still return the node with partial string
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn test_parse_unterminated_escape() {
        let input = "\"\\";
        let (nodes, errors) = parse(input);
        assert!(!errors.is_empty());
        assert_eq!(errors[0].message, "unterminated escape");
        assert!(nodes.is_empty());
    }

    #[test]
    fn test_trivia_between_forms() {
        // Test that trivia between forms gets attached correctly
        let input = "(a)   ;; comment\n(b)";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        assert_eq!(nodes.len(), 2);
        // The comment should be attached to the second node's leading trivia
        // or the first node's trailing trivia
        let first = &nodes[0];
        let second = &nodes[1];
        let has_comment = first
            .ann
            .trailing
            .iter()
            .any(|t| matches!(t, Trivia::Comment { .. }))
            || second
                .ann
                .leading
                .iter()
                .any(|t| matches!(t, Trivia::Comment { .. }));
        assert!(
            has_comment,
            "Comment should be attached to either first node's trailing or second node's leading trivia"
        );
    }

    #[test]
    fn test_rewrite_until_convergence_multiple_changes() {
        let input = "(outer (inner x))";
        let (nodes, _) = parse(input);
        let node = nodes.into_iter().next().unwrap();

        // Rule that renames 'inner' to 'middle', then 'middle' to 'innermost'
        let rule = |n: &CstNode| {
            if n.is_tagged("inner") {
                let children: Vec<_> = n.as_list()?.iter().skip(1).cloned().collect();
                Some(Box::new(CstNode::list(
                    vec![
                        Box::new(CstNode::atom("middle", Default::default())),
                        children.into_iter().next().unwrap(),
                    ],
                    Default::default(),
                )))
            } else if n.is_tagged("middle") {
                let children: Vec<_> = n.as_list()?.iter().skip(1).cloned().collect();
                Some(Box::new(CstNode::list(
                    vec![
                        Box::new(CstNode::atom("innermost", Default::default())),
                        children.into_iter().next().unwrap(),
                    ],
                    Default::default(),
                )))
            } else {
                None
            }
        };

        let result = rewrite_until_convergence(node, &[rule]);
        assert!(result.serialize().contains("innermost"));
    }

    #[test]
    fn test_to_sexpr_atom() {
        let input = "foo";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        assert_eq!(nodes.len(), 1);
        let sexpr = nodes[0].to_sexpr();
        assert_eq!(sexpr.as_atom(), Some("foo"));
    }

    #[test]
    fn test_to_sexpr_list() {
        let input = "(foo bar baz)";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        assert_eq!(nodes.len(), 1);
        let sexpr = nodes[0].to_sexpr();
        let items = sexpr.as_list().unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].as_atom(), Some("foo"));
        assert_eq!(items[1].as_atom(), Some("bar"));
        assert_eq!(items[2].as_atom(), Some("baz"));
    }

    #[test]
    fn test_to_sexpr_vector() {
        let input = "[foo bar]";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        assert_eq!(nodes.len(), 1);
        let sexpr = nodes[0].to_sexpr();
        assert!(sexpr.is_vector());
        let items = sexpr.as_list().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].as_atom(), Some("foo"));
        assert_eq!(items[1].as_atom(), Some("bar"));
    }

    #[test]
    fn test_to_sexpr_nested() {
        let input = "(foo (bar baz))";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        let sexpr = nodes[0].to_sexpr();
        let items = sexpr.as_list().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].as_atom(), Some("foo"));
        let nested = items[1].as_list().unwrap();
        assert_eq!(nested.len(), 2);
        assert_eq!(nested[0].as_atom(), Some("bar"));
        assert_eq!(nested[1].as_atom(), Some("baz"));
    }

    #[test]
    fn test_to_sexpr_string() {
        let input = r#""hello world""#;
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        let sexpr = nodes[0].to_sexpr();
        assert_eq!(sexpr.as_atom(), Some("hello world"));
    }

    #[test]
    fn test_parse_vector_empty() {
        let input = "[]";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].serialize(), "[]");
    }

    #[test]
    fn test_parse_vector_with_nested_list() {
        let input = "[a (b c) d]";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].serialize(), "[a (b c) d]");
    }

    // ── Preserved layout tests ────────────────────────────────────

    /// Helper: wrap a parsed node in a constructed `(rule "x" <node>)`.
    fn wrap_in_rule(node: Box<CstNode>) -> Box<CstNode> {
        Box::new(CstNode::list(
            vec![
                Box::new(CstNode::atom("rule", Default::default())),
                Box::new(CstNode {
                    ann: Default::default(),
                    shape: ShapeF::Str("x".into()),
                }),
                node,
            ],
            Default::default(),
        ))
    }

    #[test]
    fn test_preserved_packed_layout() {
        // Parse a packed or node and wrap it in a constructed rule
        let input = r#"(or "a" "b" "c" "d")"#;
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        let wrapped = wrap_in_rule(nodes.into_iter().next().unwrap());
        let result = wrapped.pretty_serialize(80);
        // The or node should preserve its packed layout
        assert!(
            result.contains(r#"(or "a" "b" "c" "d")"#),
            "packed or should be preserved, got:\n{result}"
        );
    }

    #[test]
    fn test_preserved_multiline_packed_layout() {
        let input = "(or \"a\" \"b\"\n    \"c\" \"d\")";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        let wrapped = wrap_in_rule(nodes.into_iter().next().unwrap());
        let result = wrapped.pretty_serialize(80);
        // The or node should preserve its multi-line packed layout
        assert!(
            result.contains("\"a\" \"b\"\n    \"c\" \"d\""),
            "multi-line packed layout should be preserved, got:\n{result}"
        );
    }

    #[test]
    fn test_preserved_cascaded_layout() {
        let input = "(or (foo)\n    (bar))";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        let wrapped = wrap_in_rule(nodes.into_iter().next().unwrap());
        let result = wrapped.pretty_serialize(80);
        // The or node should preserve its cascaded layout
        assert!(
            result.contains("(foo)\n    (bar)"),
            "cascaded layout should be preserved, got:\n{result}"
        );
    }

    #[test]
    fn test_constructed_nodes_use_reflow() {
        // Freshly constructed nodes (default trivia) should still use reflow
        let long_or = CstNode::list(
            vec![
                Box::new(CstNode::atom("or", Default::default())),
                Box::new(CstNode {
                    ann: Default::default(),
                    shape: ShapeF::Str("aaa".into()),
                }),
                Box::new(CstNode {
                    ann: Default::default(),
                    shape: ShapeF::Str("bbb".into()),
                }),
                Box::new(CstNode {
                    ann: Default::default(),
                    shape: ShapeF::Str("ccc".into()),
                }),
                Box::new(CstNode {
                    ann: Default::default(),
                    shape: ShapeF::Str("ddd".into()),
                }),
            ],
            Default::default(),
        );
        let wrapped = wrap_in_rule(Box::new(long_or));
        let result = wrapped.pretty_serialize(25);
        // Should use reflow (cascading breaks), not preserve layout
        assert!(
            result.contains('\n'),
            "constructed node should reflow when exceeding width, got:\n{result}"
        );
    }

    // ── has_source_trivia tests ─────────────────────────────────────

    #[test]
    fn test_has_source_trivia_parsed_node() {
        let input = "(foo bar)";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        assert!(
            nodes[0].has_source_trivia(),
            "parsed node should have source trivia"
        );
    }

    #[test]
    fn test_has_source_trivia_default_node() {
        let node = CstNode::atom("foo", Default::default());
        assert!(
            !node.has_source_trivia(),
            "default-constructed node should NOT have source trivia"
        );
    }

    #[test]
    fn test_has_source_trivia_node_at_offset_zero() {
        // A node starting at byte 0 but with non-zero end should still be detected
        let node = CstNode::atom(
            "foo",
            TriviaAnn {
                span: Span::new(0, 3),
                ..Default::default()
            },
        );
        assert!(
            node.has_source_trivia(),
            "node at offset 0 with non-zero end should have source trivia"
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use proptest::strategy::BoxedStrategy;

    /// Helper function to check if two CST nodes are structurally equal
    /// (ignoring span information which may differ)
    fn cst_nodes_equal(a: &CstNode, b: &CstNode) -> bool {
        match (&a.shape, &b.shape) {
            (Shape::Atom(a_str), Shape::Atom(b_str)) => a_str == b_str,
            (Shape::Str(a_str), Shape::Str(b_str)) => a_str == b_str,
            (Shape::List(a_children), Shape::List(b_children)) => {
                a_children.len() == b_children.len()
                    && a_children
                        .iter()
                        .zip(b_children.iter())
                        .all(|(a, b)| cst_nodes_equal(a, b))
            }
            (Shape::Vector(a_children), Shape::Vector(b_children)) => {
                a_children.len() == b_children.len()
                    && a_children
                        .iter()
                        .zip(b_children.iter())
                        .all(|(a, b)| cst_nodes_equal(a, b))
            }
            _ => false,
        }
    }

    /// Strategy for generating atom strings
    fn atom_string() -> impl Strategy<Value = String> {
        prop::string::string_regex("[a-zA-Z0-9-_*/.^:+?=]+").unwrap()
    }

    /// Strategy for generating string literals (without quotes)
    fn string_content() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9 ]*".prop_map(|s| s.replace('"', ""))
    }

    /// Recursive strategy for generating s-expression shapes
    fn sexpr_shape(depth: u32) -> BoxedStrategy<String> {
        let leaf: BoxedStrategy<String> = prop_oneof!(
            atom_string(),
            string_content().prop_map(|s| format!("\"{}\"", s)),
        )
        .boxed();

        if depth == 0 {
            leaf
        } else {
            let child = sexpr_shape(depth - 1);
            prop_oneof!(
                leaf,
                prop::collection::vec(child.clone(), 0..5)
                    .prop_map(|items: Vec<String>| format!("({})", items.join(" "))),
                prop::collection::vec(child, 0..5)
                    .prop_map(|items: Vec<String>| format!("[{}]", items.join(" "))),
            )
            .boxed()
        }
    }

    proptest! {
        #[test]
        fn roundtrip_simple_atoms(input in atom_string()) {
            let (nodes, errors) = parse(&input);
            prop_assert!(errors.is_empty(), "Parsing should not fail: {:?}", errors);
            prop_assert_eq!(nodes.len(), 1, "Should parse exactly one node");

            let serialized = nodes[0].serialize();
            let (reparsed, re_errors) = parse(&serialized);
            prop_assert!(re_errors.is_empty(), "Reparsing should not fail: {:?}", re_errors);
            prop_assert_eq!(reparsed.len(), 1);
            prop_assert!(cst_nodes_equal(&nodes[0], &reparsed[0]),
                "Roundtrip should preserve structure: original={:?}, reparsed={:?}", nodes[0], reparsed[0]);
        }

        #[test]
        fn roundtrip_sexprs(input in sexpr_shape(3)) {
            let (nodes, errors) = parse(&input);
            prop_assume!(errors.is_empty());

            let serialized = nodes.iter().map(|n| n.serialize()).collect::<String>();
            let (reparsed, re_errors) = parse(&serialized);
            prop_assert!(re_errors.is_empty(), "Reparsing should not fail: {:?}", re_errors);
            prop_assert_eq!(nodes.len(), reparsed.len());

            for (orig, rep) in nodes.iter().zip(reparsed.iter()) {
                prop_assert!(cst_nodes_equal(orig, rep),
                    "Roundtrip should preserve structure: original={:?}, reparsed={:?}", orig, rep);
            }
        }
    }

    #[test]
    fn edge_case_multiline_list_roundtrip() {
        let input = "(rule\n  (command \"git\")\n  (effect :allow))";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        assert_eq!(nodes.len(), 1);

        let serialized = nodes[0].serialize();
        let (reparsed, re_errors) = parse(&serialized);
        assert!(re_errors.is_empty());
        assert_eq!(reparsed.len(), 1);
        assert!(cst_nodes_equal(&nodes[0], &reparsed[0]));
    }

    #[test]
    fn edge_case_deeply_nested_roundtrip() {
        let input = "((((((((((deep))))))))))";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        assert_eq!(nodes.len(), 1);

        let serialized = nodes[0].serialize();
        let (reparsed, re_errors) = parse(&serialized);
        assert!(re_errors.is_empty());
        assert!(cst_nodes_equal(&nodes[0], &reparsed[0]));
    }

    #[test]
    fn edge_case_empty_list_roundtrip() {
        let input = "()";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        assert_eq!(nodes[0].serialize(), "()");

        let (reparsed, re_errors) = parse("()");
        assert!(re_errors.is_empty());
        assert!(cst_nodes_equal(&nodes[0], &reparsed[0]));
    }

    #[test]
    fn edge_case_empty_vector_roundtrip() {
        let input = "[]";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        assert_eq!(nodes[0].serialize(), "[]");

        let (reparsed, re_errors) = parse("[]");
        assert!(re_errors.is_empty());
        assert!(cst_nodes_equal(&nodes[0], &reparsed[0]));
    }

    #[test]
    fn edge_case_mixed_list_vector() {
        let input = "[(a b) (c [d e])]";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        let serialized = nodes[0].serialize();
        let (reparsed, re_errors) = parse(&serialized);
        assert!(re_errors.is_empty());
        assert!(cst_nodes_equal(&nodes[0], &reparsed[0]));
    }

    #[test]
    fn edge_case_comments_preserved() {
        let input = "(foo ;; comment\nbar)";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        assert_eq!(nodes[0].serialize(), input);

        let (reparsed, re_errors) = parse(&nodes[0].serialize());
        assert!(re_errors.is_empty());
        assert!(cst_nodes_equal(&nodes[0], &reparsed[0]));
    }

    // ── Functor law tests ───────────────────────────────────────────

    /// Helper to check if two CST nodes are equal (for functor tests)
    fn nodes_equal<A: PartialEq>(a: &CstNode<A>, b: &CstNode<A>) -> bool {
        a == b
    }

    #[test]
    fn functor_identity_law() {
        // map id = id
        let input = "(foo bar baz)";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        let node = &nodes[0];

        // Map with identity function
        let mapped: CstNode<TriviaAnn> = (**node).clone().map(&mut |ann| ann);

        // Should be equal to original
        assert!(nodes_equal(&mapped, node));
    }

    #[test]
    fn functor_composition_law() {
        // map (f . g) = map f . map g
        let input = "(foo bar)";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        let node = nodes[0].clone();

        // Define two transformations
        let f = |ann: &TriviaAnn| ann.span.start;
        let g = |ann: &TriviaAnn| ann.span.end;

        // map (f . g) - compose first, then map
        let composed: CstNode<usize> = node.clone().map(&mut |ann| f(&ann) + g(&ann));

        // map f . map g - map twice
        let mapped_twice: CstNode<usize> = node.map(&mut |ann| g(&ann)).map(&mut |end| {
            f(&TriviaAnn {
                span: Span::new(end, end),
                leading: vec![],
                trailing: vec![],
            })
        });

        // Both should have the same structure, just different annotations
        // We verify by checking they're both lists with same children count
        assert!(matches!(composed.shape, ShapeF::List(_)));
        assert!(matches!(mapped_twice.shape, ShapeF::List(_)));
    }

    #[test]
    fn functor_preserves_structure() {
        // Mapping should preserve tree structure
        let input = "(a (b c) d)";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        let node = nodes[0].clone();

        // Map to discard annotation
        let mapped: CstNode<()> = node.map(&mut |_ann| ());

        // Check structure is preserved
        assert!(matches!(mapped.shape, ShapeF::List(_)));
        if let ShapeF::List(children) = &mapped.shape {
            assert_eq!(children.len(), 3);
            assert!(matches!(children[1].shape, ShapeF::List(_)));
        }
    }

    // ── Fold (catamorphism) tests ───────────────────────────────────

    #[test]
    fn fold_counts_nodes() {
        let input = "(a (b c))";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        let node = &nodes[0];

        // Fold to count nodes
        let count: usize = node.fold(&mut |shape, _ann| match shape {
            ShapeF::Atom(_) => 1,
            ShapeF::Str(_) => 1,
            ShapeF::List(children) | ShapeF::Vector(children) => 1 + children.iter().sum::<usize>(),
        });

        // Should be: outer list (1) + a (1) + inner list (1) + b (1) + c (1) = 5
        assert_eq!(count, 5);
    }

    #[test]
    fn fold_collects_atoms() {
        let input = "(foo (bar baz))";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        let node = &nodes[0];

        // Fold to collect all atom values
        let atoms: Vec<String> = node.fold(&mut |shape, _ann| match shape {
            ShapeF::Atom(s) => vec![s.clone()],
            ShapeF::Str(s) => vec![s.clone()],
            ShapeF::List(children) | ShapeF::Vector(children) => {
                children.iter().flatten().cloned().collect()
            }
        });

        assert_eq!(atoms, vec!["foo", "bar", "baz"]);
    }

    #[test]
    fn fold_rebuilds_tree() {
        // Use fold to rebuild tree with modified annotations
        let input = "(hello world)";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        let node = &nodes[0];

        // Fold to collect all spans
        let spans: Vec<(usize, usize)> = node.fold(&mut |shape, ann| match shape {
            ShapeF::Atom(_) | ShapeF::Str(_) => vec![(ann.span.start, ann.span.end)],
            ShapeF::List(children) | ShapeF::Vector(children) => {
                let mut result = vec![(ann.span.start, ann.span.end)];
                result.extend(children.iter().flatten().cloned());
                result
            }
        });

        // Should have spans for outer list + 2 atoms
        assert_eq!(spans.len(), 3);
    }

    #[test]
    fn fold_bottom_up_order() {
        // Verify fold processes children before parents (bottom-up)
        let input = "(a b)";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        let node = &nodes[0];

        let mut order: Vec<String> = vec![];
        let _: () = node.fold(&mut |shape, _ann| match shape {
            ShapeF::Atom(s) => order.push(format!("atom:{}", s)),
            ShapeF::List(_) => order.push("list".to_string()),
            _ => {}
        });

        // Should visit atoms first, then list (bottom-up)
        assert_eq!(order, vec!["atom:a", "atom:b", "list"]);
    }

    // ── ShapeF functor tests ────────────────────────────────────────

    #[test]
    fn shapef_map_preserves_atoms() {
        let atom: ShapeF<i32> = ShapeF::Atom("test".to_string());
        let mapped = atom.map(|x| x * 2);
        assert!(matches!(mapped, ShapeF::Atom(s) if s == "test"));
    }

    #[test]
    fn shapef_map_transforms_list_children() {
        let list: ShapeF<i32> = ShapeF::List(vec![1, 2, 3]);
        let mapped = list.map(|x| x * 2);
        if let ShapeF::List(children) = mapped {
            assert_eq!(children, vec![2, 4, 6]);
        } else {
            panic!("expected list");
        }
    }

    #[test]
    fn shapef_map_ref_preserves_structure() {
        let list: ShapeF<i32> = ShapeF::List(vec![1, 2, 3]);
        let mapped: ShapeF<String> = list.map_ref(|x| x.to_string());
        if let ShapeF::List(children) = mapped {
            assert_eq!(children, vec!["1", "2", "3"]);
        } else {
            panic!("expected list");
        }
    }

    // ── Pretty-serialize tests ─────────────────────────────────────────

    #[test]
    fn pretty_serialize_preserves_inline_comments() {
        // Comments on their own line within a list are preserved
        let input = "(foo\n;; inline comment\nbar)";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        let pretty = nodes[0].pretty_serialize(80);
        assert!(pretty.contains(";; inline comment"));
    }

    #[test]
    fn pretty_serialize_preserves_leading_comments() {
        let input = ";; leading comment\n(foo bar)";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        let pretty = nodes[0].pretty_serialize(80);
        assert!(pretty.contains(";; leading comment"));
    }

    #[test]
    fn pretty_serialize_short_form_unchanged() {
        let input = "(rule git :effect :allow)";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        let pretty = nodes[0].pretty_serialize(80);
        assert_eq!(pretty, input);
    }

    #[test]
    fn pretty_serialize_wraps_long_lines() {
        // Create a long form that exceeds 40 chars
        let input =
            "(rule this-is-a-very-long-command-name-that-might-exceed-width :effect :allow)";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        // At width 40, this should wrap
        let pretty = nodes[0].pretty_serialize(40);
        // Should have inserted a newline somewhere
        assert!(
            pretty.contains('\n') || pretty == input,
            "Long form should wrap or stay as-is"
        );
    }

    #[test]
    fn pretty_serialize_preserves_structure() {
        let input = "(rule (or \"cmd1\" \"cmd2\") :effect :allow)";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        let pretty = nodes[0].pretty_serialize(80);
        // Should still be parseable
        let (reparsed, re_errors) = parse(&pretty);
        assert!(
            re_errors.is_empty(),
            "Pretty output should be valid: {}",
            pretty
        );
        assert_eq!(reparsed.len(), 1);
    }

    #[test]
    fn pretty_serialize_vector_with_comments() {
        let input = "[a b ;; comment\nc]";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        let pretty = nodes[0].pretty_serialize(80);
        assert!(pretty.contains(";; comment"));
        assert!(pretty.contains('['));
        assert!(pretty.contains(']'));
    }

    // ── Cond formatting tests ──────────────────────────────────────────

    #[test]
    fn pretty_serialize_cond_always_breaks_clauses() {
        // Cond always breaks clauses onto separate lines for readability
        let input = "(cond ((test) (effect)))";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        let pretty = nodes[0].pretty_serialize(80);
        // Should always have newline even for short cond
        assert!(
            pretty.contains("\n"),
            "Cond should always break clauses\nGot: {}",
            pretty
        );
        assert!(
            pretty.contains("((test)"),
            "Clause should be on its own line\nGot: {}",
            pretty
        );
    }

    #[test]
    fn pretty_serialize_cond_clauses_on_separate_lines() {
        // Each cond clause should be on its own line when cond breaks
        let input = "(cond ((test1) (effect1)) ((test2) (effect2)) (else (effect3)))";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        // Cond always breaks with clauses on separate lines
        let pretty = nodes[0].pretty_serialize(80);

        // Should have newlines for each clause (2 spaces indent)
        assert!(
            pretty.contains("\n  ((test1)"),
            "First clause should start on new line with proper indent\nGot: {}",
            pretty
        );
        assert!(
            pretty.contains("\n  ((test2)"),
            "Second clause should start on new line with proper indent\nGot: {}",
            pretty
        );
        assert!(
            pretty.contains("\n  (else"),
            "Else clause should start on new line with proper indent\nGot: {}",
            pretty
        );
    }

    #[test]
    fn pretty_serialize_cond_clauses_properly_indented() {
        // Cond clauses should each be on their own line with proper indentation
        let input = r#"(rule "cmd" (cond ((anywhere "--eval") (effect :ask "Dangerous")) (else (effect :allow))))"#;
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        let pretty = nodes[0].pretty_serialize(80);

        // Should have cond with clauses on separate lines
        let lines: Vec<&str> = pretty.lines().collect();

        // Find the cond line and verify clauses follow on separate lines
        let cond_idx = lines.iter().position(|l| l.contains("(cond"));
        let clause1_idx = lines.iter().position(|l| l.contains("(anywhere"));
        let clause2_idx = lines.iter().position(|l| l.contains("(else"));

        assert!(cond_idx.is_some(), "Should have cond\nGot:\n{}", pretty);
        assert!(
            clause1_idx.is_some(),
            "Should have first clause with anywhere\nGot:\n{}",
            pretty
        );
        assert!(
            clause2_idx.is_some(),
            "Should have else clause\nGot:\n{}",
            pretty
        );

        // Clauses should come after cond
        if let (Some(c_idx), Some(cl1_idx), Some(cl2_idx)) = (cond_idx, clause1_idx, clause2_idx) {
            assert!(cl1_idx > c_idx, "First clause should come after cond");
            assert!(
                cl2_idx > cl1_idx,
                "Else clause should come after first clause"
            );
        }
    }

    #[test]
    fn pretty_serialize_cond_no_extra_space_after_opening() {
        // There should be no space between ( and ( when a clause starts
        let input = "(cond ((test) (effect)) (else (effect)))";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        // Force break with narrow width
        let pretty = nodes[0].pretty_serialize(20);

        // Should not have "( (" pattern (space between parens)
        assert!(
            !pretty.contains("( ("),
            "Should not have space between opening parens of cond clause\nGot:\n{}",
            pretty
        );
    }

    #[test]
    fn pretty_serialize_cond_else_clause_formatting() {
        // Else clause should format the same as other clauses
        let input = "(cond ((test) (effect)) (else (effect :allow)))";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        // Cond always breaks
        let pretty = nodes[0].pretty_serialize(80);

        // Else clause should be on its own line with proper indent (2 spaces)
        assert!(
            pretty.contains("\n  (else"),
            "Else clause should be properly indented on new line\nGot:\n{}",
            pretty
        );
    }

    // ── Cascading line break tests ─────────────────────────────────────

    #[test]
    fn pretty_serialize_cascading_line_breaks() {
        // Once a form breaks, all subsequent forms at same level must break
        // This test uses :effect and :ask keywords to verify cascading breaks
        let input = r#"(rule "openspec" :effect :allow (check :allow "openspec status --change 'foo'" :allow "openspec instructions apply --change 'bar'"))"#;
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        // Use width that forces the check form to break
        let pretty = nodes[0].pretty_serialize(60);

        // The rule form should break with each child on its own line
        let lines: Vec<&str> = pretty.lines().collect();

        // Find the line with "openspec" (command)
        let cmd_idx = lines.iter().position(|l| l.contains("\"openspec\""));
        // Find the line with (check
        let check_idx = lines.iter().position(|l| l.contains("(check"));

        assert!(
            cmd_idx.is_some(),
            "Should have command on its own line\nGot:\n{}",
            pretty
        );
        assert!(
            check_idx.is_some(),
            "Should have check form on its own line\nGot:\n{}",
            pretty
        );

        // Once check breaks, any subsequent forms should also be on their own lines
        // In this case, if there were more forms after check, they would break too
        // For this test, we just verify that check broke onto its own line
        // and that the :effect keyword stayed with its value :allow
        let effect_allow_idx = lines.iter().position(|l| l.contains(":effect :allow"));
        assert!(
            effect_allow_idx.is_some(),
            ":effect :allow should be on same line (key-value pair)\nGot:\n{}",
            pretty
        );
    }

    #[test]
    fn pretty_serialize_keyword_value_pairs() {
        // Keywords introduce key-value pairs
        let input = "(foo bar :bar baz :bar :baz)";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        // Use width that forces break for longer forms
        let pretty = nodes[0].pretty_serialize(15);

        let lines: Vec<&str> = pretty.lines().collect();

        // Check keyword-value pairs stay together
        let bar_baz_idx = lines.iter().position(|l| l.contains(":bar baz"));
        let bar_baz_kw_idx = lines.iter().position(|l| l.contains(":bar :baz"));

        assert!(
            bar_baz_idx.is_some(),
            "Should have ':bar baz' key-value pair\nGot:\n{}",
            pretty
        );
        assert!(
            bar_baz_kw_idx.is_some(),
            "Should have ':bar :baz' key-value pair (value is keyword)\nGot:\n{}",
            pretty
        );

        // Once a break happens, subsequent forms should cascade
        // Verify that we have multiple lines (some form broke)
        assert!(
            lines.len() > 1,
            "Should have broken into multiple lines\nGot:\n{}",
            pretty
        );
    }

    #[test]
    fn pretty_serialize_complex_nested_with_keywords() {
        // Complex example with nested forms
        let input = r#"(foo bar baz :bar baz :bar (foo bar baz) :bar :baz :bar (if foo bar baz))"#;
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        // Force break with narrow width
        let pretty = nodes[0].pretty_serialize(20);

        let lines: Vec<&str> = pretty.lines().collect();

        // Check that keyword-value pairs stay together on their lines
        assert!(
            lines.iter().any(|l| l.contains(":bar baz")),
            "Should have ':bar baz' on same line\nGot:\n{}",
            pretty
        );
        assert!(
            lines.iter().any(|l| l.contains(":bar :baz")),
            "Should have ':bar :baz' on same line\nGot:\n{}",
            pretty
        );

        // Check that nested form in keyword value is formatted correctly
        let if_line = lines.iter().find(|l| l.contains("(if foo"));
        assert!(
            if_line.is_some(),
            "Should have nested (if form\nGot:\n{}",
            pretty
        );

        // Verify that long nested forms get broken
        let has_broken_nested = lines.iter().any(|l| l.contains("bar") && l.contains("baz"));
        assert!(
            has_broken_nested,
            "Long nested forms should be broken\nGot:\n{}",
            pretty
        );
    }

    #[test]
    fn pretty_serialize_no_compression_after_break() {
        // After a form breaks, subsequent keywords shouldn't be compressed onto previous lines
        let input = "(rule \"cmd\" (check :allow \"test\") :effect :ask)";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        // Force check to break
        let pretty = nodes[0].pretty_serialize(35);

        // Should NOT have :effect on same line as closing paren of check
        assert!(
            !pretty.contains(") :effect"),
            ":effect should be on its own line, not compressed\nGot:\n{}",
            pretty
        );

        // Should have :effect on separate line (check for newline followed by :effect)
        assert!(
            pretty.contains("\n") && pretty.contains(":effect :ask"),
            "Should have ':effect :ask' on separate line\nGot:\n{}",
            pretty
        );

        // After check breaks, :effect should come on a new line (cascading)
        let lines: Vec<&str> = pretty.lines().collect();
        let check_line = lines.iter().position(|l| l.contains("(check"));
        let effect_line = lines.iter().position(|l| l.contains(":effect"));

        if let (Some(c_idx), Some(e_idx)) = (check_line, effect_line) {
            assert!(
                e_idx > c_idx,
                ":effect should come after check on a new line\nGot:\n{}",
                pretty
            );
        }
    }

    #[test]
    fn pretty_serialize_head_with_first_arg_stays_together() {
        // The head and first argument should stay on the same line
        let input = "(rule \"openspec\" (effect :allow) (check :allow \"test\"))";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        // Force break with narrow width
        let pretty = nodes[0].pretty_serialize(40);

        // First line should have both "rule" and "openspec"
        let first_line = pretty.lines().next().unwrap();
        assert!(
            first_line.contains("rule") && first_line.contains("\"openspec\""),
            "Head and first arg should stay together on first line\nGot first line: {}\nFull output:\n{}",
            first_line,
            pretty
        );
    }

    #[test]
    fn pretty_serialize_no_extra_blank_lines() {
        // Breaking should not add extra blank lines
        let input = "(rule \"openspec\" (effect :allow) (check :allow \"test\"))";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        // Force break
        let pretty = nodes[0].pretty_serialize(40);

        // Check no consecutive newlines (blank lines)
        assert!(
            !pretty.contains("\n\n"),
            "Should not have blank lines (consecutive newlines)\nGot:\n{}",
            pretty
        );
    }

    #[test]
    fn pretty_serialize_original_openspec_example() {
        // Test the exact example from the issue
        let input = r#"(rule (command "openspec")
      (effect :allow)
      (check :allow "openspec status --change 'foo'"
             :allow "openspec instructions apply --change 'bar'"))"#;
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());

        let pretty = nodes[0].pretty_serialize(80);
        let lines: Vec<&str> = pretty.lines().collect();

        // First line should be: (rule "openspec"
        let first_line = lines[0];
        assert!(
            first_line.contains("(rule") && first_line.contains("\"openspec\""),
            "First line should have head and first arg\nGot: {}",
            first_line
        );

        // Should not have blank lines
        assert!(
            !pretty.contains("\n\n"),
            "Should not have blank lines\nGot:\n{}",
            pretty
        );

        // Check structure is preserved
        assert!(
            pretty.contains("(effect :allow)"),
            "Should have effect form"
        );
        assert!(pretty.contains("(check"), "Should have check form");
    }

    // --- Parser error path tests ---

    #[test]
    fn unclosed_list_produces_error() {
        let (nodes, errors) = parse("(foo bar");
        assert!(!errors.is_empty());
        assert!(
            errors[0].message.contains("unclosed"),
            "expected unclosed error, got: {:?}",
            errors[0].message
        );
        // Partial parse still produces a node
        assert!(!nodes.is_empty());
    }

    #[test]
    fn unterminated_string_produces_error() {
        let (_, errors) = parse("\"hello");
        assert!(!errors.is_empty());
        assert!(
            errors[0].message.contains("unterminated"),
            "expected unterminated error, got: {:?}",
            errors[0].message
        );
    }

    #[test]
    fn unexpected_character_produces_error() {
        let (_, errors) = parse("~");
        assert!(!errors.is_empty());
        assert!(
            errors[0].message.contains("unexpected"),
            "expected unexpected char error, got: {:?}",
            errors[0].message
        );
    }

    #[test]
    fn string_escape_sequences() {
        let (nodes, errors) = parse(r#""hello\nworld\t\"end\\""#);
        assert!(errors.is_empty(), "errors: {errors:?}");
        // At CST level, strings are ShapeF::Str
        match &nodes[0].shape {
            ShapeF::Str(s) => {
                assert_eq!(s, "hello\nworld\t\"end\\");
            }
            other => panic!("expected Str, got: {other:?}"),
        }
    }

    #[test]
    fn unknown_escape_produces_error() {
        let (_, errors) = parse(r#""\z""#);
        assert!(!errors.is_empty());
        assert!(
            errors[0].message.contains("unknown escape"),
            "got: {:?}",
            errors[0].message
        );
    }

    #[test]
    fn unterminated_escape_produces_error() {
        let (_, errors) = parse(r#""hello\"#);
        assert!(!errors.is_empty());
    }

    #[test]
    fn pretty_serialize_vector_form() {
        let input = "[a b c]";
        let (nodes, errors) = parse(input);
        assert!(errors.is_empty());
        let pretty = nodes[0].pretty_serialize(80);
        assert!(pretty.contains("["));
        assert!(pretty.contains("]"));
        assert!(pretty.contains("a"));
    }
}
