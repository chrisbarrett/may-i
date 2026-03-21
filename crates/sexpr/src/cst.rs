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

/// The shape of an s-expression node (structure without annotations).
#[derive(Debug, Clone, PartialEq)]
pub enum Shape {
    Atom(String),
    List(Vec<Box<CstNode>>),
    Vector(Vec<Box<CstNode>>),
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

/// A Concrete Syntax Tree node with trivia and span annotations.
#[derive(Debug, Clone, PartialEq)]
pub struct CstNode {
    pub annotation: TriviaAnn,
    pub shape: Shape,
}

/// Trivia types (comments and whitespace).
#[derive(Debug, Clone, PartialEq)]
pub enum Trivia {
    Whitespace(String),
    Comment { text: String, has_newline: bool },
}

impl Trivia {
    pub fn has_newline(&self) -> bool {
        match self {
            Trivia::Whitespace(s) => s.contains('\n'),
            Trivia::Comment { has_newline, .. } => *has_newline,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Trivia::Whitespace(s) => s,
            Trivia::Comment { text, .. } => text,
        }
    }
}

impl CstNode {
    /// Create an atom node.
    pub fn atom(value: impl Into<String>, ann: TriviaAnn) -> Self {
        Self {
            annotation: ann,
            shape: Shape::Atom(value.into()),
        }
    }

    /// Create a list node.
    pub fn list(children: Vec<Box<CstNode>>, ann: TriviaAnn) -> Self {
        Self {
            annotation: ann,
            shape: Shape::List(children),
        }
    }

    /// Create a vector node.
    pub fn vector(children: Vec<Box<CstNode>>, ann: TriviaAnn) -> Self {
        Self {
            annotation: ann,
            shape: Shape::Vector(children),
        }
    }

    /// Get the atom value if this is an atom.
    pub fn as_atom(&self) -> Option<&str> {
        match &self.shape {
            Shape::Atom(s) => Some(s),
            _ => None,
        }
    }

    /// Get list children if this is a list.
    pub fn as_list(&self) -> Option<&[Box<CstNode>]> {
        match &self.shape {
            Shape::List(children) => Some(children),
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

    /// Serialize back to string.
    pub fn serialize(&self) -> String {
        let mut output = String::new();
        self.write_to(&mut output);
        output
    }

    fn write_to(&self, output: &mut String) {
        // Write leading trivia
        for trivia in &self.annotation.leading {
            output.push_str(trivia.as_str());
        }

        // Write the shape
        match &self.shape {
            Shape::Atom(s) => {
                if needs_quoting(s) {
                    output.push_str(&quote_string(s));
                } else {
                    output.push_str(s);
                }
            }
            Shape::List(children) => {
                output.push('(');
                for (i, child) in children.iter().enumerate() {
                    if i > 0 && child.annotation.leading.is_empty() {
                        output.push(' ');
                    }
                    child.write_to(output);
                }
                output.push(')');
            }
            Shape::Vector(children) => {
                output.push('[');
                for (i, child) in children.iter().enumerate() {
                    if i > 0 && child.annotation.leading.is_empty() {
                        output.push(' ');
                    }
                    child.write_to(output);
                }
                output.push(']');
            }
        }

        // Write trailing trivia
        for trivia in &self.annotation.trailing {
            output.push_str(trivia.as_str());
        }
    }

    /// Apply a transformation to this node and all children (cata-like).
    pub fn transform<F>(&self, f: &mut F) -> Box<CstNode>
    where
        F: FnMut(&CstNode) -> Option<Box<CstNode>>,
    {
        if let Some(replacement) = f(self) {
            return replacement;
        }

        // Transform children
        let new_shape = match &self.shape {
            Shape::Atom(s) => Shape::Atom(s.clone()),
            Shape::List(children) => Shape::List(children.iter().map(|c| c.transform(f)).collect()),
            Shape::Vector(children) => {
                Shape::Vector(children.iter().map(|c| c.transform(f)).collect())
            }
        };

        Box::new(CstNode {
            annotation: self.annotation.clone(),
            shape: new_shape,
        })
    }
}

fn needs_quoting(s: &str) -> bool {
    s.is_empty()
        || s.contains(|c: char| {
            c.is_whitespace()
                || c == '('
                || c == ')'
                || c == '['
                || c == ']'
                || c == '"'
                || c == ';'
                || c == '\\'
        })
}

fn quote_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
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
                node.annotation.leading = leading;
                node.annotation.trailing = self.collect_trivia();
                results.push(Box::new(node));
            } else if !leading.is_empty()
                && !results.is_empty()
                && let Some(last) = results.last_mut()
            {
                last.annotation.trailing.extend(leading);
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
                    child.annotation.leading = leading;
                    children.push(Box::new(child));
                } else if !leading.is_empty()
                    && !children.is_empty()
                    && let Some(last) = children.last_mut()
                {
                    last.annotation.trailing.extend(leading);
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
            Shape::List(children)
        } else {
            Shape::Vector(children)
        };

        Some(CstNode {
            annotation: TriviaAnn {
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
                        annotation: TriviaAnn {
                            span: Span::new(start, end),
                            ..Default::default()
                        },
                        shape: Shape::Atom(s),
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
                annotation: TriviaAnn {
                    span: Span::new(start, end),
                    ..Default::default()
                },
                shape: Shape::Atom(s),
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
    fn apply(&self, node: &CstNode) -> Option<Box<CstNode>>;
}

/// Apply a sequence of rewrite rules until convergence.
pub fn rewrite_until_convergence<F>(node: Box<CstNode>, rules: &[F]) -> Box<CstNode>
where
    F: Fn(&CstNode) -> Option<Box<CstNode>>,
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
            let new_current = current.transform(&mut |n| {
                for rule in rules {
                    if let Some(r) = rule(n) {
                        return Some(r);
                    }
                }
                None
            });

            if std::ptr::eq(new_current.as_ref(), current.as_ref()) {
                // No changes to children either
                break;
            }
            current = new_current;
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
                let children = n.as_list()?.iter().skip(1).cloned().collect();
                Some(Box::new(CstNode::list(
                    children,
                    TriviaAnn {
                        leading: n.annotation.leading.clone(),
                        trailing: n.annotation.trailing.clone(),
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
}
