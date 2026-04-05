use crate::span::Span;

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

    pub fn has_newline(&self) -> bool {
        match self {
            Trivia::Whitespace(s) => s.contains('\n'),
            Trivia::Comment { has_newline, .. } => *has_newline,
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

/// Trait for extracting trivia information from a Doc annotation.
///
/// Implemented for `()` (no trivia, all no-ops) and `Option<TriviaAnn>`
/// (delegates to trivia when `Some`, no-ops when `None`).
pub trait TriviaSource {
    fn forced_break(&self) -> bool;
    fn leading_trivia(&self) -> &[Trivia];
    fn trailing_trivia(&self) -> &[Trivia];
}

macro_rules! impl_trivial_trivia_source {
    ($($t:ty),*) => {
        $(
            impl TriviaSource for $t {
                fn forced_break(&self) -> bool { false }
                fn leading_trivia(&self) -> &[Trivia] { &[] }
                fn trailing_trivia(&self) -> &[Trivia] { &[] }
            }
        )*
    };
}

impl_trivial_trivia_source!((), i32, i64, u32, u64, usize, bool);

impl TriviaSource for &str {
    fn forced_break(&self) -> bool {
        false
    }
    fn leading_trivia(&self) -> &[Trivia] {
        &[]
    }
    fn trailing_trivia(&self) -> &[Trivia] {
        &[]
    }
}

impl TriviaSource for TriviaAnn {
    fn forced_break(&self) -> bool {
        self.leading.iter().any(|t| t.has_newline())
    }
    fn leading_trivia(&self) -> &[Trivia] {
        &self.leading
    }
    fn trailing_trivia(&self) -> &[Trivia] {
        &self.trailing
    }
}

impl<T: TriviaSource> TriviaSource for Option<T> {
    fn forced_break(&self) -> bool {
        match self {
            Some(inner) => inner.forced_break(),
            None => false,
        }
    }
    fn leading_trivia(&self) -> &[Trivia] {
        match self {
            Some(inner) => inner.leading_trivia(),
            None => &[],
        }
    }
    fn trailing_trivia(&self) -> &[Trivia] {
        match self {
            Some(inner) => inner.trailing_trivia(),
            None => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── TriviaSource for () ──────────────────────────────────────

    #[test]
    fn unit_never_forces_break() {
        assert!(!().forced_break());
    }

    #[test]
    fn unit_has_empty_leading_trivia() {
        assert!(().leading_trivia().is_empty());
    }

    #[test]
    fn unit_has_empty_trailing_trivia() {
        assert!(().trailing_trivia().is_empty());
    }

    // ── TriviaSource for Option<TriviaAnn> ───────────────────────

    #[test]
    fn none_never_forces_break() {
        let ann: Option<TriviaAnn> = None;
        assert!(!ann.forced_break());
    }

    #[test]
    fn none_has_empty_leading_trivia() {
        let ann: Option<TriviaAnn> = None;
        assert!(ann.leading_trivia().is_empty());
    }

    #[test]
    fn none_has_empty_trailing_trivia() {
        let ann: Option<TriviaAnn> = None;
        assert!(ann.trailing_trivia().is_empty());
    }

    #[test]
    fn some_with_newline_forces_break() {
        let ann = Some(TriviaAnn {
            leading: vec![Trivia::Whitespace("\n  ".to_string())],
            trailing: vec![],
            span: Span::new(0, 5),
        });
        assert!(ann.forced_break());
    }

    #[test]
    fn some_without_newline_does_not_force_break() {
        let ann = Some(TriviaAnn {
            leading: vec![Trivia::Whitespace("  ".to_string())],
            trailing: vec![],
            span: Span::new(0, 5),
        });
        assert!(!ann.forced_break());
    }

    #[test]
    fn some_with_comment_newline_forces_break() {
        let ann = Some(TriviaAnn {
            leading: vec![Trivia::Comment {
                text: "; hello".to_string(),
                has_newline: true,
            }],
            trailing: vec![],
            span: Span::new(0, 10),
        });
        assert!(ann.forced_break());
    }

    #[test]
    fn some_delegates_leading_trivia() {
        let trivia = vec![Trivia::Whitespace(" ".to_string())];
        let ann = Some(TriviaAnn {
            leading: trivia.clone(),
            trailing: vec![],
            span: Span::new(0, 1),
        });
        assert_eq!(ann.leading_trivia(), &trivia[..]);
    }

    #[test]
    fn some_delegates_trailing_trivia() {
        let trivia = vec![Trivia::Comment {
            text: "; end".to_string(),
            has_newline: false,
        }];
        let ann = Some(TriviaAnn {
            leading: vec![],
            trailing: trivia.clone(),
            span: Span::new(0, 1),
        });
        assert_eq!(ann.trailing_trivia(), &trivia[..]);
    }

    #[test]
    fn some_with_empty_trivia_does_not_force_break() {
        let ann = Some(TriviaAnn::default());
        assert!(!ann.forced_break());
    }
}
