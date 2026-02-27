// Annotated s-expression tree based on a recursion scheme.
//
// `DocF<R>` is the base functor (one layer of tree structure).
// `Doc<A>`  is the fixpoint, pairing each node with an annotation `A`.

/// One layer of s-expression structure, parameterized over what sits
/// in recursive positions.
#[derive(Debug, Clone)]
pub enum DocF<R> {
    Atom(String),
    List(Vec<R>),
}

impl<R> DocF<R> {
    /// Functor map: transform children (recursive positions).
    pub fn map<S>(self, mut f: impl FnMut(R) -> S) -> DocF<S> {
        match self {
            DocF::Atom(s) => DocF::Atom(s),
            DocF::List(rs) => DocF::List(rs.into_iter().map(&mut f).collect()),
        }
    }

    /// Functor map by reference.
    pub fn map_ref<S>(&self, mut f: impl FnMut(&R) -> S) -> DocF<S> {
        match self {
            DocF::Atom(s) => DocF::Atom(s.clone()),
            DocF::List(rs) => DocF::List(rs.iter().map(&mut f).collect()),
        }
    }

    pub fn as_atom(&self) -> Option<&str> {
        match self {
            DocF::Atom(s) => Some(s),
            _ => None,
        }
    }

    pub fn children(&self) -> Option<&[R]> {
        match self {
            DocF::List(cs) => Some(cs),
            _ => None,
        }
    }
}

/// Layout hint for the pretty-printer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LayoutHint {
    /// Let the pretty-printer decide flat vs broken.
    #[default]
    Auto,
    /// Always break children to separate lines.
    AlwaysBreak,
}

/// An annotated s-expression tree — the fixpoint of `DocF` where each
/// node carries an annotation of type `A`.
///
/// `Doc<()>` is the unannotated tree used for parsing and rendering.
#[derive(Debug, Clone)]
pub struct Doc<A = ()> {
    pub ann: A,
    pub node: DocF<Doc<A>>,
    pub layout: LayoutHint,
    /// Render this subtree in dimmed style (for unevaluated content).
    pub dimmed: bool,
}

// ── Constructors (unannotated) ─────────────────────────────────────

impl Doc<()> {
    pub fn atom(s: impl Into<String>) -> Self {
        Doc { ann: (), node: DocF::Atom(s.into()), layout: LayoutHint::Auto, dimmed: false }
    }

    pub fn list(children: Vec<Doc<()>>) -> Self {
        Doc { ann: (), node: DocF::List(children), layout: LayoutHint::Auto, dimmed: false }
    }

    /// Create a list node that always breaks to separate lines.
    pub fn broken_list(children: Vec<Doc<()>>) -> Self {
        Doc { ann: (), node: DocF::List(children), layout: LayoutHint::AlwaysBreak, dimmed: false }
    }
}

// ── Accessors ──────────────────────────────────────────────────────

impl<A> Doc<A> {
    pub fn as_atom(&self) -> Option<&str> {
        self.node.as_atom()
    }

    pub fn children(&self) -> Option<&[Doc<A>]> {
        self.node.children()
    }

    /// The head atom of a list (first child's text if it's an Atom).
    pub fn head_atom(&self) -> Option<&str> {
        self.children()
            .and_then(|cs| cs.first())
            .and_then(|c| c.as_atom())
    }
}

// ── Functor (map) ──────────────────────────────────────────────────

impl<A> Doc<A> {
    /// Transform every annotation in the tree, preserving structure and layout.
    pub fn map<B>(self, f: &impl Fn(A) -> B) -> Doc<B> {
        Doc {
            ann: f(self.ann),
            node: self.node.map(|c| c.map(f)),
            layout: self.layout,
            dimmed: self.dimmed,
        }
    }
}

// ── Catamorphism (fold) ────────────────────────────────────────────

impl<A> Doc<A> {
    /// Bottom-up fold. Children are reduced first, then the algebra
    /// receives the shape (with reduced children) and the annotation.
    pub fn fold<B>(&self, alg: &impl Fn(DocF<B>, &A) -> B) -> B {
        let reduced = self.node.map_ref(|child| child.fold(alg));
        alg(reduced, &self.ann)
    }
}
