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
    Vector(Vec<R>),
}

impl<R> DocF<R> {
    /// Functor map: transform children (recursive positions).
    pub fn map<S>(self, mut f: impl FnMut(R) -> S) -> DocF<S> {
        match self {
            DocF::Atom(s) => DocF::Atom(s),
            DocF::List(rs) => DocF::List(rs.into_iter().map(&mut f).collect()),
            DocF::Vector(rs) => DocF::Vector(rs.into_iter().map(&mut f).collect()),
        }
    }

    /// Functor map by reference.
    pub fn map_ref<S>(&self, mut f: impl FnMut(&R) -> S) -> DocF<S> {
        match self {
            DocF::Atom(s) => DocF::Atom(s.clone()),
            DocF::List(rs) => DocF::List(rs.iter().map(&mut f).collect()),
            DocF::Vector(rs) => DocF::Vector(rs.iter().map(&mut f).collect()),
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
            DocF::List(cs) | DocF::Vector(cs) => Some(cs),
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
        Doc {
            ann: (),
            node: DocF::Atom(s.into()),
            layout: LayoutHint::Auto,
            dimmed: false,
        }
    }

    pub fn list(children: Vec<Doc<()>>) -> Self {
        Doc {
            ann: (),
            node: DocF::List(children),
            layout: LayoutHint::Auto,
            dimmed: false,
        }
    }

    pub fn vector(children: Vec<Doc<()>>) -> Self {
        Doc {
            ann: (),
            node: DocF::Vector(children),
            layout: LayoutHint::Auto,
            dimmed: false,
        }
    }

    /// Create a list node that always breaks to separate lines.
    pub fn broken_list(children: Vec<Doc<()>>) -> Self {
        Doc {
            ann: (),
            node: DocF::List(children),
            layout: LayoutHint::AlwaysBreak,
            dimmed: false,
        }
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

// ── Serialisation ─────────────────────────────────────────────────

impl<A> Doc<A> {
    /// Flat s-expression string with no pretty-printing or line breaks.
    pub fn to_flat_string(&self) -> String {
        self.fold(&|node, _ann| match node {
            DocF::Atom(s) => s,
            DocF::List(parts) => format!("({})", parts.join(" ")),
            DocF::Vector(parts) => format!("[{}]", parts.join(" ")),
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docf_map_transforms_children() {
        let docf = DocF::List(vec![1, 2, 3]);
        let mapped = docf.map(|n| n * 2);
        assert!(matches!(mapped, DocF::List(v) if v == vec![2, 4, 6]));
    }

    #[test]
    fn docf_map_preserves_atom() {
        let docf = DocF::Atom("test".into());
        let mapped = docf.map(|n: String| n.to_uppercase());
        assert!(matches!(mapped, DocF::Atom(s) if s == "test"));
    }

    #[test]
    fn docf_map_ref_by_reference() {
        let docf: DocF<&str> = DocF::Vector(vec!["a", "b"]);
        let mapped: DocF<String> = docf.map_ref(|s| s.to_string());
        assert!(matches!(mapped, DocF::Vector(v) if v == vec!["a".to_string(), "b".to_string()]));
    }

    #[test]
    fn docf_as_atom_returns_some_for_atom() {
        let docf: DocF<Doc> = DocF::Atom("hello".into());
        assert_eq!(docf.as_atom(), Some("hello"));
    }

    #[test]
    fn docf_as_atom_returns_none_for_list() {
        let docf = DocF::List::<Doc>(vec![]);
        assert_eq!(docf.as_atom(), None);
    }

    #[test]
    fn docf_children_returns_some_for_list() {
        let children = vec![Doc::atom("a"), Doc::atom("b")];
        let docf = DocF::List(children);
        assert_eq!(docf.children().map(|c| c.len()), Some(2));
    }

    #[test]
    fn docf_children_returns_some_for_vector() {
        let children = vec![Doc::atom("x")];
        let docf = DocF::Vector(children);
        assert_eq!(docf.children().map(|c| c.len()), Some(1));
    }

    #[test]
    fn docf_children_returns_none_for_atom() {
        let docf: DocF<Doc> = DocF::Atom("test".into());
        assert!(docf.children().is_none());
    }

    #[test]
    fn doc_atom_creates_unannotated() {
        let doc = Doc::atom("test");
        assert!(matches!(doc.node, DocF::Atom(s) if s == "test"));
        assert_eq!(doc.layout, LayoutHint::Auto);
        assert!(!doc.dimmed);
    }

    #[test]
    fn doc_list_creates_unannotated() {
        let children = vec![Doc::atom("a"), Doc::atom("b")];
        let doc = Doc::list(children);
        assert!(matches!(doc.node, DocF::List(cs) if cs.len() == 2));
    }

    #[test]
    fn doc_vector_creates_unannotated() {
        let children = vec![Doc::atom("x")];
        let doc = Doc::vector(children);
        assert!(matches!(doc.node, DocF::Vector(cs) if cs.len() == 1));
    }

    #[test]
    fn doc_broken_list_sets_layout() {
        let doc = Doc::broken_list(vec![]);
        assert_eq!(doc.layout, LayoutHint::AlwaysBreak);
    }

    #[test]
    fn doc_as_atom_delegates_to_node() {
        let doc = Doc::atom("hello");
        assert_eq!(doc.as_atom(), Some("hello"));
    }

    #[test]
    fn doc_children_delegates_to_node() {
        let doc = Doc::list(vec![Doc::atom("a"), Doc::atom("b")]);
        assert_eq!(doc.children().map(|c| c.len()), Some(2));
    }

    #[test]
    fn doc_head_atom_returns_first_atom() {
        let doc = Doc::list(vec![Doc::atom("head"), Doc::atom("tail")]);
        assert_eq!(doc.head_atom(), Some("head"));
    }

    #[test]
    fn doc_head_atom_returns_none_for_empty_list() {
        let doc = Doc::list(vec![]);
        assert_eq!(doc.head_atom(), None);
    }

    #[test]
    fn doc_head_atom_returns_none_for_atom() {
        let doc = Doc::atom("just-atom");
        assert_eq!(doc.head_atom(), None);
    }

    #[test]
    fn doc_map_transforms_annotation() {
        let doc = Doc {
            ann: 42,
            node: DocF::Atom("test".into()),
            layout: LayoutHint::Auto,
            dimmed: false,
        };
        let mapped = doc.map(&|n| n.to_string());
        assert_eq!(mapped.ann, "42");
    }

    #[test]
    fn doc_fold_reduces_bottom_up() {
        // Count total atoms in tree
        let doc = Doc::list(vec![Doc::atom("a"), Doc::atom("b"), Doc::atom("c")]);
        let count = doc.fold(&|node, _ann| match node {
            DocF::Atom(_) => 1,
            DocF::List(cs) => cs.iter().sum::<i32>(),
            DocF::Vector(cs) => cs.iter().sum::<i32>(),
        });
        assert_eq!(count, 3);
    }

    // ── Property tests: Doc functor laws ──────────────────────────────

    use proptest::prelude::*;

    fn any_doc() -> impl Strategy<Value = Doc<()>> {
        let leaf = "[a-z_]{1,12}".prop_map(Doc::atom);
        leaf.prop_recursive(4, 64, 8, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..4).prop_map(Doc::list),
                prop::collection::vec(inner.clone(), 0..4).prop_map(Doc::vector),
                prop::collection::vec(inner, 0..4).prop_map(Doc::broken_list),
            ]
        })
    }

    /// Structural + annotation equality via fold.
    fn docs_equal<A: PartialEq>(a: &Doc<A>, b: &Doc<A>) -> bool {
        if a.ann != b.ann || a.layout != b.layout || a.dimmed != b.dimmed {
            return false;
        }
        match (&a.node, &b.node) {
            (DocF::Atom(sa), DocF::Atom(sb)) => sa == sb,
            (DocF::List(ca), DocF::List(cb)) | (DocF::Vector(ca), DocF::Vector(cb)) => {
                ca.len() == cb.len() && ca.iter().zip(cb).all(|(x, y)| docs_equal(x, y))
            }
            _ => false,
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        #[test]
        fn map_identity(doc in any_doc()) {
            let mapped = doc.clone().map(&|x| x);
            prop_assert!(
                docs_equal(&doc, &mapped),
                "identity law failed:\n  original: {}\n  mapped:   {}",
                doc.to_flat_string(),
                mapped.to_flat_string()
            );
        }

        #[test]
        fn map_composition(doc in any_doc()) {
            let f = |_: ()| 1u32;
            let g = |x: u32| x + 10;

            let map_f_then_g = doc.clone().map(&f).map(&g);
            let map_fg = doc.map(&|x| g(f(x)));

            prop_assert!(
                docs_equal(&map_f_then_g, &map_fg),
                "composition law failed:\n  f then g: {}\n  f∘g:      {}",
                map_f_then_g.to_flat_string(),
                map_fg.to_flat_string()
            );
        }
    }
}
