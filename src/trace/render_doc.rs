// Render-time projection from `TraceNode` to `Doc<Option<NodeMeta>>`.
//
// `NodeMeta` is the renderer-facing carrier for a node's role and evidence.
// Renderers access role/evidence via accessor methods on `NodeMeta`; they
// MUST NOT pattern-match on `TraceNode`'s internal `Body` or other private
// state. The projection reuses `may_i_pp` for layout while preserving the
// producer/renderer seam discipline from `output-rendering`.

use may_i_core::doc::{Doc, DocF, LayoutHint};
use may_i_core::trivia::{Trivia, TriviaSource};

use super::node::{Evidence, Layout, Role, TraceNode};

#[derive(Clone, Debug)]
pub struct NodeMeta {
    role: Role,
    evidence: Option<Evidence>,
}

impl NodeMeta {
    pub fn new(role: Role, evidence: Option<Evidence>) -> Self {
        Self { role, evidence }
    }

    pub fn role(&self) -> &Role {
        &self.role
    }

    pub fn evidence(&self) -> Option<&Evidence> {
        self.evidence.as_ref()
    }
}

impl TriviaSource for NodeMeta {
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

impl TraceNode {
    /// Project this node into a pretty-printable `Doc` carrying `NodeMeta`
    /// at each Doc node where evidence or a non-plain role is present.
    ///
    /// `Role::Plain` nodes carrying no evidence project to a `Doc` with
    /// `ann == None` (no annotation). Renderers reading the projected Doc
    /// MUST go through `NodeMeta`'s accessors.
    pub fn to_render_doc(&self) -> Doc<Option<NodeMeta>> {
        let layout = match self.layout() {
            Layout::Auto => LayoutHint::Auto,
            Layout::AlwaysBreak => LayoutHint::AlwaysBreak,
        };
        let ann = match (self.role(), self.evidence()) {
            (Role::Plain, None) => None,
            (role, ev) => Some(NodeMeta::new(role.clone(), ev.cloned())),
        };
        let node = match self.body_for_render() {
            BodyView::Atom(text) => DocF::Atom(text.into()),
            BodyView::List(children) => {
                DocF::List(children.iter().map(TraceNode::to_render_doc).collect())
            }
        };
        Doc {
            ann,
            node,
            layout,
            dimmed: self.dimmed(),
        }
    }
}

/// Body view used internally by `to_render_doc`. Mirrors `node::Body` but
/// is constructed via accessor logic rather than direct field access.
enum BodyView<'a> {
    Atom(&'a str),
    List(&'a [TraceNode]),
}

impl TraceNode {
    fn body_for_render(&self) -> BodyView<'_> {
        match self.label() {
            Some(s) => BodyView::Atom(s),
            None => BodyView::List(self.children()),
        }
    }
}

// Helper accessor on `NodeMeta` used by renderers.
impl NodeMeta {
    /// Returns true iff this meta carries no rendered annotation
    /// (i.e. `Role::Plain` with no evidence). Internally used by the
    /// renderer to skip plain structural atoms during line-annotation
    /// collection.
    pub fn is_plain(&self) -> bool {
        matches!(self.role, Role::Plain) && self.evidence.is_none()
    }
}
