use may_i_core::doc::{Doc, DocF, LayoutHint};

pub(crate) use crate::annotation::Ann;

pub(crate) fn atom(s: &str) -> Doc<Option<Ann>> {
    Doc {
        ann: None,
        node: DocF::Atom(s.into()),
        layout: LayoutHint::Auto,
        dimmed: false,
    }
}

pub(crate) fn atom_ann(s: &str, ann: Ann) -> Doc<Option<Ann>> {
    Doc {
        ann: Some(ann),
        node: DocF::Atom(s.into()),
        layout: LayoutHint::Auto,
        dimmed: false,
    }
}

pub(crate) fn list(children: Vec<Doc<Option<Ann>>>) -> Doc<Option<Ann>> {
    Doc {
        ann: None,
        node: DocF::List(children),
        layout: LayoutHint::Auto,
        dimmed: false,
    }
}

pub(crate) fn list_ann(ann: Ann, children: Vec<Doc<Option<Ann>>>) -> Doc<Option<Ann>> {
    Doc {
        ann: Some(ann),
        node: DocF::List(children),
        layout: LayoutHint::Auto,
        dimmed: false,
    }
}

pub(crate) fn vec_doc(children: Vec<Doc<Option<Ann>>>) -> Doc<Option<Ann>> {
    Doc {
        ann: None,
        node: DocF::Vector(children),
        layout: LayoutHint::Auto,
        dimmed: false,
    }
}
