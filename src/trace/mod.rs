// Constructors and accessor surface land ahead of the producer/renderer
// port; `dead_code` is tolerated only until those land in the same change.
#![allow(dead_code)]

pub mod node;
pub mod render_doc;

pub use node::{CaptureSource, Evidence, Layout, Role, TraceNode};
pub use render_doc::NodeMeta;
