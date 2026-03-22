# Design: Migration Diff Pretty-Print

## Architecture Overview

### Phase 1: CST Refactor to Fixpoint Pattern

```rust
// crates/sexpr/src/cst.rs

/// Base functor: one layer of CST structure
pub enum ShapeF<R> {
    Atom(String),
    Str(String),
    List(Vec<R>),
    Vector(Vec<R>),
}

impl<R> ShapeF<R> {
    /// Functor map
    pub fn map<S>(self, f: impl FnMut(R) -> S) -> ShapeF<S>
    
    /// Map by reference
    pub fn map_ref<S>(&self, f: impl FnMut(&R) -> S) -> ShapeF<S>
}

/// The fixpoint: recursive structure with annotation
pub struct CstNode<A = TriviaAnn> {
    pub ann: A,
    pub shape: ShapeF<Box<CstNode<A>>>,
}

impl<A> CstNode<A> {
    /// Transform annotations (functor)
    pub fn map<B>(self, f: impl Fn(A) -> B) -> CstNode<B>
    
    /// Bottom-up fold (catamorphism)
    pub fn fold<B>(&self, alg: impl Fn(ShapeF<B>, &A) -> B) -> B
    
    /// Top-down traversal with state
    pub fn traverse<S>(&self, state: S, f: impl Fn(&Self, S) -> S) -> S
}
```

### Phase 2: Diff Annotation

```rust
// crates/sexpr/src/diff.rs

/// Change type for diff annotation
#[derive(Debug, Clone)]
pub enum ChangeType {
    Unchanged,
    Modified { after: CstNode<TriviaAnn> },
    Deleted,
}

/// Diff annotation combining trivia and change status
#[derive(Debug, Clone)]
pub struct DiffAnn {
    pub trivia: TriviaAnn,
    pub change: ChangeType,
}

/// Type aliases
pub type PlainCst = CstNode<TriviaAnn>;
pub type DiffCst = CstNode<DiffAnn>;

/// Compute diff between original and migrated CSTs
pub fn compute_diff(
    original: Vec<PlainCst>,
    migrated: Vec<PlainCst>,
) -> Vec<DiffCst>
```

### Phase 3: Diff Rendering

```rust
// crates/output/src/diff_renderer.rs

pub struct DiffConfig {
    pub line_numbers: bool,
    pub two_column_threshold: usize,  // 80
    pub fold_marker: String,          // "⋮"
    pub show_context_lines: usize,    // 2
}

pub fn render_diff(
    annotated: Vec<DiffCst>,
    config: DiffConfig,
) -> Vec<Element> {
    // Group consecutive Unchanged (for fold markers)
    // Render Changed forms in two columns
    // Pretty-print both sides via pp
}
```

### Phase 4: Pager Integration

```rust
// src/cmd_migrate.rs

use minus::{page_all, Pager};

fn display_with_pager(elements: Vec<Element>) -> Result<()> {
    let mut pager = Pager::new();
    
    for element in elements {
        writeln!(pager, "{}", render_element(&element))?;
    }
    
    page_all(pager)?;
    Ok(())
}
```

## Rendering Layout

```
┌────────────────────────────────────────────────────────────────────┐
│                           BEFORE │ AFTER                             │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  1: ;; Wrappers section                                            │
│  2:                                                                │
│  ────────────────────────────────────────────────────────────────  │
│                              ⋮                                     │
│  3:  ┌────────────────────┬─────────────────────────┐              │
│  4:  │(wrapper "nohup"    │ (rule "nohup"           │              │
│  5:  │  :command+args)    │   . (may-i *)           │              │
│      │                    │   (effect :allow))      │              │
│      └────────────────────┴─────────────────────────┘              │
│                              ⋮                                     │
│  6:  ;; Context definitions                                        │
│  ────────────────────────────────────────────────────────────────  │
│                              ⋮                                     │
│      ┌────────────────────┬─────────────────────────┐              │
│      │(defcontext write-ok│ (define write-ok        │              │
│      │  (has ...))        │   (has ...))            │              │
│      └────────────────────┴─────────────────────────┘              │
│                              ⋮                                     │
└────────────────────────────────────────────────────────────────────┘

Line nums:  Input file lines (left gutter only)
Columns:    50/50 split of remaining width
Width calc: term_width - gutter_width - separator_width
Gutter:     line_num_width + 2 spaces
Separator:  " │ " (3 chars)
```

## Width Calculation

```rust
fn calculate_column_width(term_width: usize, max_line_num: usize) -> usize {
    let line_num_width = format!("{}", max_line_num).len();
    let gutter = line_num_width + 2;           // " 1:"
    let separator = 3;                          // " │ "
    let available = term_width - gutter - separator - 2;  // padding
    available / 2
}
```

## Diff Computation Algorithm

```rust
fn compute_diff(original: Vec<PlainCst>, migrated: Vec<PlainCst>) -> Vec<DiffCst> {
    let mut result = Vec::new();
    let mut mig_iter = migrated.into_iter().peekable();
    
    for orig in original {
        // Compare shapes
        let change = if let Some(mig) = mig_iter.peek() {
            if shapes_equal(&orig, mig) {
                ChangeType::Unchanged
            } else {
                ChangeType::Modified { 
                    after: mig_iter.next().unwrap() 
                }
            }
        } else {
            ChangeType::Deleted
        };
        
        result.push(CstNode {
            ann: DiffAnn {
                trivia: orig.ann.clone(),
                change,
            },
            shape: orig.shape.clone(),
        });
    }
    
    result
}
```

## Testing Strategy

1. **Unit tests**: Functor laws, fold correctness
2. **Property tests**: Round-trip serialization, annotation preservation
3. **Integration tests**: Full migration diff with mock CSTs
4. **Snapshot tests**: Diff output for sample configs

## Dependencies

- `minus`: Built-in pager (add to Cargo.toml)
- No changes to existing pp/output crates
