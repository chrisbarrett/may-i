// Byte-offset span for source location tracking.

/// Byte-offset span within source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}

/// Convert a byte offset in source text to a 1-based (line, column) pair.
pub fn offset_to_line_col(source: &str, offset: usize) -> (usize, usize) {
    let before = &source[..offset.min(source.len())];
    let line = before.bytes().filter(|&b| b == b'\n').count() + 1;
    let col = before
        .rfind('\n')
        .map_or(before.len(), |p| before.len() - p - 1)
        + 1;
    (line, col)
}
