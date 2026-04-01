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

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        /// The function is designed for ASCII/byte-aligned source text (as produced by
        /// the config parser). All strategies here use ASCII-only sources so that byte
        /// offsets and char boundaries coincide, matching the function's real use case.

        #[test]
        fn line_is_one_plus_newline_count(source in "[[:ascii:]]*", offset in 0usize..2000) {
            let clamped = offset.min(source.len());
            let (line, _col) = offset_to_line_col(&source, offset);
            let expected_line = source[..clamped].bytes().filter(|&b| b == b'\n').count() + 1;
            prop_assert_eq!(line, expected_line);
        }

        #[test]
        fn column_resets_to_one_after_newline(source in "[[:ascii:]]*\n[[:ascii:]]*") {
            // The byte right after the first '\n' must yield column 1.
            if let Some(newline_pos) = source.find('\n') {
                let after_newline = newline_pos + 1;
                if after_newline <= source.len() {
                    let (_line, col) = offset_to_line_col(&source, after_newline);
                    prop_assert_eq!(col, 1, "col after newline at {} should be 1", newline_pos);
                }
            }
        }

        #[test]
        fn never_panics(source in "[[:ascii:]]*", offset in 0usize..2000) {
            // Offsets beyond source.len() are clamped, so this must not panic.
            let _ = offset_to_line_col(&source, offset);
        }

        #[test]
        fn line_is_one_when_no_newlines(source in "[[:ascii:]&&[^\n]]*", offset in 0usize..2000) {
            let (line, _col) = offset_to_line_col(&source, offset);
            prop_assert_eq!(line, 1);
        }
    }
}
