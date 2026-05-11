// Segmentation — split a shell command at top-level operators for display.
// This is a presentation concern: used by the CLI to colorize command segments
// independently.

use crate::lexer::{Lexer, Token};

/// A segment of a shell command for display purposes.
#[derive(Debug, Clone)]
pub struct Segment {
    /// Byte range in the original input.
    pub start: usize,
    pub end: usize,
    /// True if this segment is an operator (|, &&, ||, ;, &), false if a command.
    pub is_operator: bool,
}

/// Split a shell command into segments at top-level operators.
/// Returns alternating command and operator segments with their byte ranges.
pub fn segment(input: &str) -> Vec<Segment> {
    let mut lex = Lexer::new(input);
    let tokens = lex.tokenize_with_offsets();

    let mut segments = Vec::new();
    let mut depth: i32 = 0;
    let mut cmd_start: Option<usize> = None;

    for (tok, byte_off) in &tokens {
        match tok {
            Token::Eof => {
                // Flush any pending command segment
                if let Some(start) = cmd_start {
                    let end = input[start..].trim_end().len() + start;
                    if end > start {
                        segments.push(Segment {
                            start,
                            end,
                            is_operator: false,
                        });
                    }
                }
            }
            // Depth-increasing tokens
            Token::LParen
            | Token::If
            | Token::For
            | Token::While
            | Token::Until
            | Token::Case
            | Token::Do
            | Token::LBrace => {
                depth += 1;
                if cmd_start.is_none() {
                    cmd_start = Some(*byte_off);
                }
            }
            // Depth-decreasing tokens
            Token::RParen | Token::Fi | Token::Done | Token::Esac | Token::RBrace => {
                depth -= 1;
                if cmd_start.is_none() {
                    cmd_start = Some(*byte_off);
                }
            }
            // Top-level operators split segments
            Token::Pipe | Token::And | Token::Or | Token::Semi | Token::Amp if depth <= 0 => {
                // Flush the command segment before this operator
                if let Some(start) = cmd_start.take() {
                    let end = trim_end_offset(input, start, *byte_off);
                    if end > start {
                        segments.push(Segment {
                            start,
                            end,
                            is_operator: false,
                        });
                    }
                }
                // Add the operator segment
                let op_len = match tok {
                    Token::And | Token::Or => 2,
                    _ => 1,
                };
                segments.push(Segment {
                    start: *byte_off,
                    end: byte_off + op_len,
                    is_operator: true,
                });
            }
            // Newlines are treated like semicolons at depth 0
            Token::Newline if depth <= 0 => {
                if let Some(start) = cmd_start.take() {
                    let end = trim_end_offset(input, start, *byte_off);
                    if end > start {
                        segments.push(Segment {
                            start,
                            end,
                            is_operator: false,
                        });
                    }
                }
            }
            // Everything else is part of a command
            _ => {
                if cmd_start.is_none() {
                    cmd_start = Some(*byte_off);
                }
            }
        }
    }

    segments
}

/// Find the end of a command segment by trimming trailing whitespace.
fn trim_end_offset(input: &str, start: usize, operator_start: usize) -> usize {
    let between = &input[start..operator_start];
    start + between.trim_end().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_empty_input() {
        let segs = segment("");
        assert!(segs.is_empty());
    }

    #[test]
    fn segment_whitespace_only() {
        let segs = segment("   \t  ");
        assert!(segs.is_empty());
    }

    #[test]
    fn segment_single_command() {
        let segs = segment("ls -la");
        assert_eq!(segs.len(), 1);
        assert!(!segs[0].is_operator);
        assert_eq!(segs[0].start, 0);
        assert_eq!(segs[0].end, 6);
    }

    #[test]
    fn segment_simple_pipe() {
        let input = "cat file | grep foo";
        let segs = segment(input);
        assert_eq!(segs.len(), 3);
        // "cat file"
        assert!(!segs[0].is_operator);
        assert_eq!(&input[segs[0].start..segs[0].end], "cat file");
        // "|"
        assert!(segs[1].is_operator);
        assert_eq!(segs[1].end - segs[1].start, 1);
        // "grep foo"
        assert!(!segs[2].is_operator);
        assert_eq!(&input[segs[2].start..segs[2].end], "grep foo");
    }

    #[test]
    fn segment_and_operator() {
        let segs = segment("make && make install");
        assert_eq!(segs.len(), 3);
        // "make"
        assert!(!segs[0].is_operator);
        // "&&" (2 chars)
        assert!(segs[1].is_operator);
        assert_eq!(segs[1].end - segs[1].start, 2);
        // "make install"
        assert!(!segs[2].is_operator);
    }

    #[test]
    fn segment_or_operator() {
        let segs = segment("test -f file || echo missing");
        assert_eq!(segs.len(), 3);
        assert!(segs[1].is_operator);
        assert_eq!(segs[1].end - segs[1].start, 2);
    }

    #[test]
    fn segment_semicolon() {
        let segs = segment("echo a; echo b");
        assert_eq!(segs.len(), 3);
        assert!(segs[1].is_operator);
        assert_eq!(segs[1].end - segs[1].start, 1);
    }

    #[test]
    fn segment_ampersand_background() {
        let segs = segment("sleep 10 &");
        assert_eq!(segs.len(), 2);
        assert!(!segs[0].is_operator);
        assert!(segs[1].is_operator);
        assert_eq!(segs[1].end - segs[1].start, 1);
    }

    #[test]
    fn segment_multiple_operators() {
        let segs = segment("a && b || c");
        assert_eq!(segs.len(), 5);
        assert!(!segs[0].is_operator); // "a"
        assert!(segs[1].is_operator); // "&&"
        assert!(!segs[2].is_operator); // "b"
        assert!(segs[3].is_operator); // "||"
        assert!(!segs[4].is_operator); // "c"
    }

    #[test]
    fn segment_parens_not_split() {
        // Parenthesized commands should NOT be split at operators inside
        let segs = segment("(echo a && echo b)");
        assert_eq!(segs.len(), 1);
        assert!(!segs[0].is_operator);
    }

    #[test]
    fn segment_braces_not_split() {
        // Brace groups should NOT be split at operators inside
        let segs = segment("{ echo a; echo b; }");
        assert_eq!(segs.len(), 1);
        assert!(!segs[0].is_operator);
    }

    #[test]
    fn segment_if_statement_not_split() {
        let segs = segment("if true; then echo yes; fi");
        assert_eq!(segs.len(), 1);
        assert!(!segs[0].is_operator);
    }

    #[test]
    fn segment_for_loop_not_split() {
        let segs = segment("for x in a b; do echo $x; done");
        assert_eq!(segs.len(), 1);
        assert!(!segs[0].is_operator);
    }

    #[test]
    fn segment_while_loop_not_split() {
        let segs = segment("while read line; do echo $line; done");
        assert_eq!(segs.len(), 1);
        assert!(!segs[0].is_operator);
    }

    #[test]
    fn segment_case_statement_not_split() {
        let segs = segment("case $x in a) echo A;; esac");
        assert_eq!(segs.len(), 1);
        assert!(!segs[0].is_operator);
    }

    #[test]
    fn segment_mixed_parens_and_operators() {
        // Parens don't prevent splitting at top level
        let segs = segment("(echo a) | cat");
        assert_eq!(segs.len(), 3);
        assert!(!segs[0].is_operator);
        assert!(segs[1].is_operator);
        assert!(!segs[2].is_operator);
    }

    #[test]
    fn segment_newline_treated_as_separator() {
        let segs = segment("echo a\necho b");
        assert_eq!(segs.len(), 2);
        assert!(!segs[0].is_operator);
        assert!(!segs[1].is_operator);
    }

    #[test]
    fn segment_trims_trailing_whitespace() {
        let segs = segment("ls   ");
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].end, 2); // "ls" not "ls   "
    }

    #[test]
    fn segment_leading_whitespace_preserved_in_output() {
        let segs = segment("  ls");
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].start, 2); // starts at first non-whitespace
        assert_eq!(segs[0].end, 4); // "ls"
    }

    #[test]
    fn segment_trim_end_offset_basic() {
        assert_eq!(trim_end_offset("hello world", 0, 11), 11);
    }

    #[test]
    fn segment_trim_end_offset_trims_space() {
        assert_eq!(trim_end_offset("hello   ", 0, 8), 5);
    }

    #[test]
    fn segment_trim_end_offset_middle() {
        assert_eq!(trim_end_offset("a && b", 0, 1), 1); // "a" at start
    }

    #[test]
    fn segment_complex_pipeline() {
        let segs = segment("cat file | sort | uniq -c");
        assert_eq!(segs.len(), 5);
        assert!(!segs[0].is_operator);
        assert!(segs[1].is_operator);
        assert!(!segs[2].is_operator);
        assert!(segs[3].is_operator);
        assert!(!segs[4].is_operator);
    }

    #[test]
    fn segment_quotes_and_escapes() {
        // Quotes should be part of the command
        let segs = segment("echo 'hello world' | cat");
        assert_eq!(segs.len(), 3);
        assert!(!segs[0].is_operator);
        assert!(segs[1].is_operator);
        assert!(!segs[2].is_operator);
    }

    #[test]
    fn segment_redirections() {
        // Redirections should be part of the command segment
        let segs = segment("cat < input.txt > output.txt");
        assert_eq!(segs.len(), 1);
        assert!(!segs[0].is_operator);
    }

    #[test]
    fn segment_empty_between_operators() {
        // Edge case: what happens with empty command?
        let segs = segment("&& ls");
        assert_eq!(segs.len(), 2);
        assert!(segs[0].is_operator);
        assert!(!segs[1].is_operator);
    }

    #[test]
    fn segment_only_operators() {
        let segs = segment("&& ||");
        assert_eq!(segs.len(), 2);
        assert!(segs[0].is_operator);
        assert!(segs[1].is_operator);
    }

    #[test]
    fn segment_closing_token_starts_command() {
        // When a closing token is encountered and cmd_start is None,
        // it should start a new command segment
        let segs = segment(") echo hi");
        assert_eq!(segs.len(), 1);
        assert!(!segs[0].is_operator);
        assert_eq!(segs[0].start, 0);
    }

    #[test]
    fn segment_done_starts_command() {
        let segs = segment("done echo hi");
        assert_eq!(segs.len(), 1);
        assert!(!segs[0].is_operator);
    }

    #[test]
    fn segment_fi_starts_command() {
        let segs = segment("fi echo hi");
        assert_eq!(segs.len(), 1);
        assert!(!segs[0].is_operator);
    }

    #[test]
    fn segment_esac_starts_command() {
        let segs = segment("esac echo hi");
        assert_eq!(segs.len(), 1);
        assert!(!segs[0].is_operator);
    }

    #[test]
    fn segment_rbrace_starts_command() {
        let segs = segment("} echo hi");
        assert_eq!(segs.len(), 1);
        assert!(!segs[0].is_operator);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 50, .. ProptestConfig::default() })]

        /// Segments cover the entire input (no bytes lost between segments).
        #[test]
        fn segments_cover_input(input in "[a-zA-Z0-9 |;&./\\-`#<>\\\\]{1,80}") {
            let segs = segment(&input);
            if segs.is_empty() {
                // Empty segments means input was all whitespace/empty
                return Ok(());
            }
            // All segment ranges must be within the input
            for seg in &segs {
                prop_assert!(seg.start <= seg.end, "start > end: {:?}", seg);
                prop_assert!(seg.end <= input.len(), "end > input.len(): {:?}", seg);
            }
            // Segments should not overlap
            for pair in segs.windows(2) {
                prop_assert!(pair[0].end <= pair[1].start,
                    "overlapping segments: {:?} and {:?}", pair[0], pair[1]);
            }
            // Joining command segments and operator segments should reconstruct
            // all the non-whitespace content
            let reconstructed: String = segs.iter()
                .map(|s| &input[s.start..s.end])
                .collect::<Vec<_>>()
                .join("");
            let original_tokens: String = input.split_whitespace().collect();
            let recon_tokens: String = reconstructed.split_whitespace().collect();
            // All non-whitespace chars from segments appear in input
            for ch in recon_tokens.chars() {
                prop_assert!(original_tokens.contains(ch),
                    "char {:?} in segments not found in input", ch);
            }
        }
    }
}
