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
                        segments.push(Segment { start, end, is_operator: false });
                    }
                }
            }
            // Depth-increasing tokens
            Token::LParen | Token::If | Token::For | Token::While | Token::Until
            | Token::Case | Token::Do | Token::LBrace => {
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
            Token::Pipe | Token::And | Token::Or | Token::Semi | Token::Amp
                if depth <= 0 =>
            {
                // Flush the command segment before this operator
                if let Some(start) = cmd_start.take() {
                    let end = trim_end_offset(input, start, *byte_off);
                    if end > start {
                        segments.push(Segment { start, end, is_operator: false });
                    }
                }
                // Add the operator segment
                let op_len = match tok {
                    Token::And | Token::Or => 2,
                    _ => 1,
                };
                segments.push(Segment { start: *byte_off, end: byte_off + op_len, is_operator: true });
            }
            // Newlines are treated like semicolons at depth 0
            Token::Newline if depth <= 0 => {
                if let Some(start) = cmd_start.take() {
                    let end = trim_end_offset(input, start, *byte_off);
                    if end > start {
                        segments.push(Segment { start, end, is_operator: false });
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
