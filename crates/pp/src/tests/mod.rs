// Test-only debug diagnostics print to stdout; the workspace `print_stdout`
// deny targets production code (the sink), not test scaffolding.
#![allow(clippy::print_stdout)]

mod annotated_lines;
mod properties;
mod rendering;
mod trivia;
mod width;
