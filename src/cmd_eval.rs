// Eval subcommand — evaluate a command and print result.

use colored::Colorize;

use may_i_config as config;
use may_i_core::{ContextFacts, Decision};
use may_i_engine as engine;
use may_i_shell_parser as parser;

use crate::output;
use crate::output::print_trace;
use crate::runtime_facts::parse_cli_facts;

/// A span of source text with its permission level
#[derive(Debug, Clone, serde::Serialize)]
struct PermissionSpan {
    /// The exact source text for this span
    text: String,
    /// The permission level: "allow", "ask", "deny", or "ignore"
    permission: String,
}

/// Coalesce consecutive spans with "ignore" permission.
/// Merges adjacent ignore spans while preserving all other spans.
fn coalesce_spans(spans: Vec<PermissionSpan>) -> Vec<PermissionSpan> {
    if spans.is_empty() {
        return spans;
    }

    let mut result = Vec::with_capacity(spans.len());
    let mut current_ignore: Option<String> = None;

    for span in spans {
        if span.permission == "ignore" {
            // Accumulate ignore spans
            match current_ignore {
                Some(ref mut text) => text.push_str(&span.text),
                None => current_ignore = Some(span.text),
            }
        } else {
            // Flush any accumulated ignore span first
            if let Some(text) = current_ignore.take() {
                result.push(PermissionSpan {
                    text,
                    permission: "ignore".to_string(),
                });
            }
            // Add the non-ignore span
            result.push(span);
        }
    }

    // Flush trailing ignore span
    if let Some(text) = current_ignore {
        result.push(PermissionSpan {
            text,
            permission: "ignore".to_string(),
        });
    }

    result
}

/// Build permission spans from command segments and their evaluation decisions.
/// Handles gaps between segments (whitespace) and maps operators to "ignore".
fn build_spans(
    command: &str,
    segments: &[parser::Segment],
    decisions: &[Decision],
) -> Vec<PermissionSpan> {
    let mut spans = Vec::new();
    let mut last_end = 0;
    let mut decision_iter = decisions.iter();

    for seg in segments {
        // Handle gap before this segment (whitespace)
        if seg.start > last_end {
            spans.push(PermissionSpan {
                text: command[last_end..seg.start].to_string(),
                permission: "ignore".to_string(),
            });
        }

        let text = &command[seg.start..seg.end];
        let permission = if seg.is_operator {
            "ignore".to_string()
        } else {
            decision_iter
                .next()
                .map_or("ignore".to_string(), |d| d.to_string().to_lowercase())
        };

        spans.push(PermissionSpan {
            text: text.to_string(),
            permission,
        });

        last_end = seg.end;
    }

    // Handle trailing whitespace
    if last_end < command.len() {
        spans.push(PermissionSpan {
            text: command[last_end..].to_string(),
            permission: "ignore".to_string(),
        });
    }

    spans
}

pub fn cmd_eval(
    command: &str,
    raw_facts: &[String],
    json_mode: bool,
    config_path: Option<&std::path::Path>,
) -> miette::Result<()> {
    let config_file = config::resolve_path(config_path)?;
    let config = config::load(&config_file)?;
    let context = parse_cli_facts(raw_facts)?;

    if json_mode {
        let (result, spans) = evaluate_segments_json(command, &config, &context);
        let json = serde_json::json!({
            "decision": result.decision.to_string(),
            "reason": result.reason.unwrap_or_default(),
            "spans": spans,
            "trace": crate::output::trace_to_json(&result.trace),
        });
        println!(
            "{}",
            serde_json::to_string(&json).expect("response serialization is infallible")
        );
    } else {
        // Evaluate per-segment so we can both colorize and derive the aggregate result.
        let (result, colored_command) = evaluate_segments(command, &config, &context);

        if !result.trace.is_empty() {
            println!("\n{}\n", "Trace".bold());
            print_trace(&result.trace, "  ");
        }

        println!("\n{}\n", "Result".bold());
        println!("  {colored_command}");
        println!();
        {
            use may_i_pp::colorize_atom;
            let keyword = format!(":{}", result.decision);
            let colored_keyword = output::colorize_decision_keyword(&keyword);
            match &result.reason {
                Some(reason) => {
                    let quoted = format!("\"{reason}\"");
                    println!(
                        "  {} {colored_keyword} {}",
                        "→".dimmed(),
                        colorize_atom(&quoted, true)
                    );
                }
                None => println!("  {} {colored_keyword}", "→".dimmed()),
            }
        }
        println!();
        let display_path = output::shorten_home(&config_file);
        println!("  {} {}", "config:".dimmed(), display_path.dimmed());
    }

    Ok(())
}

/// Evaluate each segment of a command for JSON output, returning the aggregate
/// result and permission spans for each segment.
fn evaluate_segments_json(
    command: &str,
    config: &may_i_core::Config,
    context: &ContextFacts,
) -> (may_i_core::EvalResult, Vec<PermissionSpan>) {
    let segments = parser::segment(command);

    if segments.is_empty() {
        let result = engine::evaluate_with_context(command, config, context);
        let spans = vec![PermissionSpan {
            text: command.to_string(),
            permission: result.decision.to_string().to_lowercase(),
        }];
        return (result, spans);
    }

    // Evaluate each non-operator segment, collecting results
    let mut segment_decisions: Vec<Decision> = Vec::new();
    let mut cmd_evals: Vec<(&str, may_i_core::EvalResult)> = Vec::new();

    for seg in &segments {
        let text = &command[seg.start..seg.end];
        if !seg.is_operator {
            let seg_result = engine::evaluate_with_context(text, config, context);
            segment_decisions.push(seg_result.decision);
            cmd_evals.push((text, seg_result));
        }
    }

    // Build spans using the decisions
    let spans = build_spans(command, &segments, &segment_decisions);

    // Coalesce adjacent ignore spans for cleaner JSON output
    let spans = coalesce_spans(spans);

    // Build aggregate result
    let mut trace = Vec::new();
    let mut aggregate_decision = Decision::Allow;
    let mut aggregate_reason = None;
    let multi_segment = cmd_evals.len() > 1;

    for (idx, (text, eval)) in cmd_evals.iter().enumerate() {
        // Only add segment headers for multi-segment commands
        if multi_segment {
            trace.push(may_i_core::TraceEntry::SegmentHeader {
                command: text.to_string(),
                decision: eval.decision,
            });
        }
        trace.extend(eval.trace.iter().cloned());

        // Set reason for first segment, or update when finding higher decision
        if idx == 0 || eval.decision > aggregate_decision {
            aggregate_decision = eval.decision;
            aggregate_reason = eval.reason.clone();
        }
    }

    let result = may_i_core::EvalResult {
        decision: aggregate_decision,
        reason: aggregate_reason,
        trace,
    };

    (result, spans)
}

/// Evaluate each segment of a command, returning the aggregate result and a
/// colorized display string. This avoids evaluating the entire command twice.
fn evaluate_segments(
    command: &str,
    config: &may_i_core::Config,
    context: &ContextFacts,
) -> (may_i_core::EvalResult, String) {
    let segments = parser::segment(command);

    if segments.is_empty() {
        return (
            engine::evaluate_with_context(command, config, context),
            command.to_string(),
        );
    }

    // Evaluate each command segment, collecting (text, result) pairs.
    let mut display_parts = Vec::new();
    let mut cmd_evals: Vec<(&str, may_i_core::EvalResult)> = Vec::new();
    for seg in &segments {
        let text = &command[seg.start..seg.end];
        if seg.is_operator {
            display_parts.push(format!(" {text} "));
        } else {
            let seg_result = engine::evaluate_with_context(text, config, context);
            let colored = match seg_result.decision {
                Decision::Allow => text.green().underline().to_string(),
                Decision::Ask => text.yellow().underline().to_string(),
                Decision::Deny => text.red().underline().to_string(),
            };
            display_parts.push(colored);
            cmd_evals.push((text, seg_result));
        }
    }

    let multi_segment = cmd_evals.len() > 1;

    // Build aggregate trace with segment headers for compound commands.
    let mut trace = Vec::new();
    let mut aggregate_decision = Decision::Allow;
    let mut aggregate_reason = None;

    for (text, eval) in &cmd_evals {
        if multi_segment {
            trace.push(may_i_core::TraceEntry::SegmentHeader {
                command: text.to_string(),
                decision: eval.decision,
            });
        }
        trace.extend(eval.trace.iter().cloned());
        if eval.decision > aggregate_decision {
            aggregate_decision = eval.decision;
            aggregate_reason = eval.reason.clone();
        }
    }

    let result = may_i_core::EvalResult {
        decision: aggregate_decision,
        reason: aggregate_reason,
        trace,
    };

    (result, display_parts.concat())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_spans_empty_command() {
        let segments: Vec<parser::Segment> = vec![];
        let decisions: Vec<Decision> = vec![];
        let spans = build_spans("", &segments, &decisions);
        assert!(spans.is_empty());
    }

    #[test]
    fn test_build_spans_single_command() {
        let command = "ls";
        let segments = vec![parser::Segment {
            start: 0,
            end: 2,
            is_operator: false,
        }];
        let decisions = vec![Decision::Allow];
        let spans = build_spans(command, &segments, &decisions);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].text, "ls");
        assert_eq!(spans[0].permission, "allow");
    }

    #[test]
    fn test_build_spans_with_operator() {
        let command = "true && curl";
        let segments = vec![
            parser::Segment {
                start: 0,
                end: 4,
                is_operator: false,
            },
            parser::Segment {
                start: 5,
                end: 7,
                is_operator: true,
            },
            parser::Segment {
                start: 8,
                end: 12,
                is_operator: false,
            },
        ];
        let decisions = vec![Decision::Allow, Decision::Ask];
        let spans = build_spans(command, &segments, &decisions);
        // Spans: "true", " ", "&&", " ", "curl"
        assert_eq!(spans.len(), 5);
        assert_eq!(spans[0].text, "true");
        assert_eq!(spans[0].permission, "allow");
        assert_eq!(spans[1].text, " ");
        assert_eq!(spans[1].permission, "ignore");
        assert_eq!(spans[2].text, "&&");
        assert_eq!(spans[2].permission, "ignore");
        assert_eq!(spans[3].text, " ");
        assert_eq!(spans[3].permission, "ignore");
        assert_eq!(spans[4].text, "curl");
        assert_eq!(spans[4].permission, "ask");
    }

    #[test]
    fn test_build_spans_leading_trailing_whitespace() {
        let command = "  ls  ";
        let segments = vec![parser::Segment {
            start: 2,
            end: 4,
            is_operator: false,
        }];
        let decisions = vec![Decision::Allow];
        let spans = build_spans(command, &segments, &decisions);
        assert_eq!(spans.len(), 3);
        assert_eq!(spans[0].text, "  ");
        assert_eq!(spans[0].permission, "ignore");
        assert_eq!(spans[1].text, "ls");
        assert_eq!(spans[1].permission, "allow");
        assert_eq!(spans[2].text, "  ");
        assert_eq!(spans[2].permission, "ignore");
    }

    #[test]
    fn test_build_spans_multiple_operators() {
        let command = "a && b || c";
        let segments = vec![
            parser::Segment {
                start: 0,
                end: 1,
                is_operator: false,
            },
            parser::Segment {
                start: 2,
                end: 4,
                is_operator: true,
            },
            parser::Segment {
                start: 5,
                end: 6,
                is_operator: false,
            },
            parser::Segment {
                start: 7,
                end: 9,
                is_operator: true,
            },
            parser::Segment {
                start: 10,
                end: 11,
                is_operator: false,
            },
        ];
        let decisions = vec![Decision::Allow, Decision::Deny, Decision::Ask];
        let spans = build_spans(command, &segments, &decisions);
        // Spans: "a", " ", "&&", " ", "b", " ", "||", " ", "c"
        assert_eq!(spans.len(), 9);
        assert_eq!(spans[0].text, "a");
        assert_eq!(spans[0].permission, "allow");
        assert_eq!(spans[1].text, " ");
        assert_eq!(spans[1].permission, "ignore");
        assert_eq!(spans[2].text, "&&");
        assert_eq!(spans[2].permission, "ignore");
        assert_eq!(spans[3].text, " ");
        assert_eq!(spans[3].permission, "ignore");
        assert_eq!(spans[4].text, "b");
        assert_eq!(spans[4].permission, "deny");
        assert_eq!(spans[5].text, " ");
        assert_eq!(spans[5].permission, "ignore");
        assert_eq!(spans[6].text, "||");
        assert_eq!(spans[6].permission, "ignore");
        assert_eq!(spans[7].text, " ");
        assert_eq!(spans[7].permission, "ignore");
        assert_eq!(spans[8].text, "c");
        assert_eq!(spans[8].permission, "ask");

        // Verify coalescing works correctly
        let coalesced = coalesce_spans(spans);
        assert_eq!(coalesced.len(), 5);
        assert_eq!(coalesced[0].text, "a");
        assert_eq!(coalesced[0].permission, "allow");
        assert_eq!(coalesced[1].text, " && ");
        assert_eq!(coalesced[1].permission, "ignore");
        assert_eq!(coalesced[2].text, "b");
        assert_eq!(coalesced[2].permission, "deny");
        assert_eq!(coalesced[3].text, " || ");
        assert_eq!(coalesced[3].permission, "ignore");
        assert_eq!(coalesced[4].text, "c");
        assert_eq!(coalesced[4].permission, "ask");
    }

    #[test]
    fn test_build_spans_reproduces_original_command() {
        let command = "  true && curl example.com  ";
        let segments = vec![
            parser::Segment {
                start: 2,
                end: 6,
                is_operator: false,
            },
            parser::Segment {
                start: 7,
                end: 9,
                is_operator: true,
            },
            parser::Segment {
                start: 10,
                end: 27,
                is_operator: false,
            },
        ];
        let decisions = vec![Decision::Allow, Decision::Ask];
        let spans = build_spans(command, &segments, &decisions);
        let reconstructed: String = spans.iter().map(|s| &s.text[..]).collect();
        assert_eq!(reconstructed, command);
    }

    // Tests for coalesce_spans function

    #[test]
    fn test_coalesce_spans_empty() {
        let spans: Vec<PermissionSpan> = vec![];
        let result = coalesce_spans(spans);
        assert!(result.is_empty());
    }

    #[test]
    fn test_coalesce_spans_single() {
        let spans = vec![PermissionSpan {
            text: "ls".to_string(),
            permission: "allow".to_string(),
        }];
        let result = coalesce_spans(spans.clone());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].text, "ls");
        assert_eq!(result[0].permission, "allow");
    }

    #[test]
    fn test_coalesce_spans_two_consecutive_ignore() {
        let spans = vec![
            PermissionSpan {
                text: " ".to_string(),
                permission: "ignore".to_string(),
            },
            PermissionSpan {
                text: "&&".to_string(),
                permission: "ignore".to_string(),
            },
        ];
        let result = coalesce_spans(spans);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].text, " &&");
        assert_eq!(result[0].permission, "ignore");
    }

    #[test]
    fn test_coalesce_spans_ignore_allow_ignore() {
        let spans = vec![
            PermissionSpan {
                text: " ".to_string(),
                permission: "ignore".to_string(),
            },
            PermissionSpan {
                text: "ls".to_string(),
                permission: "allow".to_string(),
            },
            PermissionSpan {
                text: " ".to_string(),
                permission: "ignore".to_string(),
            },
        ];
        let result = coalesce_spans(spans);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].text, " ");
        assert_eq!(result[0].permission, "ignore");
        assert_eq!(result[1].text, "ls");
        assert_eq!(result[1].permission, "allow");
        assert_eq!(result[2].text, " ");
        assert_eq!(result[2].permission, "ignore");
    }

    #[test]
    fn test_coalesce_spans_multiple_ignore() {
        let spans = vec![
            PermissionSpan {
                text: " ".to_string(),
                permission: "ignore".to_string(),
            },
            PermissionSpan {
                text: "&&".to_string(),
                permission: "ignore".to_string(),
            },
            PermissionSpan {
                text: " ".to_string(),
                permission: "ignore".to_string(),
            },
            PermissionSpan {
                text: "||".to_string(),
                permission: "ignore".to_string(),
            },
        ];
        let result = coalesce_spans(spans);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].text, " && ||");
        assert_eq!(result[0].permission, "ignore");
    }

    #[test]
    fn test_coalesce_spans_no_ignore() {
        let spans = vec![
            PermissionSpan {
                text: "true".to_string(),
                permission: "allow".to_string(),
            },
            PermissionSpan {
                text: "curl".to_string(),
                permission: "ask".to_string(),
            },
            PermissionSpan {
                text: "rm".to_string(),
                permission: "deny".to_string(),
            },
        ];
        let result = coalesce_spans(spans.clone());
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].text, "true");
        assert_eq!(result[0].permission, "allow");
        assert_eq!(result[1].text, "curl");
        assert_eq!(result[1].permission, "ask");
        assert_eq!(result[2].text, "rm");
        assert_eq!(result[2].permission, "deny");
    }

    #[test]
    fn test_coalesce_spans_mixed_permissions() {
        let spans = vec![
            PermissionSpan {
                text: "true".to_string(),
                permission: "allow".to_string(),
            },
            PermissionSpan {
                text: " ".to_string(),
                permission: "ignore".to_string(),
            },
            PermissionSpan {
                text: "sudo".to_string(),
                permission: "ask".to_string(),
            },
            PermissionSpan {
                text: " ".to_string(),
                permission: "ignore".to_string(),
            },
            PermissionSpan {
                text: "rm -rf".to_string(),
                permission: "deny".to_string(),
            },
        ];
        let result = coalesce_spans(spans);
        assert_eq!(result.len(), 5);
        assert_eq!(result[0].permission, "allow");
        assert_eq!(result[1].permission, "ignore");
        assert_eq!(result[2].permission, "ask");
        assert_eq!(result[3].permission, "ignore");
        assert_eq!(result[4].permission, "deny");
    }

    #[test]
    fn test_coalesce_spans_preserves_reconstruction() {
        // Simulate spans from "true && curl"
        let spans = vec![
            PermissionSpan {
                text: "true".to_string(),
                permission: "allow".to_string(),
            },
            PermissionSpan {
                text: " ".to_string(),
                permission: "ignore".to_string(),
            },
            PermissionSpan {
                text: "&&".to_string(),
                permission: "ignore".to_string(),
            },
            PermissionSpan {
                text: " ".to_string(),
                permission: "ignore".to_string(),
            },
            PermissionSpan {
                text: "curl".to_string(),
                permission: "ask".to_string(),
            },
        ];
        let original: String = spans.iter().map(|s| &s.text[..]).collect();
        let coalesced = coalesce_spans(spans);
        let reconstructed: String = coalesced.iter().map(|s| &s.text[..]).collect();
        assert_eq!(reconstructed, original);
        assert_eq!(reconstructed, "true && curl");
    }
}
