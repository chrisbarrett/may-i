// Eval subcommand — evaluate a command and print result.

use colored::Colorize;

use may_i_config as config;
use may_i_core::{ContextFacts, Decision, EvalResult, TraceEntry};
use may_i_engine as engine;
use may_i_shell_parser as parser;

use crate::output;
use crate::output::format_trace;
use crate::runtime_facts::parse_cli_facts;

// =============================================================================
// EvalReport Builder
// =============================================================================

/// A segment of a command with its permission level.
#[derive(Debug, Clone)]
struct EvalSegment {
    text: String,
    decision: Decision,
}

/// Builder for eval command output.
/// Separates data extraction from rendering.
#[derive(Debug, Clone)]
struct EvalReport {
    command: String,
    segments: Vec<EvalSegment>,
    aggregate_result: EvalResult,
    config_path: std::path::PathBuf,
}

impl EvalReport {
    /// Evaluate a command and build a structured report.
    fn from_command(
        command: &str,
        config: &may_i_core::Config,
        context: &ContextFacts,
        config_path: &std::path::Path,
    ) -> Self {
        let segments = parser::segment(command);

        if segments.is_empty() {
            // Single command, no operators
            let result = engine::evaluate_with_context(command, config, context);
            return Self {
                command: command.to_string(),
                segments: vec![EvalSegment {
                    text: command.to_string(),
                    decision: result.decision,
                }],
                aggregate_result: result,
                config_path: config_path.to_path_buf(),
            };
        }

        // Evaluate each segment and build colored display
        let mut segment_results: Vec<EvalSegment> = Vec::new();
        let mut cmd_evals: Vec<(&str, EvalResult)> = Vec::new();

        for seg in &segments {
            let text = &command[seg.start..seg.end];
            if seg.is_operator {
                segment_results.push(EvalSegment {
                    text: text.to_string(),
                    decision: Decision::Allow, // Operators don't have a decision
                });
            } else {
                let seg_result = engine::evaluate_with_context(text, config, context);
                segment_results.push(EvalSegment {
                    text: text.to_string(),
                    decision: seg_result.decision,
                });
                cmd_evals.push((text, seg_result));
            }
        }

        // Build aggregate result
        let multi_segment = cmd_evals.len() > 1;
        let mut trace = Vec::new();
        let mut aggregate_decision = Decision::Allow;
        let mut aggregate_reason = None;

        for (idx, (text, eval)) in cmd_evals.iter().enumerate() {
            if multi_segment {
                trace.push(TraceEntry::SegmentHeader {
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

        let aggregate_result = EvalResult {
            decision: aggregate_decision,
            reason: aggregate_reason,
            trace,
        };

        Self {
            command: command.to_string(),
            segments: segment_results,
            aggregate_result,
            config_path: config_path.to_path_buf(),
        }
    }

    /// Render the report as human-readable text.
    fn render_text(&self) -> String {
        let mut output = String::new();

        // Render trace
        if !self.aggregate_result.trace.is_empty() {
            output.push_str(&format!("\n{}\n\n", "Trace".bold()));
            output.push_str(&format_trace(&self.aggregate_result.trace, "  "));
        }

        // Render result with colored command
        output.push_str(&format!("\n{}\n\n", "Result".bold()));
        let colored_command = self.render_colored_command();
        output.push_str(&format!("  {}\n\n", colored_command));

        // Render decision
        {
            use may_i_pp::colorize_atom;
            let keyword = format!(":{}", self.aggregate_result.decision);
            let colored_keyword = output::colorize_decision_keyword(&keyword);
            match &self.aggregate_result.reason {
                Some(reason) => {
                    let quoted = format!("\"{reason}\"");
                    output.push_str(&format!(
                        "  {} {colored_keyword} {}\n",
                        "→".dimmed(),
                        colorize_atom(&quoted, true)
                    ));
                }
                None => output.push_str(&format!("  {} {colored_keyword}\n", "→".dimmed())),
            }
        }

        output.push('\n');
        let display_path = output::shorten_home(&self.config_path);
        output.push_str(&format!(
            "  {} {}\n",
            "config:".dimmed(),
            display_path.dimmed()
        ));

        output
    }

    /// Render the command with colored segments.
    fn render_colored_command(&self) -> String {
        self.segments
            .iter()
            .map(|seg| {
                if seg.text.trim().is_empty()
                    || seg.text == "&&"
                    || seg.text == "||"
                    || seg.text == ";"
                {
                    // Whitespace and operators - no color
                    seg.text.clone()
                } else {
                    match seg.decision {
                        Decision::Allow => seg.text.green().underline().to_string(),
                        Decision::Ask => seg.text.yellow().underline().to_string(),
                        Decision::Deny => seg.text.red().underline().to_string(),
                    }
                }
            })
            .collect()
    }

    /// Build permission spans for JSON output using the original command string.
    /// This ensures whitespace is preserved exactly as in the original command.
    fn build_spans(&self, command: &str) -> Vec<PermissionSpan> {
        let parser_segments = parser::segment(command);

        if parser_segments.is_empty() {
            // Single command, no operators
            return vec![PermissionSpan {
                text: command.to_string(),
                permission: self.aggregate_result.decision.to_string().to_lowercase(),
            }];
        }

        let mut spans = Vec::new();
        let mut last_end = 0;
        let mut segment_iter = self.segments.iter();

        for seg in &parser_segments {
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
            } else if let Some(eval_seg) = segment_iter.next() {
                eval_seg.decision.to_string().to_lowercase()
            } else {
                "ignore".to_string()
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

        coalesce_spans(spans)
    }

    /// Render the report as JSON.
    fn to_json(&self) -> serde_json::Value {
        let spans = self.build_spans(&self.command);
        serde_json::json!({
            "decision": self.aggregate_result.decision.to_string(),
            "reason": self.aggregate_result.reason.clone().unwrap_or_default(),
            "spans": spans,
            "trace": output::trace_to_json(&self.aggregate_result.trace),
        })
    }
}

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
#[cfg(test)]
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
    use_v2: bool,
    config_path: Option<&std::path::Path>,
) -> miette::Result<()> {
    let config_file = config::resolve_path(config_path)?;
    let context = parse_cli_facts(raw_facts)?;

    if use_v2 {
        // Task 7.3: Use v2 parser and evaluator
        let v2_config = config::load_v2(&config_file)?;
        let args: Vec<String> = command
            .split_whitespace()
            .skip(1)
            .map(String::from)
            .collect();
        let cmd = command.split_whitespace().next().unwrap_or(command);
        let result = may_i_engine::v2::evaluate_v2(cmd, &args, &v2_config, &context);

        if json_mode {
            println!(
                "{}",
                serde_json::json!({
                    "decision": result.decision.to_string(),
                    "reason": result.reason.clone().unwrap_or_default(),
                })
            );
        } else {
            println!("{}: {:?}", "Decision".bold(), result.decision);
            if let Some(reason) = &result.reason {
                println!("{}: {}", "Reason".bold(), reason);
            }
        }
    } else {
        let config = config::load(&config_file)?;
        // Build the report
        let report = EvalReport::from_command(command, &config, &context, &config_file);

        if json_mode {
            let json = report.to_json();
            println!(
                "{}",
                serde_json::to_string(&json).expect("response serialization is infallible")
            );
        } else {
            let output = report.render_text();
            print!("{}", output);
        }
    }

    Ok(())
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

    // Snapshot tests for EvalReport

    fn create_test_eval_report(command: &str, decisions: Vec<Decision>) -> EvalReport {
        use may_i_core::{EvalResult, TraceEntry};

        let segments: Vec<EvalSegment> = command
            .split("&&")
            .enumerate()
            .flat_map(|(i, part)| {
                let mut result = Vec::new();
                if i > 0 {
                    result.push(EvalSegment {
                        text: "&&".to_string(),
                        decision: Decision::Allow,
                    });
                }
                let trimmed = part.trim();
                if !trimmed.is_empty() {
                    let decision = decisions.get(i).copied().unwrap_or(Decision::Allow);
                    result.push(EvalSegment {
                        text: trimmed.to_string(),
                        decision,
                    });
                }
                result
            })
            .collect();

        let aggregate_decision = decisions.iter().copied().max().unwrap_or(Decision::Allow);

        EvalReport {
            command: command.to_string(),
            segments,
            aggregate_result: EvalResult {
                decision: aggregate_decision,
                reason: Some("Test reason".to_string()),
                trace: vec![TraceEntry::SegmentHeader {
                    command: command.to_string(),
                    decision: aggregate_decision,
                }],
            },
            config_path: std::path::PathBuf::from("/test/config.yaml"),
        }
    }

    #[test]
    fn test_eval_report_render_text_single_allow() {
        let report = create_test_eval_report("ls", vec![Decision::Allow]);
        let output = report.render_text();
        insta::assert_snapshot!(output);
    }

    #[test]
    fn test_eval_report_render_text_single_ask() {
        let report = create_test_eval_report("sudo apt install", vec![Decision::Ask]);
        let output = report.render_text();
        insta::assert_snapshot!(output);
    }

    #[test]
    fn test_eval_report_render_text_single_deny() {
        let report = create_test_eval_report("rm -rf /", vec![Decision::Deny]);
        let output = report.render_text();
        insta::assert_snapshot!(output);
    }

    #[test]
    fn test_eval_report_render_text_compound() {
        let report = create_test_eval_report(
            "true && curl example.com",
            vec![Decision::Allow, Decision::Ask],
        );
        let output = report.render_text();
        insta::assert_snapshot!(output);
    }

    #[test]
    fn test_eval_report_to_json_single() {
        let report = create_test_eval_report("ls -la", vec![Decision::Allow]);
        let json = report.to_json();
        let json_str = serde_json::to_string_pretty(&json).unwrap();
        insta::assert_snapshot!(json_str);
    }

    #[test]
    fn test_eval_report_to_json_compound() {
        let report = create_test_eval_report("true && curl", vec![Decision::Allow, Decision::Ask]);
        let json = report.to_json();
        let json_str = serde_json::to_string_pretty(&json).unwrap();
        insta::assert_snapshot!(json_str);
    }

    #[test]
    fn test_eval_report_to_json_with_deny() {
        let report = create_test_eval_report("rm -rf /", vec![Decision::Deny]);
        let json = report.to_json();
        let json_str = serde_json::to_string_pretty(&json).unwrap();
        insta::assert_snapshot!(json_str);
    }
}
