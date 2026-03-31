// Check subcommand — validate config and run checks with trace output.

use colored::Colorize;
use may_i_pp::colorize_atom;

use may_i_config as config;
use may_i_engine as engine;

use crate::annotation::{TraceEntry, TracingFold};
use crate::output;

pub fn cmd_check(
    json_mode: bool,
    verbose: bool,
    config_path: Option<&std::path::Path>,
) -> miette::Result<()> {
    let config_file = config::resolve_path(config_path)?;
    let mut canonical_config = config::load(&config_file)?;

    // Resolve named predicates before evaluation.
    let (resolved_rules, _) =
        config::resolve::validate_and_resolve(&canonical_config.rules, &canonical_config.defines)
            .map_err(|errs| miette::miette!("Predicate resolution failed: {}", errs[0].message))?;
    canonical_config.rules = resolved_rules;

    let results = run_checks_with_traces(&canonical_config);

    let passed = results.iter().filter(|r| r.passed).count();
    let failed = results.len() - passed;

    if json_mode {
        let json_results: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "command": r.command,
                    "expected": r.expected.to_string(),
                    "actual": r.actual.to_string(),
                    "passed": r.passed,
                    "context": context_to_json(&r.context),
                    "location": r.location,
                    "reason": r.reason,
                    "trace": output::trace_to_json(&r.traces),
                })
            })
            .collect();

        let output = serde_json::json!({
            "passed": passed,
            "failed": failed,
            "results": json_results
        });
        println!(
            "{}",
            serde_json::to_string(&output).expect("response serialization is infallible")
        );
    } else {
        let mut failures = Vec::new();

        for r in &results {
            if verbose {
                if r.passed {
                    println!(
                        "  {} {}",
                        "PASS".green().bold(),
                        format!("{} → {}", r.command, r.actual).dimmed()
                    );
                } else {
                    println!(
                        "  {} {}",
                        "FAIL".red().bold(),
                        format!("{} → {} (expected {})", r.command, r.actual, r.expected)
                            .truecolor(255, 165, 0)
                    );
                }
            }
            if !r.passed {
                failures.push(r);
            }
        }

        for (i, r) in failures.iter().enumerate() {
            if i > 0 {
                println!();
            }

            println!();
            let icon = "✗".red().bold().to_string();
            let label = format!("{icon} {}", r.command.bold());
            let label_width = 2 + r.command.len();
            output::print_separator("", Some((&label, label_width)));
            println!();

            let loc = r.location.as_deref().unwrap_or("<unknown>");
            let (file, line_col) = loc.split_once(':').unwrap_or((loc, ""));
            let short_file = output::shorten_home(std::path::Path::new(file));
            print!("{}", short_file.dimmed());
            if !line_col.is_empty() {
                print!("{}", format!(":{line_col}").dimmed());
            }
            println!();

            let expected_kw = format!(":{}", r.expected);
            let actual_kw = format!(":{}", r.actual);
            let mut rows = vec![
                output::ColRow::kv("expected", output::colorize_decision_keyword(&expected_kw)),
                output::ColRow::kv("actual", output::colorize_decision_keyword(&actual_kw)),
            ];
            if r.context.iter().next().is_some() {
                rows.push(output::ColRow::kv("context", render_context(&r.context)));
            }
            if let Some(reason) = &r.reason {
                let quoted = format!("\"{reason}\"");
                rows.push(output::ColRow::kv("reason", colorize_atom(&quoted, true)));
            }
            output::render_elements("  ", &[output::Layout::Columns(rows)]);

            if !r.traces.is_empty() {
                println!("\n  {}\n", "Trace".bold());
                output::print_trace(&r.traces, &r.command, "  ");
            }
        }

        if !failures.is_empty() {
            println!();
            output::print_separator("", None);
        }
        println!("\n{}\n", "Summary".bold());
        let icon = if failed > 0 {
            "✗".red()
        } else {
            "✓".green()
        };
        println!(
            "  {icon} {} passed, {} failed",
            passed.to_string().bold(),
            failed.to_string().bold()
        );
        println!();
        let display_path = output::shorten_home(&config_file);
        println!("  {} {}", "config:".dimmed(), display_path.dimmed());
    }

    if failed > 0 {
        std::process::exit(1);
    }

    Ok(())
}

/// Check result with trace data for CLI output.
struct CheckResultWithTrace {
    command: String,
    expected: may_i_core::Decision,
    actual: may_i_core::Decision,
    passed: bool,
    context: may_i_core::ContextFacts,
    reason: Option<String>,
    location: Option<String>,
    traces: Vec<TraceEntry>,
}

/// Run all checks using TracingFold to capture traces for failure reporting.
fn run_checks_with_traces(config: &may_i_core::ast::Config) -> Vec<CheckResultWithTrace> {
    use may_i_shell_parser::{self as parser, Command, Word, WordPart};

    fn word_to_string(word: &Word) -> String {
        word.parts
            .iter()
            .map(|part| match part {
                WordPart::Literal(s) => s.clone(),
                WordPart::SingleQuoted(s) => s.clone(),
                WordPart::DoubleQuoted(parts) => parts
                    .iter()
                    .map(|p| match p {
                        WordPart::Literal(s) => s.clone(),
                        _ => String::new(),
                    })
                    .collect(),
                _ => String::new(),
            })
            .collect()
    }

    fn evaluate_with_trace(
        input: &str,
        config: &may_i_core::ast::Config,
        context: &may_i_core::ContextFacts,
    ) -> (engine::EvalResult, Vec<TraceEntry>) {
        let cmd = parser::parse(input);
        match cmd {
            Command::Simple(sc) if !sc.words.is_empty() => {
                let cmd_name = word_to_string(&sc.words[0]);
                let args: Vec<String> = sc.words[1..].iter().map(word_to_string).collect();
                let mut fold = TracingFold::new().with_initial_facts(context);
                let result =
                    engine::eval::evaluate_with_fold(&cmd_name, &args, config, context, &mut fold);
                (result, fold.traces)
            }
            Command::Simple(_) => (
                engine::EvalResult::new(may_i_core::Decision::Allow, None),
                Vec::new(),
            ),
            _ => (
                engine::EvalResult::new(
                    may_i_core::Decision::Ask,
                    Some("Compound commands not yet supported in checks".into()),
                ),
                Vec::new(),
            ),
        }
    }

    let mut results = Vec::new();

    for rule in &config.rules {
        for check in &rule.checks {
            let (eval, traces) = evaluate_with_trace(&check.command, config, &check.context);
            results.push(CheckResultWithTrace {
                command: check.command.clone(),
                expected: check.expected,
                actual: eval.decision,
                passed: eval.decision == check.expected,
                context: check.context.clone(),
                reason: eval.reason,
                location: None,
                traces,
            });
        }
    }

    for check in &config.checks {
        let (eval, traces) = evaluate_with_trace(&check.command, config, &check.context);
        results.push(CheckResultWithTrace {
            command: check.command.clone(),
            expected: check.expected,
            actual: eval.decision,
            passed: eval.decision == check.expected,
            context: check.context.clone(),
            reason: eval.reason,
            location: None,
            traces,
        });
    }

    results
}

fn context_to_json(context: &may_i_core::ContextFacts) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    for (key, values) in context.iter() {
        if values.is_empty() {
            obj.insert(key.to_string(), serde_json::Value::Bool(true));
        } else if values.len() == 1 {
            obj.insert(
                key.to_string(),
                serde_json::Value::String(values.iter().next().unwrap().clone()),
            );
        } else {
            let arr: Vec<serde_json::Value> = values
                .iter()
                .map(|v| serde_json::Value::String(v.clone()))
                .collect();
            obj.insert(key.to_string(), serde_json::Value::Array(arr));
        }
    }
    serde_json::Value::Object(obj)
}

fn render_context(context: &may_i_core::ContextFacts) -> String {
    context
        .iter()
        .map(|(key, values)| {
            if values.is_empty() {
                key.to_string()
            } else {
                let vals: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
                format!("{key}={}", vals.join(","))
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}
