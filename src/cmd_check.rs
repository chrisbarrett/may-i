// Check subcommand — validate config and run checks with trace output.

use colored::Colorize;
use may_i_pp::colorize_atom;

use may_i_config as config;
use may_i_engine as engine;
use engine::check::CheckResult;

use crate::annotation::{TraceEntry, TracingFold};
use crate::output;

struct TraceExtra {
    location: Option<String>,
    traces: Vec<TraceEntry>,
}

pub fn cmd_check(
    json_mode: bool,
    verbose: bool,
    config_path: Option<&std::path::Path>,
) -> miette::Result<()> {
    let config_file = config::resolve_path(config_path)?;
    let mut canonical_config = config::load(&config_file)?;

    // Resolve named predicates before evaluation.
    let resolved_rules =
        config::resolve::validate_and_resolve(&canonical_config.rules, &canonical_config.defines)
            .map_err(|errs| miette::miette!("Predicate resolution failed: {}", errs[0].message))?;
    canonical_config.rules = resolved_rules;

    let results = run_checks_with_traces(&canonical_config, &config_file)?;

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
                    "location": r.extra.location,
                    "reason": r.reason,
                    "trace": output::trace_to_json(&r.extra.traces),
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
        let term = output::Terminal::detect();
        if let Some(note) = output::migration_note(&canonical_config, &config_file) {
            output::write_layout(&mut std::io::stderr(), &note, &term);
        }
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
            output::print_separator("", Some((&label, label_width)), &term);
            println!();

            let loc = r.extra.location.as_deref().unwrap_or("<unknown>");
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
            output::render_elements("  ", &[output::Layout::Columns(rows)], &term);

            if !r.extra.traces.is_empty() {
                println!("\n  {}\n", "Trace".bold());
                output::print_trace(&r.extra.traces, &r.command, "  ", &term);
            }
        }

        if !failures.is_empty() {
            println!();
            output::print_separator("", None, &term);
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

/// Run all checks using TracingFold to capture traces for failure reporting.
fn run_checks_with_traces(
    config: &may_i_core::ast::Config,
    config_file: &std::path::Path,
) -> miette::Result<Vec<CheckResult<TraceExtra>>> {
    use may_i_core::span::offset_to_line_col;

    let file_str = config_file.display().to_string();

    let make_location = |span: &may_i_core::Span| -> Option<String> {
        config.source_text.as_ref().map(|source| {
            let (line, col) = offset_to_line_col(source, span.start);
            format!("{file_str}:{line}:{col}")
        })
    };

    engine::check::run_checks_with(config, |check| {
        let (cmd, args) = crate::cmd_eval::parse_command_args(&check.command);
        let mut fold = TracingFold::new()
            .with_source_text(config.source_text.clone())
            .with_pre_migration_forms(config.pre_migration_forms.clone());
        let result =
            engine::eval::evaluate_with_fold(&cmd, &args, config, &check.context, &mut fold)
                .map_err(|e| miette::miette!("{e}"))?;
        Ok((result, TraceExtra {
            location: make_location(&check.span),
            traces: fold.traces,
        }))
    })
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
