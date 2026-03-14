// Check subcommand — validate config and run checks.

use colored::Colorize;
use may_i_core::{ConfigWarning, ContextFacts, ContextValue};
use may_i_pp::colorize_atom;

use may_i_config as config;
use may_i_engine as engine;

use crate::output;
use crate::output::{print_trace, trace_to_json};

pub fn cmd_check(
    json_mode: bool,
    verbose: bool,
    config_path: Option<&std::path::Path>,
) -> miette::Result<()> {
    let config_file = config::resolve_path(config_path)?;
    let config = config::load(&config_file)?;
    let results = engine::run_checks(&config);

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
                    "trace": trace_to_json(&r.trace),
                })
            })
            .collect();

        let json_warnings: Vec<serde_json::Value> = config
            .warnings
            .iter()
            .map(|warning| warning_to_json(warning, &config))
            .collect();

        let output = serde_json::json!({
            "passed": passed,
            "failed": failed,
            "warnings": json_warnings,
            "results": json_results
        });
        println!(
            "{}",
            serde_json::to_string(&output).expect("response serialization is infallible")
        );
    } else {
        if !config.warnings.is_empty() {
            println!("\n{}\n", "Warnings".yellow().bold());
            for warning in &config.warnings {
                let location = warning_location(warning, &config);
                println!("  {} {}", "WARN".yellow().bold(), warning.message.yellow());
                println!("       {}", location.dimmed());
                if let Some(help) = &warning.help {
                    println!("       {} {}", "help:".dimmed(), help.dimmed());
                }
            }
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
                        format!("{} → {} (expected {})", r.command, r.actual, r.expected).red()
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

            // Location
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
                output::Row::kv("expected", output::colorize_decision_keyword(&expected_kw)),
                output::Row::kv("actual", output::colorize_decision_keyword(&actual_kw)),
            ];
            if r.context.iter().next().is_some() {
                rows.push(output::Row::kv("context", render_context(&r.context)));
            }
            if let Some(reason) = &r.reason {
                let quoted = format!("\"{reason}\"");
                rows.push(output::Row::kv("reason", colorize_atom(&quoted, true)));
            }
            output::render_elements("  ", &[output::Element::Table(rows)]);

            // Trace
            if !r.trace.is_empty() {
                println!("\n  {}\n", "Trace".bold());
                print_trace(&r.trace, "  ");
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

fn context_to_json(context: &ContextFacts) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    for (key, value) in context.iter() {
        let value = match value {
            ContextValue::Present => serde_json::Value::Bool(true),
            ContextValue::Scalar(value) => serde_json::Value::String(value.clone()),
        };
        obj.insert(key.to_string(), value);
    }
    serde_json::Value::Object(obj)
}

fn render_context(context: &ContextFacts) -> String {
    context
        .iter()
        .map(|(key, value)| match value {
            ContextValue::Present => key.to_string(),
            ContextValue::Scalar(value) => format!("{key}={value}"),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn warning_location(warning: &ConfigWarning, config: &may_i_core::Config) -> String {
    config
        .source_info
        .as_ref()
        .map(|info| info.location_of(warning.span))
        .unwrap_or_else(|| "<unknown>".to_string())
}

fn warning_to_json(warning: &ConfigWarning, config: &may_i_core::Config) -> serde_json::Value {
    serde_json::json!({
        "message": warning.message,
        "location": warning_location(warning, config),
        "help": warning.help,
    })
}
