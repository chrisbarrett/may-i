// Check subcommand — validate config and run checks.

use colored::Colorize;

use may_i_core::LoadError;
use may_i_config as config;
use may_i_engine as engine;

use crate::output::print_trace;

pub fn cmd_check(json_mode: bool, verbose: bool, config_path: Option<&std::path::Path>) -> Result<(), LoadError> {
    let config = config::load(config_path)?;
    let results = engine::run_checks(&config);

    let mut passed = 0;
    let mut failed = 0;

    if json_mode {
        let json_results: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                if r.passed {
                    passed += 1;
                } else {
                    failed += 1;
                }
                serde_json::json!({
                    "command": r.command,
                    "expected": r.expected.to_string(),
                    "actual": r.actual.to_string(),
                    "passed": r.passed,
                    "location": r.location,
                    "reason": r.reason,
                    "trace": r.trace,
                })
            })
            .collect();

        let output = serde_json::json!({
            "passed": passed,
            "failed": failed,
            "results": json_results
        });
        println!("{}", serde_json::to_string(&output).unwrap());
    } else {
        let mut failures = Vec::new();

        for r in &results {
            if r.passed {
                passed += 1;
                if verbose {
                    println!("  {} {}", "PASS".green().bold(), format!("{} → {}", r.command, r.actual).dimmed());
                }
            } else {
                failed += 1;
                if verbose {
                    println!("  {} {}", "FAIL".red().bold(), format!("{} → {} (expected {})", r.command, r.actual, r.expected).truecolor(255, 165, 0));
                }
                failures.push(r);
            }
        }

        if !failures.is_empty() {
            println!("\n{}\n", "Failures".bold());
            for r in &failures {
                let loc = r.location.as_deref().unwrap_or("<unknown>");
                let (file, line_col) = loc.split_once(':').unwrap_or((loc, ""));
                print!("{}", file.red());
                if !line_col.is_empty() {
                    print!("{}", format!(":{line_col}").dimmed());
                }
                println!(": {}", r.command.bold());
                println!("  expected: {}", r.expected.to_string().green());
                println!("  actual:   {}", r.actual.to_string().red());
                if let Some(reason) = &r.reason {
                    println!("  reason:   {}", reason.italic());
                }
                if !r.trace.is_empty() {
                    println!("  trace:");
                    print_trace(&r.trace, "    ");
                }
                println!();
            }
        }

        println!("{}\n", "Summary".bold());
        println!("  {passed} passed, {failed} failed");
    }

    if failed > 0 {
        Err(LoadError::CheckFailure(format!("{failed} check(s) failed")))
    } else {
        Ok(())
    }
}
