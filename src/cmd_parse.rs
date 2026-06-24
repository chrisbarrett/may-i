use std::io::{Read, Write};

use may_i_shell_parser as parser;

use may_i::sink;

pub(crate) fn cmd_parse(
    command: Option<String>,
    file: Option<String>,
    json: bool,
) -> miette::Result<()> {
    let input = if let Some(path) = file {
        if path == "-" {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf).map_err(|e| {
                miette::miette!(
                    "Failed to read stdin: {}",
                    may_i_core::SafeText::new(e.to_string())
                )
            })?;
            buf
        } else {
            std::fs::read_to_string(&path).map_err(|e| {
                miette::miette!(
                    "Failed to read {}: {}",
                    may_i_core::SafeText::new(path),
                    may_i_core::SafeText::new(e.to_string())
                )
            })?
        }
    } else {
        // clap enforces `command` is present when `file` is absent
        command.unwrap()
    };

    let result = parser::parse(&input);

    if json {
        let json_output = serde_json::to_string_pretty(&result.command).map_err(|e| {
            miette::miette!("JSON error: {}", may_i_core::SafeText::new(e.to_string()))
        })?;
        // serde escapes control bytes; the pretty JSON is ANSI-safe.
        sink::with_stdout(|w| {
            let _ = writeln!(w, "{json_output}");
        });
    } else {
        // `{:#?}` escapes control characters in interpolated strings, so the
        // input-derived AST debug dump is display-safe.
        sink::with_stdout(|w| {
            let _ = writeln!(w, "{result:#?}");
        });
    }

    Ok(())
}
