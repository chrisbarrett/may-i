// Falsifiable proof for the display-safe-output boundary.
//
// Drives adversarial input — raw `\x1b`, ANSI-C `$'\n'`-style control bytes,
// and arbitrary control characters embedded in command names, argv, regex
// actuals, and captured values — through the real `render_eval` / `render_check`
// / trace render surfaces, then asserts:
//
//  - colour OFF: the bytes delivered to the sink contain no control character
//    (other than the `\n` line separator). With colour off the renderer emits
//    no SGR, so any control byte in the output would be an injection.
//  - colour ON: every `\x1b` introduces a well-formed SGR sequence whose
//    parameters are drawn from the role palette, and no other control byte
//    appears.

use std::io::Write;

use may_i::cmd_eval::evaluate_with_colorization;
use may_i::output::{CheckOutput, CheckResultView, EvalOutput};
use may_i_core::{ContextFacts, Decision};
use may_i_output::Terminal;
use proptest::prelude::*;
use tempfile::NamedTempFile;

/// SGR parameter strings the renderer's role palette can emit (plus the `0`
/// reset). Mirrors `may_i_output`'s `sgr_params` table.
const PALETTE: &[&str] = &[
    "0", "1", "2", "3", "31", "32", "33", "34", "36", "94", "1;31", "1;32", "1;33", "1;34", "3;33",
    "4;31", "4;32", "4;33",
];

/// A string mixing normal command text with adversarial control bytes:
/// `\x1b` (escape), `\n`/`\r`/`\t`, a C1 control, and `\0`.
fn adversarial() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof![
            "[a-z/ .\"#()-]{1,6}",
            Just("\u{1b}".to_string()),
            Just("\u{1b}[31m".to_string()),
            Just("\n".to_string()),
            Just("\r".to_string()),
            Just("\t".to_string()),
            Just("\u{7}".to_string()),
            Just("\u{0}".to_string()),
            Just("\u{85}".to_string()),
        ],
        1..8,
    )
    .prop_map(|parts| parts.concat())
}

fn load(config_src: &str) -> may_i_config::LoadResult {
    let mut tmp = NamedTempFile::new().expect("tempfile");
    tmp.write_all(config_src.as_bytes()).expect("write");
    let mut loaded = may_i_config::load(tmp.path()).expect("load");
    let resolved =
        may_i_config::resolve::validate_and_resolve(&loaded.config.rules, &loaded.config.defines)
            .expect("resolve");
    loaded.config.rules = resolved;
    loaded
}

/// Evaluate `command` and render the full eval surface (trace + result block)
/// at the given colour setting.
fn render_eval_surface(loaded: &may_i_config::LoadResult, command: &str, color: bool) -> Vec<u8> {
    let ctx = ContextFacts::default();
    let (result, traces, colored, _audit) =
        evaluate_with_colorization(command, loaded, &ctx, &may_i_core::EntryEnv::empty())
            .expect("evaluate");
    let term = Terminal::new(100).with_color(color);
    let mut buf = Vec::new();
    EvalOutput {
        config_path: std::path::Path::new("cfg.lisp"),
        trace_entries: &traces,
        command,
        colored_command: &colored,
        eval_result: &result,
    }
    .render(&mut buf, &term);
    buf
}

/// Render the check surface for an adversarial command + reason.
fn render_check_surface(command: &str, reason: &str, color: bool) -> Vec<u8> {
    let ctx = ContextFacts::default();
    let views = vec![CheckResultView {
        command,
        expected: Decision::Deny,
        actual: Decision::Allow,
        passed: false,
        context: &ctx,
        location: Some("cfg.lisp:1:1"),
        reason: Some(reason),
        traces: &[],
    }];
    let term = Terminal::new(100).with_color(color);
    let mut buf = Vec::new();
    CheckOutput {
        config_path: std::path::Path::new("cfg.lisp"),
        results: &views,
        verbose: true,
        untested_scope_rules: &[],
    }
    .render(&mut buf, &term);
    buf
}

/// Assert no control character other than `\n` is present.
fn assert_control_free(bytes: &[u8]) -> Result<(), TestCaseError> {
    let s = String::from_utf8_lossy(bytes);
    for c in s.chars() {
        prop_assert!(
            c == '\n' || !c.is_control(),
            "control char {:?} leaked into colour-off output: {:?}",
            c,
            s
        );
    }
    Ok(())
}

/// Assert every `\x1b` starts a well-formed SGR `\x1b[<palette>m` and no other
/// control character (besides `\n`) appears.
fn assert_only_palette_sgr(bytes: &[u8]) -> Result<(), TestCaseError> {
    let s = String::from_utf8_lossy(bytes);
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\x1b' {
            // Expect `[`, then params [0-9;]+, then `m`.
            prop_assert!(
                chars.get(i + 1) == Some(&'['),
                "ESC not followed by '[': {s:?}"
            );
            let mut j = i + 2;
            let mut params = String::new();
            while j < chars.len() && (chars[j].is_ascii_digit() || chars[j] == ';') {
                params.push(chars[j]);
                j += 1;
            }
            prop_assert!(
                chars.get(j) == Some(&'m'),
                "SGR not terminated by 'm': {s:?}"
            );
            prop_assert!(
                PALETTE.contains(&params.as_str()),
                "SGR params {params:?} not in role palette: {s:?}"
            );
            i = j + 1;
        } else {
            prop_assert!(
                c == '\n' || !c.is_control(),
                "non-SGR control char {:?} in colour-on output: {:?}",
                c,
                s
            );
            i += 1;
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// Colour off: adversarial command through the eval+trace surface is
    /// control-free.
    #[test]
    fn eval_colour_off_is_control_free(command in adversarial()) {
        let loaded = load("(rule \"git\" (allow \"ok\"))\n");
        let bytes = render_eval_surface(&loaded, &command, false);
        assert_control_free(&bytes)?;
    }

    /// Colour on: adversarial command through the eval+trace surface emits only
    /// palette SGR.
    #[test]
    fn eval_colour_on_palette_only(command in adversarial()) {
        let loaded = load("(rule \"git\" (allow \"ok\"))\n");
        let bytes = render_eval_surface(&loaded, &command, true);
        assert_only_palette_sgr(&bytes)?;
    }

    /// Colour off: adversarial command + reason through the check surface is
    /// control-free.
    #[test]
    fn check_colour_off_is_control_free(command in adversarial(), reason in adversarial()) {
        let bytes = render_check_surface(&command, &reason, false);
        assert_control_free(&bytes)?;
    }

    /// Colour on: adversarial command + reason through the check surface emits
    /// only palette SGR.
    #[test]
    fn check_colour_on_palette_only(command in adversarial(), reason in adversarial()) {
        let bytes = render_check_surface(&command, &reason, true);
        assert_only_palette_sgr(&bytes)?;
    }
}
