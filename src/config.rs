// Configuration — R10, R10a, R10b
// TOML-based configuration for authorization rules, wrappers, and security.

use std::path::PathBuf;

use crate::types::{
    ArgMatcher, CommandMatcher, Config, Decision, Example, Pattern, Rule, SecurityConfig, Wrapper,
    WrapperKind,
};

/// Find the config file path per R10.
pub fn config_path() -> Option<PathBuf> {
    // 1. $MAYI_CONFIG
    if let Ok(p) = std::env::var("MAYI_CONFIG") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
    }

    // 2. $XDG_CONFIG_HOME/may-i/config.toml
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        let path = PathBuf::from(xdg).join("may-i/config.toml");
        if path.exists() {
            return Some(path);
        }
    }

    // 3. ~/.config/may-i/config.toml
    if let Some(home) = dirs::home_dir() {
        let path = home.join(".config/may-i/config.toml");
        if path.exists() {
            return Some(path);
        }
    }

    None
}

/// Load config, creating a starter config file if none exists.
pub fn load() -> Result<Config, String> {
    let path = match config_path() {
        Some(path) => path,
        None => {
            let path = default_config_path()
                .ok_or("cannot determine config directory")?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
            }
            std::fs::write(&path, include_str!("starter_config.toml"))
                .map_err(|e| format!("Failed to write {}: {e}", path.display()))?;
            eprintln!("Created starter config at {}", path.display());
            path
        }
    };

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    parse_toml(&content)
}

/// The preferred config path (XDG or ~/.config fallback).
fn default_config_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg).join("may-i/config.toml"));
    }
    dirs::home_dir().map(|h| h.join(".config/may-i/config.toml"))
}

/// Parse TOML config string into Config.
pub fn parse_toml(input: &str) -> Result<Config, String> {
    let doc: toml::Value = input.parse().map_err(|e: toml::de::Error| e.to_string())?;

    let mut rules = Vec::new();
    let mut wrappers = Vec::new();
    let mut security = SecurityConfig::default();

    if let Some(toml::Value::Array(rule_arr)) = doc.get("rules") {
        for rule_val in rule_arr {
            rules.push(parse_rule(rule_val)?);
        }
    }

    if let Some(toml::Value::Array(wrapper_arr)) = doc.get("wrappers") {
        for w_val in wrapper_arr {
            wrappers.push(parse_wrapper(w_val)?);
        }
    }

    if let Some(toml::Value::Table(sec)) = doc.get("security")
        && let Some(toml::Value::Array(paths)) = sec.get("blocked_paths")
    {
        for p in paths {
            if let toml::Value::String(s) = p {
                let re = regex::Regex::new(s)
                    .map_err(|e| format!("invalid blocked_path regex '{s}': {e}"))?;
                // Append user patterns to defaults (security filters cannot be overridden)
                if !security.blocked_paths.iter().any(|existing| existing.as_str() == re.as_str()) {
                    security.blocked_paths.push(re);
                }
            }
        }
    }

    Ok(Config { rules, wrappers, security })
}

fn parse_command_matcher(val: &toml::Value) -> Result<CommandMatcher, String> {
    match val {
        toml::Value::String(s) => {
            if s.starts_with('^') {
                let re = regex::Regex::new(s)
                    .map_err(|e| format!("invalid command regex '{s}': {e}"))?;
                Ok(CommandMatcher::Regex(re))
            } else {
                Ok(CommandMatcher::Exact(s.clone()))
            }
        }
        toml::Value::Array(arr) => {
            let mut names = Vec::new();
            for v in arr {
                if let toml::Value::String(s) = v {
                    names.push(s.clone());
                } else {
                    return Err("command array must contain strings".into());
                }
            }
            Ok(CommandMatcher::List(names))
        }
        _ => Err("command must be string or array".into()),
    }
}

fn parse_rule(val: &toml::Value) -> Result<Rule, String> {
    let table = val.as_table().ok_or("rule must be a table")?;

    let command = table
        .get("command")
        .ok_or("rule must have 'command'")?;
    let command = parse_command_matcher(command)?;

    let decision_str = table
        .get("decision")
        .and_then(|v| v.as_str())
        .ok_or("rule must have 'decision'")?;
    let decision = match decision_str {
        "allow" => Decision::Allow,
        "deny" => Decision::Deny,
        "ask" => Decision::Ask,
        other => return Err(format!("unknown decision: {other}")),
    };

    let reason = table
        .get("reason")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let mut matchers = Vec::new();
    if let Some(toml::Value::Table(args)) = table.get("args") {
        if let Some(v) = args.get("positional") {
            matchers.push(ArgMatcher::Positional(parse_pattern_list(v)?));
        }
        if let Some(v) = args.get("anywhere") {
            matchers.push(ArgMatcher::Anywhere(parse_pattern_list(v)?));
        }
        if let Some(v) = args.get("anywhere_also") {
            matchers.push(ArgMatcher::Anywhere(parse_pattern_list(v)?));
        }
        if let Some(v) = args.get("forbidden") {
            matchers.push(ArgMatcher::Forbidden(parse_string_list(v)?));
        }
    }

    let mut examples = Vec::new();
    if let Some(toml::Value::Array(ex_arr)) = table.get("examples") {
        for ex in ex_arr {
            let ex_table = ex.as_table().ok_or("example must be a table")?;
            let cmd = ex_table
                .get("command")
                .and_then(|v| v.as_str())
                .ok_or("example must have 'command'")?
                .to_string();
            let expected = ex_table
                .get("expected")
                .and_then(|v| v.as_str())
                .ok_or("example must have 'expected'")?;
            let expected = match expected {
                "allow" => Decision::Allow,
                "deny" => Decision::Deny,
                "ask" => Decision::Ask,
                other => return Err(format!("unknown expected decision: {other}")),
            };
            examples.push(Example { command: cmd, expected });
        }
    }

    Ok(Rule {
        command,
        matchers,
        decision,
        reason,
        examples,
    })
}

fn parse_wrapper(val: &toml::Value) -> Result<Wrapper, String> {
    let table = val.as_table().ok_or("wrapper must be a table")?;

    let command = table
        .get("command")
        .and_then(|v| v.as_str())
        .ok_or("wrapper must have 'command'")?
        .to_string();

    let inner_command = table
        .get("inner_command")
        .ok_or("wrapper must have 'inner_command'")?;

    let kind = match inner_command {
        toml::Value::String(s) if s == "after_flags" => WrapperKind::AfterFlags,
        toml::Value::Table(t) => {
            if let Some(toml::Value::String(delim)) = t.get("after") {
                WrapperKind::AfterDelimiter(delim.clone())
            } else {
                return Err("wrapper inner_command table must have 'after'".into());
            }
        }
        _ => return Err("invalid inner_command value".into()),
    };

    let mut positional = Vec::new();
    if let Some(toml::Value::Table(args)) = table.get("args")
        && let Some(v) = args.get("positional")
    {
        positional = parse_string_list(v)?;
    }

    Ok(Wrapper {
        command,
        positional_args: positional,
        kind,
    })
}

fn parse_pattern_list(val: &toml::Value) -> Result<Vec<Pattern>, String> {
    match val {
        toml::Value::Array(arr) => {
            let mut result = Vec::new();
            for v in arr {
                if let toml::Value::String(s) = v {
                    let pat = Pattern::new(s)
                        .map_err(|e| format!("invalid pattern regex '{s}': {e}"))?;
                    result.push(pat);
                } else {
                    return Err("expected string in array".into());
                }
            }
            Ok(result)
        }
        toml::Value::String(s) => {
            let pat = Pattern::new(s)
                .map_err(|e| format!("invalid pattern regex '{s}': {e}"))?;
            Ok(vec![pat])
        }
        _ => Err("expected string or array".into()),
    }
}

fn parse_string_list(val: &toml::Value) -> Result<Vec<String>, String> {
    match val {
        toml::Value::Array(arr) => {
            let mut result = Vec::new();
            for v in arr {
                if let toml::Value::String(s) = v {
                    result.push(s.clone());
                } else {
                    return Err("expected string in array".into());
                }
            }
            Ok(result)
        }
        toml::Value::String(s) => Ok(vec![s.clone()]),
        _ => Err("expected string or array".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_location_env_var() {
        // R10: $MAYI_CONFIG takes priority when the file exists
        let dir = std::env::temp_dir().join("may-i-test-config");
        let _ = std::fs::create_dir_all(&dir);
        let config_file = dir.join("config.toml");
        std::fs::write(&config_file, "# test").unwrap();

        unsafe { std::env::set_var("MAYI_CONFIG", &config_file) };
        let path = config_path();
        assert_eq!(path.unwrap(), config_file);
        unsafe { std::env::remove_var("MAYI_CONFIG") };

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_parse_basic_rule() {
        let toml = r#"
[[rules]]
command = "cat"
decision = "allow"
reason = "Read-only"
"#;
        let config = parse_toml(toml).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].decision, Decision::Allow);
        assert_eq!(config.rules[0].reason.as_deref(), Some("Read-only"));
    }

    #[test]
    fn config_parse_rule_no_reason() {
        let toml = r#"
[[rules]]
command = "ls"
decision = "deny"
"#;
        let config = parse_toml(toml).unwrap();
        assert_eq!(config.rules[0].decision, Decision::Deny);
        assert!(config.rules[0].reason.is_none());
    }

    #[test]
    fn config_parse_ask_decision() {
        let toml = r#"
[[rules]]
command = "rm"
decision = "ask"
"#;
        let config = parse_toml(toml).unwrap();
        assert_eq!(config.rules[0].decision, Decision::Ask);
    }

    #[test]
    fn config_parse_unknown_decision() {
        let toml = r#"
[[rules]]
command = "rm"
decision = "maybe"
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_multiple_rules() {
        let toml = r#"
[[rules]]
command = "cat"
decision = "allow"

[[rules]]
command = "rm"
decision = "deny"

[[rules]]
command = "git"
decision = "ask"
"#;
        let config = parse_toml(toml).unwrap();
        assert_eq!(config.rules.len(), 3);
        assert_eq!(config.rules[0].decision, Decision::Allow);
        assert_eq!(config.rules[1].decision, Decision::Deny);
        assert_eq!(config.rules[2].decision, Decision::Ask);
    }

    #[test]
    fn config_parse_empty_config() {
        let config = parse_toml("").unwrap();
        assert!(config.rules.is_empty());
        assert!(config.wrappers.is_empty());
        // Security defaults should still be present
        assert!(!config.security.blocked_paths.is_empty());
    }

    #[test]
    fn config_parse_regex_command() {
        let toml = r#"
[[rules]]
command = "^git.*$"
decision = "allow"
"#;
        let config = parse_toml(toml).unwrap();
        match &config.rules[0].command {
            CommandMatcher::Regex(re) => assert!(re.is_match("git-log")),
            _ => panic!("expected Regex command matcher"),
        }
    }

    #[test]
    fn config_parse_list_command() {
        let toml = r#"
[[rules]]
command = ["cat", "head", "tail"]
decision = "allow"
"#;
        let config = parse_toml(toml).unwrap();
        match &config.rules[0].command {
            CommandMatcher::List(v) => assert_eq!(v, &["cat", "head", "tail"]),
            _ => panic!("expected List command matcher"),
        }
    }

    #[test]
    fn config_parse_command_list_non_string_error() {
        let toml = r#"
[[rules]]
command = [1, 2]
decision = "allow"
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_command_invalid_type_error() {
        let toml = r#"
[[rules]]
command = 42
decision = "allow"
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_positional_args() {
        let toml = r#"
[[rules]]
command = "git"
decision = "allow"
[rules.args]
positional = ["commit", "*"]
"#;
        let config = parse_toml(toml).unwrap();
        assert_eq!(config.rules[0].matchers.len(), 1);
        match &config.rules[0].matchers[0] {
            ArgMatcher::Positional(patterns) => {
                assert_eq!(patterns.len(), 2);
                assert!(patterns[0].is_match("commit"));
                assert!(patterns[1].is_wildcard());
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn config_parse_anywhere_args() {
        let toml = r#"
[[rules]]
command = "git"
decision = "allow"
[rules.args]
anywhere = ["--no-verify"]
"#;
        let config = parse_toml(toml).unwrap();
        match &config.rules[0].matchers[0] {
            ArgMatcher::Anywhere(patterns) => {
                assert!(patterns[0].is_match("--no-verify"));
            }
            _ => panic!("expected Anywhere"),
        }
    }

    #[test]
    fn config_parse_anywhere_also_args() {
        let toml = r#"
[[rules]]
command = "git"
decision = "allow"
[rules.args]
anywhere_also = ["--force"]
"#;
        let config = parse_toml(toml).unwrap();
        match &config.rules[0].matchers[0] {
            ArgMatcher::Anywhere(patterns) => {
                assert!(patterns[0].is_match("--force"));
            }
            _ => panic!("expected Anywhere from anywhere_also"),
        }
    }

    #[test]
    fn config_parse_forbidden_args() {
        let toml = r#"
[[rules]]
command = "git"
decision = "allow"
[rules.args]
forbidden = ["--force"]
"#;
        let config = parse_toml(toml).unwrap();
        match &config.rules[0].matchers[0] {
            ArgMatcher::Forbidden(strings) => {
                assert_eq!(strings, &["--force"]);
            }
            _ => panic!("expected Forbidden"),
        }
    }

    #[test]
    fn config_parse_single_string_pattern_list() {
        let toml = r#"
[[rules]]
command = "git"
decision = "allow"
[rules.args]
positional = "commit"
"#;
        let config = parse_toml(toml).unwrap();
        match &config.rules[0].matchers[0] {
            ArgMatcher::Positional(patterns) => {
                assert_eq!(patterns.len(), 1);
                assert!(patterns[0].is_match("commit"));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn config_parse_single_string_for_forbidden() {
        let toml = r#"
[[rules]]
command = "git"
decision = "allow"
[rules.args]
forbidden = "--force"
"#;
        let config = parse_toml(toml).unwrap();
        match &config.rules[0].matchers[0] {
            ArgMatcher::Forbidden(strings) => {
                assert_eq!(strings, &["--force"]);
            }
            _ => panic!("expected Forbidden"),
        }
    }

    #[test]
    fn config_parse_regex_in_pattern_list() {
        let toml = r#"
[[rules]]
command = "git"
decision = "allow"
[rules.args]
positional = ["^(commit|push)$"]
"#;
        let config = parse_toml(toml).unwrap();
        match &config.rules[0].matchers[0] {
            ArgMatcher::Positional(patterns) => {
                assert!(patterns[0].is_match("commit"));
                assert!(patterns[0].is_match("push"));
                assert!(!patterns[0].is_match("pull"));
            }
            _ => panic!("expected Positional"),
        }
    }

    #[test]
    fn config_parse_examples() {
        let toml = r#"
[[rules]]
command = "git"
decision = "allow"
[[rules.examples]]
command = "git commit -m 'test'"
expected = "allow"
[[rules.examples]]
command = "git push --force"
expected = "deny"
"#;
        let config = parse_toml(toml).unwrap();
        assert_eq!(config.rules[0].examples.len(), 2);
        assert_eq!(config.rules[0].examples[0].command, "git commit -m 'test'");
        assert_eq!(config.rules[0].examples[0].expected, Decision::Allow);
        assert_eq!(config.rules[0].examples[1].expected, Decision::Deny);
    }

    #[test]
    fn config_parse_example_unknown_expected() {
        let toml = r#"
[[rules]]
command = "git"
decision = "allow"
[[rules.examples]]
command = "git status"
expected = "maybe"
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_wrapper_after_flags() {
        let toml = r#"
[[wrappers]]
command = "nohup"
inner_command = "after_flags"
"#;
        let config = parse_toml(toml).unwrap();
        assert_eq!(config.wrappers.len(), 1);
        assert_eq!(config.wrappers[0].command, "nohup");
        assert!(matches!(config.wrappers[0].kind, WrapperKind::AfterFlags));
        assert!(config.wrappers[0].positional_args.is_empty());
    }

    #[test]
    fn config_parse_wrapper_after_delimiter() {
        let toml = r#"
[[wrappers]]
command = "mise"
inner_command = { after = "--" }
[wrappers.args]
positional = ["exec"]
"#;
        let config = parse_toml(toml).unwrap();
        assert_eq!(config.wrappers[0].command, "mise");
        match &config.wrappers[0].kind {
            WrapperKind::AfterDelimiter(d) => assert_eq!(d, "--"),
            _ => panic!("expected AfterDelimiter"),
        }
        assert_eq!(config.wrappers[0].positional_args, vec!["exec"]);
    }

    #[test]
    fn config_parse_wrapper_invalid_inner_command() {
        let toml = r#"
[[wrappers]]
command = "bad"
inner_command = 42
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_wrapper_table_missing_after() {
        let toml = r#"
[[wrappers]]
command = "bad"
inner_command = { foo = "bar" }
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_security_custom_blocked_paths() {
        let toml = r#"
[security]
blocked_paths = ["^/secret/"]
"#;
        let config = parse_toml(toml).unwrap();
        // Should have defaults + the custom one
        let patterns: Vec<&str> = config.security.blocked_paths.iter().map(|r| r.as_str()).collect();
        assert!(patterns.contains(&"^/secret/"));
        // Defaults still present
        assert!(patterns.iter().any(|p| p.contains(".env")));
    }

    #[test]
    fn config_parse_security_duplicate_not_added() {
        let toml = r#"
[security]
blocked_paths = ["(^|/)\\.env($|[./])"]
"#;
        let config = parse_toml(toml).unwrap();
        // Should still have exactly 10 (the default set, not 11)
        assert_eq!(config.security.blocked_paths.len(), 10);
    }

    #[test]
    fn config_parse_security_invalid_regex() {
        let toml = r#"
[security]
blocked_paths = ["^[invalid"]
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_invalid_toml() {
        assert!(parse_toml("this is not valid toml {{{").is_err());
    }

    #[test]
    fn config_parse_rule_missing_command() {
        let toml = r#"
[[rules]]
decision = "allow"
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_rule_missing_decision() {
        let toml = r#"
[[rules]]
command = "cat"
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_invalid_pattern_in_args() {
        let toml = r#"
[[rules]]
command = "git"
decision = "allow"
[rules.args]
positional = ["^[invalid"]
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_non_string_in_pattern_list() {
        let toml = r#"
[[rules]]
command = "git"
decision = "allow"
[rules.args]
positional = [1, 2]
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_invalid_pattern_list_type() {
        let toml = r#"
[[rules]]
command = "git"
decision = "allow"
[rules.args]
positional = 42
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_non_string_in_string_list() {
        let toml = r#"
[[rules]]
command = "git"
decision = "allow"
[rules.args]
forbidden = [1, 2]
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_invalid_string_list_type() {
        let toml = r#"
[[rules]]
command = "git"
decision = "allow"
[rules.args]
forbidden = 42
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_invalid_command_regex() {
        let toml = r#"
[[rules]]
command = "^[invalid"
decision = "allow"
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_rule_not_a_table() {
        let toml = r#"
rules = ["not a table"]
"#;
        // "rules" is an array but elements are strings, not tables
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_wrapper_not_a_table() {
        let toml = r#"
wrappers = ["not a table"]
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_wrapper_missing_command() {
        let toml = r#"
[[wrappers]]
inner_command = "after_flags"
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_wrapper_missing_inner_command() {
        let toml = r#"
[[wrappers]]
command = "nohup"
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_combined_rules_and_wrappers() {
        let toml = r#"
[[rules]]
command = "cat"
decision = "allow"

[[wrappers]]
command = "nohup"
inner_command = "after_flags"
"#;
        let config = parse_toml(toml).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.wrappers.len(), 1);
    }

    #[test]
    fn config_parse_example_missing_command() {
        let toml = r#"
[[rules]]
command = "git"
decision = "allow"
[[rules.examples]]
expected = "allow"
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_example_missing_expected() {
        let toml = r#"
[[rules]]
command = "git"
decision = "allow"
[[rules.examples]]
command = "git status"
"#;
        assert!(parse_toml(toml).is_err());
    }

    #[test]
    fn config_parse_example_not_a_table() {
        let toml = r#"
[[rules]]
command = "git"
decision = "allow"
examples = ["not a table"]
"#;
        assert!(parse_toml(toml).is_err());
    }
}
