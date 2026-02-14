// Configuration — R10, R10a, R10b
// TOML-based configuration for authorization rules, wrappers, and security.

use std::path::PathBuf;

use crate::engine::{ArgMatcher, Decision, Rule, Wrapper, WrapperKind};

/// Top-level configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub rules: Vec<Rule>,
    pub wrappers: Vec<Wrapper>,
    pub security: SecurityConfig,
}

/// Security section of config.
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub blocked_paths: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            blocked_paths: vec![
                r"\.env".into(),
                r"\.ssh/".into(),
                r"\.aws/".into(),
                r"\.gnupg/".into(),
                r"\.docker/".into(),
                r"\.kube/".into(),
                r"credentials\.json".into(),
                r"\.netrc".into(),
                r"\.npmrc".into(),
                r"\.pypirc".into(),
            ],
        }
    }
}

/// Find the config file path per R10.
pub fn config_path() -> Option<PathBuf> {
    // 1. $YOLT_CONFIG
    if let Ok(p) = std::env::var("YOLT_CONFIG") {
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

/// Load config from the default location, merging with built-in defaults.
pub fn load() -> Result<Config, String> {
    let defaults = crate::defaults::builtin_config();

    match config_path() {
        Some(path) => {
            let content = std::fs::read_to_string(&path)
                .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
            let user = parse_toml(&content)?;
            Ok(merge(user, defaults))
        }
        None => Ok(defaults),
    }
}

/// Load config from a specific path, merging with built-in defaults.
pub fn load_from(path: &std::path::Path) -> Result<Config, String> {
    let defaults = crate::defaults::builtin_config();
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    let user = parse_toml(&content)?;
    Ok(merge(user, defaults))
}

/// Merge user config with defaults. User rules prepend to defaults.
fn merge(user: Config, defaults: Config) -> Config {
    let mut rules = user.rules;
    rules.extend(defaults.rules);

    let mut wrappers = user.wrappers;
    wrappers.extend(defaults.wrappers);

    let security = if user.security.blocked_paths.is_empty() {
        defaults.security
    } else {
        user.security
    };

    Config { rules, wrappers, security }
}

/// Parse TOML config string into Config.
pub fn parse_toml(input: &str) -> Result<Config, String> {
    // TODO: implement full TOML parsing
    let doc: toml::Value = input.parse().map_err(|e: toml::de::Error| e.to_string())?;

    let mut rules = Vec::new();
    let mut wrappers = Vec::new();
    let mut security = SecurityConfig { blocked_paths: vec![] };

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

    if let Some(toml::Value::Table(sec)) = doc.get("security") {
        if let Some(toml::Value::Array(paths)) = sec.get("blocked_paths") {
            for p in paths {
                if let toml::Value::String(s) = p {
                    security.blocked_paths.push(s.clone());
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
                Ok(CommandMatcher::Regex(s.clone()))
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

#[derive(Debug, Clone)]
pub enum CommandMatcher {
    Exact(String),
    Regex(String),
    List(Vec<String>),
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
            matchers.push(ArgMatcher::Positional(parse_string_list(v)?));
        }
        if let Some(v) = args.get("anywhere") {
            matchers.push(ArgMatcher::Anywhere(parse_string_list(v)?));
        }
        if let Some(v) = args.get("anywhere_also") {
            matchers.push(ArgMatcher::Anywhere(parse_string_list(v)?));
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
    if let Some(toml::Value::Table(args)) = table.get("args") {
        if let Some(v) = args.get("positional") {
            positional = parse_string_list(v)?;
        }
    }

    Ok(Wrapper {
        command,
        positional_args: positional,
        kind,
    })
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

/// An embedded example for config validation.
#[derive(Debug, Clone)]
pub struct Example {
    pub command: String,
    pub expected: Decision,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_location_env_var() {
        // R10: $YOLT_CONFIG takes priority
        unsafe { std::env::set_var("YOLT_CONFIG", "/nonexistent/path") };
        let path = config_path();
        // Path doesn't exist, so should fall through
        assert!(path.is_none() || path.unwrap().to_str().unwrap().contains("nonexistent"));
        unsafe { std::env::remove_var("YOLT_CONFIG") };
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
    }
}
