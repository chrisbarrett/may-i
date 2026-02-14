// Security filters — R11
// Hard-coded credential file blocking that runs before rule evaluation.

use crate::config::Config;
use crate::parser;

/// Check if any word in the command references a blocked path.
/// Returns the reason string if blocked, None otherwise.
pub fn check_blocked_paths(input: &str, config: &Config) -> Option<String> {
    let ast = parser::parse(input);
    let words = parser::extract_all_words(&ast);

    let patterns: Vec<regex::Regex> = config
        .security
        .blocked_paths
        .iter()
        .filter_map(|p| regex::Regex::new(p).ok())
        .collect();

    for word in &words {
        let text = word.to_str();
        for pattern in &patterns {
            if pattern.is_match(&text) {
                return Some(format!(
                    "Access to credential/sensitive file: {text}"
                ));
            }
        }
    }

    // Also check the raw input for heredoc content and other positions
    // the AST might not fully capture
    for pattern in &patterns {
        // Check against raw tokens split by whitespace as a fallback
        for token in input.split_whitespace() {
            // Strip flag prefixes for --config=.env style
            let value = if let Some((_flag, val)) = token.split_once('=') {
                val
            } else {
                token
            };
            if pattern.is_match(value) {
                return Some(format!(
                    "Access to credential/sensitive file: {value}"
                ));
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecurityConfig;

    fn test_config() -> Config {
        Config {
            rules: vec![],
            wrappers: vec![],
            security: SecurityConfig::default(),
        }
    }

    #[test]
    fn security_blocks_env_file() {
        let config = test_config();
        assert!(check_blocked_paths("cat .env", &config).is_some());
    }

    #[test]
    fn security_blocks_ssh_directory() {
        let config = test_config();
        assert!(check_blocked_paths("cat .ssh/id_rsa", &config).is_some());
    }

    #[test]
    fn security_blocks_flag_value() {
        let config = test_config();
        assert!(check_blocked_paths("cmd --config=.env", &config).is_some());
    }

    #[test]
    fn security_allows_normal_files() {
        let config = test_config();
        assert!(check_blocked_paths("cat README.md", &config).is_none());
    }
}
