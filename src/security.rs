// Security filters — R11
// Hard-coded credential file blocking that runs before rule evaluation.

use crate::parser::{self, RedirectionTarget};
use crate::types::Config;

/// Check if any word in the command contains dynamic shell constructs
/// that prevent static analysis.
pub fn check_dynamic_parts(input: &str) -> Option<String> {
    let ast = parser::parse(input);
    let words = parser::extract_all_words(&ast);

    for word in &words {
        if word.has_dynamic_parts() {
            return Some(
                "Dynamic shell constructs prevent static analysis of this command".to_string(),
            );
        }
    }

    None
}

/// Check if any word in the command references a blocked path.
/// Returns the reason string if blocked, None otherwise.
pub fn check_blocked_paths(input: &str, config: &Config) -> Option<String> {
    let ast = parser::parse(input);
    let words = parser::extract_all_words(&ast);

    let patterns = &config.security.blocked_paths;

    for word in &words {
        let text = word.to_str();
        for pattern in patterns {
            if pattern.is_match(&text) {
                return Some(format!(
                    "Access to credential/sensitive file: {text}"
                ));
            }
        }
    }

    // Scan heredoc content from redirections
    let simple_commands = parser::extract_simple_commands(&ast);
    for sc in &simple_commands {
        for redir in &sc.redirections {
            if let RedirectionTarget::Heredoc(content) = &redir.target
                && !content.is_empty()
            {
                for pattern in patterns {
                    if pattern.is_match(content) {
                        return Some(format!(
                            "Access to credential/sensitive file in heredoc: {content}"
                        ));
                    }
                }
            }
        }
    }

    // Also check the raw input for content the AST might not fully capture
    for pattern in patterns {
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
    use crate::types::SecurityConfig;

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
