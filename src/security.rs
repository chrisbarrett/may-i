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

    // ── check_blocked_paths: default patterns ──────────────────────────

    #[test]
    fn blocks_dot_env() {
        let c = test_config();
        assert!(check_blocked_paths("cat .env", &c).is_some());
    }

    #[test]
    fn blocks_dot_env_local() {
        let c = test_config();
        assert!(check_blocked_paths("cat .env.local", &c).is_some());
    }

    #[test]
    fn blocks_dot_env_production() {
        let c = test_config();
        assert!(check_blocked_paths("cat .env.production", &c).is_some());
    }

    #[test]
    fn blocks_nested_dot_env() {
        let c = test_config();
        assert!(check_blocked_paths("cat config/.env", &c).is_some());
    }

    #[test]
    fn blocks_absolute_dot_env() {
        let c = test_config();
        assert!(check_blocked_paths("cat /home/user/.env", &c).is_some());
    }

    #[test]
    fn blocks_ssh_directory() {
        let c = test_config();
        assert!(check_blocked_paths("cat .ssh/id_rsa", &c).is_some());
    }

    #[test]
    fn blocks_absolute_ssh() {
        let c = test_config();
        assert!(check_blocked_paths("cat /home/user/.ssh/config", &c).is_some());
    }

    #[test]
    fn blocks_aws_directory() {
        let c = test_config();
        assert!(check_blocked_paths("cat .aws/credentials", &c).is_some());
    }

    #[test]
    fn blocks_absolute_aws() {
        let c = test_config();
        assert!(check_blocked_paths("cat /home/user/.aws/config", &c).is_some());
    }

    #[test]
    fn blocks_gnupg_directory() {
        let c = test_config();
        assert!(check_blocked_paths("cat .gnupg/pubring.kbx", &c).is_some());
    }

    #[test]
    fn blocks_docker_directory() {
        let c = test_config();
        assert!(check_blocked_paths("cat .docker/config.json", &c).is_some());
    }

    #[test]
    fn blocks_kube_directory() {
        let c = test_config();
        assert!(check_blocked_paths("cat .kube/config", &c).is_some());
    }

    #[test]
    fn blocks_credentials_json() {
        let c = test_config();
        assert!(check_blocked_paths("cat credentials.json", &c).is_some());
    }

    #[test]
    fn blocks_nested_credentials_json() {
        let c = test_config();
        assert!(check_blocked_paths("cat app/credentials.json", &c).is_some());
    }

    #[test]
    fn blocks_netrc() {
        let c = test_config();
        assert!(check_blocked_paths("cat .netrc", &c).is_some());
    }

    #[test]
    fn blocks_npmrc() {
        let c = test_config();
        assert!(check_blocked_paths("cat .npmrc", &c).is_some());
    }

    #[test]
    fn blocks_pypirc() {
        let c = test_config();
        assert!(check_blocked_paths("cat .pypirc", &c).is_some());
    }

    // ── check_blocked_paths: negative cases / edge cases ─────────────

    #[test]
    fn allows_normal_files() {
        let c = test_config();
        assert!(check_blocked_paths("cat README.md", &c).is_none());
    }

    #[test]
    fn allows_env_without_dot() {
        let c = test_config();
        // "env" is not ".env"
        assert!(check_blocked_paths("env FOO=1 cmd", &c).is_none());
    }

    #[test]
    fn allows_envrc() {
        let c = test_config();
        // .envrc is not matched by the .env pattern (the pattern requires .env
        // to be followed by nothing, a dot, or a slash)
        assert!(check_blocked_paths("cat .envrc", &c).is_none());
    }

    #[test]
    fn allows_ssh_without_slash() {
        let c = test_config();
        // ".ssh" alone (no trailing slash) should not match the directory pattern
        assert!(check_blocked_paths("echo .ssh", &c).is_none());
    }

    #[test]
    fn allows_partial_credential_name() {
        let c = test_config();
        assert!(check_blocked_paths("cat my_credentials.json.bak", &c).is_none());
    }

    #[test]
    fn allows_unrelated_json() {
        let c = test_config();
        assert!(check_blocked_paths("cat package.json", &c).is_none());
    }

    // ── check_blocked_paths: flag value extraction ───────────────────

    #[test]
    fn blocks_flag_equals_env() {
        let c = test_config();
        assert!(check_blocked_paths("cmd --config=.env", &c).is_some());
    }

    #[test]
    fn blocks_flag_equals_ssh_path() {
        let c = test_config();
        assert!(check_blocked_paths("cmd --key=/home/user/.ssh/id_rsa", &c).is_some());
    }

    #[test]
    fn blocks_flag_equals_credentials() {
        let c = test_config();
        assert!(check_blocked_paths("cmd --file=credentials.json", &c).is_some());
    }

    // ── check_blocked_paths: heredoc scanning ────────────────────────

    #[test]
    fn blocks_env_in_heredoc() {
        let c = test_config();
        let cmd = "cat <<EOF\n.env\nEOF";
        assert!(check_blocked_paths(cmd, &c).is_some());
    }

    #[test]
    fn blocks_ssh_path_in_heredoc() {
        let c = test_config();
        let cmd = "cat <<EOF\n.ssh/id_rsa\nEOF";
        assert!(check_blocked_paths(cmd, &c).is_some());
    }

    #[test]
    fn blocks_sensitive_in_heredoc_strip() {
        let c = test_config();
        let cmd = "cat <<-EOF\n\t.ssh/config\n\tEOF";
        assert!(check_blocked_paths(cmd, &c).is_some());
    }

    #[test]
    fn allows_safe_heredoc_content() {
        let c = test_config();
        let cmd = "cat <<EOF\nhello world\nEOF";
        assert!(check_blocked_paths(cmd, &c).is_none());
    }

    // ── check_blocked_paths: multiple args ───────────────────────────

    #[test]
    fn blocks_when_sensitive_file_among_many_args() {
        let c = test_config();
        assert!(check_blocked_paths("cat foo.txt bar.txt .env baz.txt", &c).is_some());
    }

    #[test]
    fn allows_when_all_args_safe() {
        let c = test_config();
        assert!(check_blocked_paths("cat foo.txt bar.txt baz.txt", &c).is_none());
    }

    // ── check_blocked_paths: custom config patterns ──────────────────

    #[test]
    fn blocks_custom_pattern() {
        let mut config = test_config();
        let custom = regex::Regex::new(r"(^|/)secret\.yaml$").unwrap();
        config.security.blocked_paths.push(custom);
        assert!(check_blocked_paths("cat secret.yaml", &config).is_some());
    }

    #[test]
    fn custom_pattern_coexists_with_defaults() {
        let mut config = test_config();
        let custom = regex::Regex::new(r"(^|/)secret\.yaml$").unwrap();
        config.security.blocked_paths.push(custom);
        // Custom pattern blocks
        assert!(check_blocked_paths("cat secret.yaml", &config).is_some());
        // Default pattern still blocks
        assert!(check_blocked_paths("cat .env", &config).is_some());
        // Unrelated file still allowed
        assert!(check_blocked_paths("cat README.md", &config).is_none());
    }

    // ── check_blocked_paths: message content ─────────────────────────

    #[test]
    fn blocked_message_contains_path() {
        let c = test_config();
        let msg = check_blocked_paths("cat .ssh/id_rsa", &c).unwrap();
        assert!(msg.contains(".ssh/id_rsa"));
    }

    // ── check_dynamic_parts ──────────────────────────────────────────

    #[test]
    fn dynamic_detects_command_substitution() {
        assert!(check_dynamic_parts("echo $(whoami)").is_some());
    }

    #[test]
    fn dynamic_detects_backtick_substitution() {
        assert!(check_dynamic_parts("echo `whoami`").is_some());
    }

    #[test]
    fn dynamic_detects_variable_expansion() {
        assert!(check_dynamic_parts("echo $HOME").is_some());
    }

    #[test]
    fn dynamic_allows_plain_command() {
        assert!(check_dynamic_parts("echo hello world").is_none());
    }

    #[test]
    fn dynamic_allows_flags_and_args() {
        assert!(check_dynamic_parts("ls -la /tmp").is_none());
    }

    #[test]
    fn dynamic_message_content() {
        let msg = check_dynamic_parts("echo $(id)").unwrap();
        assert!(msg.contains("Dynamic shell constructs"));
    }

    // ── check_blocked_paths: piped commands ──────────────────────────

    #[test]
    fn blocks_sensitive_file_in_piped_command() {
        let c = test_config();
        assert!(check_blocked_paths("cat .env | grep SECRET", &c).is_some());
    }

    #[test]
    fn blocks_sensitive_file_after_pipe() {
        let c = test_config();
        assert!(check_blocked_paths("echo foo | tee .aws/creds", &c).is_some());
    }

    // ── check_blocked_paths: subshells / compound commands ───────────

    #[test]
    fn blocks_sensitive_in_and_chain() {
        let c = test_config();
        assert!(check_blocked_paths("true && cat .ssh/id_rsa", &c).is_some());
    }

    #[test]
    fn blocks_sensitive_in_semicolon_chain() {
        let c = test_config();
        assert!(check_blocked_paths("cd /tmp; cat .env", &c).is_some());
    }
}
