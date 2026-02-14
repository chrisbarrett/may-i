// Built-in defaults — R10c
// Default rules compiled into the binary, matching the reference implementation.

use crate::config::{CommandMatcher, Config, Example, SecurityConfig};
use crate::engine::{ArgMatcher, Decision, Rule, Wrapper, WrapperKind};

/// Returns the built-in default configuration.
pub fn builtin_config() -> Config {
    Config {
        rules: builtin_rules(),
        wrappers: builtin_wrappers(),
        security: SecurityConfig::default(),
    }
}

fn builtin_rules() -> Vec<Rule> {
    let mut rules = Vec::new();

    // =========================================================================
    // Deny rules (highest priority)
    // =========================================================================

    // rm -r / (recursive deletion from root)
    rules.push(Rule {
        command: "rm".into(),
        matchers: vec![
            ArgMatcher::Anywhere(vec!["-r".into(), "--recursive".into()]),
            ArgMatcher::Anywhere(vec!["/".into()]),
        ],
        decision: Decision::Deny,
        reason: Some("Recursive deletion from root is dangerous".into()),
        examples: vec![
            Example { command: "rm -rf /".into(), expected: Decision::Deny },
            Example { command: "rm -r /".into(), expected: Decision::Deny },
            Example { command: "rm --recursive /".into(), expected: Decision::Deny },
        ],
    });

    // Dangerous filesystem/device operations
    rules.push(Rule {
        command: vec!["mkfs", "dd", "fdisk", "parted", "gdisk"].into(),
        matchers: vec![],
        decision: Decision::Deny,
        reason: Some("Dangerous filesystem or device operation".into()),
        examples: vec![
            Example { command: "mkfs /dev/sda".into(), expected: Decision::Deny },
            Example { command: "dd if=/dev/zero of=/dev/sda".into(), expected: Decision::Deny },
            Example { command: "fdisk /dev/sda".into(), expected: Decision::Deny },
        ],
    });

    // System power control
    rules.push(deny(
        vec!["shutdown", "reboot", "halt", "poweroff", "init"],
        "System power control is dangerous",
    ));

    // Firewall manipulation
    rules.push(deny(
        vec!["iptables", "nft", "pfctl"],
        "Firewall manipulation is dangerous",
    ));

    // =========================================================================
    // Networking
    // =========================================================================

    // curl: HEAD request with -I/--head
    rules.push(Rule {
        command: "curl".into(),
        matchers: vec![ArgMatcher::Anywhere(vec!["-I".into(), "--head".into()])],
        decision: Decision::Allow,
        reason: Some("HEAD request is read-only".into()),
        examples: vec![
            Example { command: "curl -I https://example.com".into(), expected: Decision::Allow },
            Example { command: "curl --head https://example.com".into(), expected: Decision::Allow },
        ],
    });

    // curl: non-mutating HTTP method with -X/--request
    rules.push(Rule {
        command: "curl".into(),
        matchers: vec![
            ArgMatcher::Anywhere(vec!["-X".into(), "--request".into()]),
            ArgMatcher::Anywhere(vec!["GET".into(), "HEAD".into(), "OPTIONS".into()]),
        ],
        decision: Decision::Allow,
        reason: Some("Non-mutating HTTP method".into()),
        examples: vec![
            Example { command: "curl -X GET https://example.com".into(), expected: Decision::Allow },
            Example { command: "curl -X HEAD https://example.com".into(), expected: Decision::Allow },
            Example { command: "curl -X OPTIONS https://example.com".into(), expected: Decision::Allow },
        ],
    });

    // curl: GET request (default, no mutating flags)
    rules.push(Rule {
        command: "curl".into(),
        matchers: vec![ArgMatcher::Forbidden(vec![
            "-d".into(), "--data".into(), "--data-raw".into(), "--data-binary".into(),
            "--data-urlencode".into(), "-F".into(), "--form".into(), "-T".into(),
            "--upload-file".into(), "-X".into(), "--request".into(),
        ])],
        decision: Decision::Allow,
        reason: Some("GET request (default, no mutating flags)".into()),
        examples: vec![
            Example { command: "curl https://example.com".into(), expected: Decision::Allow },
            Example { command: "curl -s https://example.com".into(), expected: Decision::Allow },
            Example { command: "curl -sL https://example.com".into(), expected: Decision::Allow },
        ],
    });

    // curl/wget/ssh/scp: ask for network operations
    rules.push(Rule {
        command: vec!["curl", "wget", "ssh", "scp"].into(),
        matchers: vec![],
        decision: Decision::Ask,
        reason: Some("Network operation requires approval".into()),
        examples: vec![
            Example { command: "curl -d 'data' https://example.com".into(), expected: Decision::Ask },
            Example { command: "curl --data 'data' https://example.com".into(), expected: Decision::Ask },
            Example { command: "curl -F 'file=@f' https://example.com".into(), expected: Decision::Ask },
            Example { command: "curl -X POST https://example.com".into(), expected: Decision::Ask },
            Example { command: "curl -X PUT https://example.com".into(), expected: Decision::Ask },
            Example { command: "curl -X DELETE https://example.com".into(), expected: Decision::Ask },
            Example { command: "wget https://example.com".into(), expected: Decision::Ask },
            Example { command: "ssh user@host".into(), expected: Decision::Ask },
            Example { command: "scp file user@host:".into(), expected: Decision::Ask },
        ],
    });

    // Process termination
    rules.push(ask(
        vec!["kill", "pkill", "killall"],
        "Process termination requires confirmation",
    ));

    // rmdir only deletes empty directories
    rules.push(Rule {
        command: "rmdir".into(),
        matchers: vec![],
        decision: Decision::Allow,
        reason: Some("rmdir only deletes empty directories".into()),
        examples: vec![
            Example { command: "rmdir /foo".into(), expected: Decision::Allow },
        ],
    });

    // rm -r (recursive deletion requires confirmation)
    rules.push(Rule {
        command: "rm".into(),
        matchers: vec![ArgMatcher::Anywhere(vec!["-r".into(), "--recursive".into()])],
        decision: Decision::Ask,
        reason: Some("Recursive deletion requires confirmation".into()),
        examples: vec![],
    });

    // mv/rsync: file moves can be destructive
    rules.push(ask(vec!["mv", "rsync"], "File moves can be destructive"));

    // sponge
    rules.push(allow("sponge", ""));

    // =========================================================================
    // AWS rules
    // =========================================================================

    // AWS read-only operations
    rules.push(Rule {
        command: "aws".into(),
        matchers: vec![ArgMatcher::Positional(vec![
            "*".into(),
            "^(get|describe|list|show|head|batch-get|scan|tail|simulate|filter|lookup)".into(),
        ])],
        decision: Decision::Allow,
        reason: None,
        examples: vec![
            Example { command: "aws ec2 describe-instances".into(), expected: Decision::Allow },
            Example { command: "aws s3api list-buckets".into(), expected: Decision::Allow },
            Example { command: "aws logs describe-log-groups".into(), expected: Decision::Allow },
            Example { command: "aws logs tail /aws/lambda/foo".into(), expected: Decision::Allow },
            Example { command: "aws logs filter-log-events --log-group-name /aws/lambda/foo".into(), expected: Decision::Allow },
            Example { command: "aws sts get-caller-identity".into(), expected: Decision::Allow },
            Example { command: "aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::123:role/foo --action-names s3:GetObject".into(), expected: Decision::Allow },
            Example { command: "aws cloudtrail lookup-events --start-time 2024-01-01".into(), expected: Decision::Allow },
            Example { command: "aws --profile staging ec2 describe-instances".into(), expected: Decision::Allow },
        ],
    });

    // AWS S3 ls/cp
    rules.push(Rule {
        command: "aws".into(),
        matchers: vec![ArgMatcher::Positional(vec![
            "s3".into(),
            "^(ls|cp)$".into(),
        ])],
        decision: Decision::Allow,
        reason: None,
        examples: vec![
            Example { command: "aws s3 ls".into(), expected: Decision::Allow },
            Example { command: "aws s3 ls s3://bucket".into(), expected: Decision::Allow },
            Example { command: "aws s3 cp s3://bucket/key .".into(), expected: Decision::Allow },
        ],
    });

    // AWS fallback: ask
    rules.push(Rule {
        command: "aws".into(),
        matchers: vec![],
        decision: Decision::Ask,
        reason: Some("AWS operation requires confirmation".into()),
        examples: vec![
            Example { command: "aws ec2 run-instances --image-id ami-123".into(), expected: Decision::Ask },
            Example { command: "aws s3 rm s3://bucket/key".into(), expected: Decision::Ask },
            Example { command: "aws lambda invoke --function-name foo".into(), expected: Decision::Ask },
        ],
    });

    // =========================================================================
    // gh (GitHub CLI) rules
    // =========================================================================

    // Dangerous gh operations (supply chain attack vectors) - split z.union into separate rules
    for (sub, actions) in [
        ("repo", vec!["create", "delete", "fork"]),
        ("release", vec!["create", "delete", "upload"]),
        ("secret", vec!["set", "delete"]),
        ("variable", vec!["set", "delete"]),
        ("ssh-key", vec!["add", "delete"]),
        ("gpg-key", vec!["add", "delete"]),
    ] {
        rules.push(Rule {
            command: "gh".into(),
            matchers: vec![ArgMatcher::Positional(vec![
                sub.into(),
                format!("^({})$", actions.join("|")),
            ])],
            decision: Decision::Deny,
            reason: Some("Dangerous gh operation (supply chain attack vector)".into()),
            examples: vec![],
        });
    }
    // gh extension install
    rules.push(Rule {
        command: "gh".into(),
        matchers: vec![ArgMatcher::Positional(vec!["extension".into(), "install".into()])],
        decision: Decision::Deny,
        reason: Some("Dangerous gh operation (supply chain attack vector)".into()),
        examples: vec![
            Example { command: "gh repo delete foo/bar".into(), expected: Decision::Deny },
            Example { command: "gh release create v1.0".into(), expected: Decision::Deny },
            Example { command: "gh secret set FOO".into(), expected: Decision::Deny },
            Example { command: "gh ssh-key add key.pub".into(), expected: Decision::Deny },
        ],
    });

    // Read-only gh api calls (GET default, no mutating flags)
    rules.push(Rule {
        command: "gh".into(),
        matchers: vec![
            ArgMatcher::Positional(vec!["api".into()]),
            ArgMatcher::Forbidden(vec![
                "-X".into(), "--method".into(), "-f".into(), "--field".into(),
                "-F".into(), "--raw-field".into(), "--input".into(),
            ]),
        ],
        decision: Decision::Allow,
        reason: Some("Read-only API call (GET request)".into()),
        examples: vec![
            Example { command: "gh api /repos/foo/bar".into(), expected: Decision::Allow },
            Example { command: "gh api repos/actions/checkout/git/ref/tags/v4".into(), expected: Decision::Allow },
            Example { command: "gh api /user".into(), expected: Decision::Allow },
        ],
    });

    // Sensitive gh operations - split z.union
    rules.push(Rule {
        command: "gh".into(),
        matchers: vec![ArgMatcher::Positional(vec!["workflow".into(), "run".into()])],
        decision: Decision::Ask,
        reason: Some("Sensitive gh operation requires confirmation".into()),
        examples: vec![],
    });
    rules.push(Rule {
        command: "gh".into(),
        matchers: vec![ArgMatcher::Positional(vec!["api".into()])],
        decision: Decision::Ask,
        reason: Some("Sensitive gh operation requires confirmation".into()),
        examples: vec![],
    });
    rules.push(Rule {
        command: "gh".into(),
        matchers: vec![ArgMatcher::Positional(vec!["gist".into(), "^(create|edit)$".into()])],
        decision: Decision::Ask,
        reason: Some("Sensitive gh operation requires confirmation".into()),
        examples: vec![],
    });
    rules.push(Rule {
        command: "gh".into(),
        matchers: vec![ArgMatcher::Positional(vec!["auth".into()])],
        decision: Decision::Ask,
        reason: Some("Sensitive gh operation requires confirmation".into()),
        examples: vec![
            Example { command: "gh workflow run deploy.yml".into(), expected: Decision::Ask },
            Example { command: "gh api -X POST /repos/foo/bar/issues".into(), expected: Decision::Ask },
            Example { command: "gh api -f name=value /repos/foo/bar".into(), expected: Decision::Ask },
            Example { command: "gh gist create file.txt".into(), expected: Decision::Ask },
        ],
    });

    // Read-only gh operations - split z.union
    rules.push(Rule {
        command: "gh".into(),
        matchers: vec![ArgMatcher::Positional(vec!["search".into()])],
        decision: Decision::Allow,
        reason: None,
        examples: vec![],
    });
    rules.push(Rule {
        command: "gh".into(),
        matchers: vec![ArgMatcher::Positional(vec!["browse".into()])],
        decision: Decision::Allow,
        reason: None,
        examples: vec![],
    });
    rules.push(Rule {
        command: "gh".into(),
        matchers: vec![ArgMatcher::Positional(vec!["run".into(), "watch".into()])],
        decision: Decision::Allow,
        reason: None,
        examples: vec![],
    });
    rules.push(Rule {
        command: "gh".into(),
        matchers: vec![ArgMatcher::Positional(vec![
            "^(issue|pr|run)$".into(),
            "^(list|status|view)$".into(),
        ])],
        decision: Decision::Allow,
        reason: None,
        examples: vec![],
    });
    rules.push(Rule {
        command: "gh".into(),
        matchers: vec![ArgMatcher::Positional(vec![
            "repo".into(),
            "^(view|clone|list)$".into(),
        ])],
        decision: Decision::Allow,
        reason: None,
        examples: vec![],
    });
    rules.push(Rule {
        command: "gh".into(),
        matchers: vec![ArgMatcher::Positional(vec![
            "pr".into(),
            "^(checkout|diff|checks)$".into(),
        ])],
        decision: Decision::Allow,
        reason: None,
        examples: vec![
            Example { command: "gh pr list".into(), expected: Decision::Allow },
            Example { command: "gh pr view 123".into(), expected: Decision::Allow },
            Example { command: "gh issue list".into(), expected: Decision::Allow },
            Example { command: "gh run watch 123".into(), expected: Decision::Allow },
            Example { command: "gh search repos foo".into(), expected: Decision::Allow },
            Example { command: "gh repo clone foo/bar".into(), expected: Decision::Allow },
            Example { command: "gh pr checkout 123".into(), expected: Decision::Allow },
        ],
    });

    // =========================================================================
    // Package managers
    // =========================================================================

    // pip
    rules.push(Rule {
        command: vec!["pip", "pip3"].into(),
        matchers: vec![ArgMatcher::Positional(vec!["install".into()])],
        decision: Decision::Ask,
        reason: Some("Package installation requires confirmation".into()),
        examples: vec![],
    });
    rules.push(Rule {
        command: vec!["pip", "pip3"].into(),
        matchers: vec![ArgMatcher::Positional(vec!["^(list|show|freeze|check)$".into()])],
        decision: Decision::Allow,
        reason: None,
        examples: vec![],
    });

    // brew
    rules.push(Rule {
        command: "brew".into(),
        matchers: vec![ArgMatcher::Positional(vec!["^(install|uninstall)$".into()])],
        decision: Decision::Deny,
        reason: Some("Imperative package installation is not allowed".into()),
        examples: vec![],
    });
    rules.push(Rule {
        command: "brew".into(),
        matchers: vec![ArgMatcher::Positional(vec!["upgrade".into()])],
        decision: Decision::Ask,
        reason: Some("Homebrew operation requires confirmation".into()),
        examples: vec![],
    });
    rules.push(Rule {
        command: "brew".into(),
        matchers: vec![ArgMatcher::Positional(vec!["^(list|search|info|outdated|deps)$".into()])],
        decision: Decision::Allow,
        reason: None,
        examples: vec![],
    });

    // JS package managers
    rules.push(Rule {
        command: vec!["npm", "pnpm", "yarn"].into(),
        matchers: vec![ArgMatcher::Positional(vec!["^(install|add|publish)$".into()])],
        decision: Decision::Ask,
        reason: Some("Side-effect requires confirmation".into()),
        examples: vec![],
    });
    rules.push(Rule {
        command: "npm".into(),
        matchers: vec![ArgMatcher::Positional(vec!["publish".into()])],
        decision: Decision::Ask,
        reason: Some("Publishing packages requires confirmation".into()),
        examples: vec![],
    });
    rules.push(Rule {
        command: vec!["npm", "pnpm", "yarn"].into(),
        matchers: vec![ArgMatcher::Positional(vec!["^(ci|test|build|ls|list|outdated|audit)$".into()])],
        decision: Decision::Allow,
        reason: None,
        examples: vec![],
    });

    // pnpm
    rules.push(Rule {
        command: "pnpm".into(),
        matchers: vec![ArgMatcher::Positional(vec!["^(add|install)$".into()])],
        decision: Decision::Ask,
        reason: Some("pnpm install requires confirmation".into()),
        examples: vec![],
    });
    rules.push(Rule {
        command: "pnpm".into(),
        matchers: vec![ArgMatcher::Positional(vec!["^(test|build|list|outdated|audit)$".into()])],
        decision: Decision::Allow,
        reason: None,
        examples: vec![],
    });

    // =========================================================================
    // Docker
    // =========================================================================

    rules.push(Rule {
        command: "docker".into(),
        matchers: vec![ArgMatcher::Positional(vec!["^(run|exec|build)$".into()])],
        decision: Decision::Ask,
        reason: Some("Docker execution requires confirmation".into()),
        examples: vec![],
    });
    rules.push(Rule {
        command: "docker".into(),
        matchers: vec![ArgMatcher::Positional(vec!["^(ps|images|logs|inspect|stats|top|port|version|info)$".into()])],
        decision: Decision::Allow,
        reason: None,
        examples: vec![],
    });

    // =========================================================================
    // Service control
    // =========================================================================

    rules.push(Rule {
        command: "systemctl".into(),
        matchers: vec![ArgMatcher::Positional(vec!["^(start|stop|restart|enable|disable)$".into()])],
        decision: Decision::Ask,
        reason: Some("Service control requires confirmation".into()),
        examples: vec![],
    });
    rules.push(Rule {
        command: "systemctl".into(),
        matchers: vec![ArgMatcher::Positional(vec!["^(status|is-active|is-enabled|list-units)$".into()])],
        decision: Decision::Allow,
        reason: None,
        examples: vec![],
    });

    // =========================================================================
    // Read-only filesystem access
    // =========================================================================

    rules.push(allow(
        vec![
            "cat", "bat", "head", "tail", "less", "ls", "tree", "file", "stat",
            "find", "fd", "grep", "rg", "ag", "fzf", "diff", "cmp", "readlink",
            "realpath", "pwd", "xxd", "hexdump", "od", "strings", "md5sum",
            "sha256sum", "shasum",
        ],
        "Read-only filesystem access",
    ));

    // =========================================================================
    // Read-only system state access
    // =========================================================================

    rules.push(allow(
        vec![
            "date", "hostname", "uname", "uptime", "ps", "top", "htop", "pgrep",
            "lsof", "df", "du", "id", "whoami", "groups", "printenv", "env",
            "which", "whereis", "type", "command", "netstat", "scutil",
        ],
        "Read-only system state access",
    ));

    // =========================================================================
    // Read-only network diagnostics
    // =========================================================================

    rules.push(allow(
        vec!["ping", "nslookup", "dig", "host", "traceroute"],
        "Read-only network diagnostics",
    ));

    // =========================================================================
    // Streaming data manipulation
    // =========================================================================

    rules.push(allow(
        vec![
            "awk", "sed", "cut", "tr", "sort", "uniq", "wc", "nl", "jq",
            "base64", "rev", "column", "expand", "unexpand", "tee",
        ],
        "Streaming data transformation",
    ));

    // =========================================================================
    // Idempotent filesystem operations
    // =========================================================================

    rules.push(allow(
        vec!["mkdir", "touch", "cp"],
        "Idempotent filesystem operation",
    ));

    // =========================================================================
    // Archive operations
    // =========================================================================

    rules.push(allow(
        vec!["tar", "zip", "unzip", "gzip", "gunzip", "bzip2", "xz"],
        "Archive operation",
    ));

    // =========================================================================
    // Safe shell utilities
    // =========================================================================

    rules.push(allow(
        vec![
            "echo", "printf", "test", "[", "[[", "sleep", "seq", "basename",
            "dirname", "cal", "expr", "bc", "xargs", "cd",
        ],
        "Safe shell utility",
    ));

    // =========================================================================
    // Documentation access
    // =========================================================================

    rules.push(allow(vec!["man", "info", "help"], "Documentation access"));

    // =========================================================================
    // Development/linting tools
    // =========================================================================

    rules.push(allow(vec!["actionlint", "shellcheck"], "Safe linting tool"));
    rules.push(allow("cloc", "Safe analysis tool"));
    rules.push(allow("bd", "Safe issue management tool"));

    // =========================================================================
    // Ask for potentially dangerous operations
    // =========================================================================

    rules.push(ask(
        vec!["nc", "patch"],
        "Potentially dangerous operation requires confirmation",
    ));

    // rm without -r is allowed (rm -r is ask, handled earlier)
    rules.push(allow("rm", ""));

    // chmod +x
    rules.push(Rule {
        command: "chmod".into(),
        matchers: vec![ArgMatcher::Positional(vec!["+x".into()])],
        decision: Decision::Allow,
        reason: None,
        examples: vec![],
    });

    // =========================================================================
    // Git
    // =========================================================================

    // Dangerous git operations: remote add/remove/rename/set-url (must come before
    // the generic git remote allow rule so the more specific ask rule matches first)
    rules.push(Rule {
        command: "git".into(),
        matchers: vec![ArgMatcher::Positional(vec!["remote".into(), "^(add|remove|rename|set-url)".into()])],
        decision: Decision::Ask,
        reason: Some("Dangerous git operation".into()),
        examples: vec![],
    });

    // git remote (read-only)
    rules.push(Rule {
        command: "git".into(),
        matchers: vec![ArgMatcher::Positional(vec!["remote".into()])],
        decision: Decision::Allow,
        reason: Some("Read-only remote operation".into()),
        examples: vec![
            Example { command: "git remote".into(), expected: Decision::Allow },
            Example { command: "git remote show origin".into(), expected: Decision::Allow },
        ],
    });
    rules.push(Rule {
        command: "git".into(),
        matchers: vec![ArgMatcher::Positional(vec!["^(reset|clean|gc|push)$".into()])],
        decision: Decision::Ask,
        reason: Some("Dangerous git operation".into()),
        examples: vec![
            Example { command: "git push origin main".into(), expected: Decision::Ask },
            Example { command: "git push --force".into(), expected: Decision::Ask },
            Example { command: "git reset --hard HEAD~1".into(), expected: Decision::Ask },
            Example { command: "git clean -fd".into(), expected: Decision::Ask },
            Example { command: "git remote add upstream url".into(), expected: Decision::Ask },
        ],
    });

    // git fallback: allow
    rules.push(Rule {
        command: "git".into(),
        matchers: vec![],
        decision: Decision::Allow,
        reason: None,
        examples: vec![
            Example { command: "git status".into(), expected: Decision::Allow },
            Example { command: "git log".into(), expected: Decision::Allow },
            Example { command: "git diff".into(), expected: Decision::Allow },
            Example { command: "git branch".into(), expected: Decision::Allow },
            Example { command: "git checkout main".into(), expected: Decision::Allow },
            Example { command: "git add .".into(), expected: Decision::Allow },
            Example { command: "git commit -m 'msg'".into(), expected: Decision::Allow },
            Example { command: "git fetch".into(), expected: Decision::Allow },
            Example { command: "git pull".into(), expected: Decision::Allow },
            Example { command: "git stash".into(), expected: Decision::Allow },
        ],
    });

    // =========================================================================
    // Build tools
    // =========================================================================

    // Deploy/publish requires confirmation
    rules.push(Rule {
        command: vec!["deno", "cargo", "npm", "pnpm", "make"].into(),
        matchers: vec![ArgMatcher::Positional(vec!["^(deploy|publish)$".into()])],
        decision: Decision::Ask,
        reason: Some("Publishing packages requires confirmation".into()),
        examples: vec![],
    });

    // Build/test/lint/etc allowed
    rules.push(Rule {
        command: vec!["deno", "dune", "cargo", "npm", "pnpm", "make", "eldev"].into(),
        matchers: vec![ArgMatcher::Positional(vec!["^(build|clean|check|doc|lint|test|test-quick|fmt|format)$".into()])],
        decision: Decision::Allow,
        reason: None,
        examples: vec![],
    });

    // cargo specific
    rules.push(Rule {
        command: "cargo".into(),
        matchers: vec![ArgMatcher::Positional(vec!["^(clippy|fetch|build|test)$".into()])],
        decision: Decision::Allow,
        reason: None,
        examples: vec![],
    });

    // dune exec test executables
    rules.push(Rule {
        command: "dune".into(),
        matchers: vec![ArgMatcher::Positional(vec!["exec".into(), r"^(\.\/)?test\/.*\.exe$".into()])],
        decision: Decision::Allow,
        reason: Some("Running test executables via dune".into()),
        examples: vec![
            Example { command: "dune exec test/typing/types_test.exe".into(), expected: Decision::Allow },
            Example { command: "dune exec ./test/foo/bar.exe".into(), expected: Decision::Allow },
            Example { command: "dune exec ./bin/main.exe".into(), expected: Decision::Ask },
        ],
    });

    // dune runtest
    rules.push(Rule {
        command: "dune".into(),
        matchers: vec![ArgMatcher::Positional(vec!["runtest".into()])],
        decision: Decision::Allow,
        reason: Some("Running test via dune".into()),
        examples: vec![
            Example { command: "dune runtest test/lsp".into(), expected: Decision::Allow },
            Example { command: "dune exec evil runtest".into(), expected: Decision::Ask },
        ],
    });

    // Linting/formatting tools
    rules.push(allow(vec!["eslint", "tsc", "biome", "prettier"], ""));

    // =========================================================================
    // Terraform/Tofu/Terragrunt
    // =========================================================================

    rules.push(Rule {
        command: vec!["terraform", "tofu", "terragrunt"].into(),
        matchers: vec![ArgMatcher::Positional(vec!["^(apply|destroy)$".into()])],
        decision: Decision::Ask,
        reason: Some("Infra change requires confirmation".into()),
        examples: vec![
            Example { command: "terraform apply".into(), expected: Decision::Ask },
            Example { command: "terraform destroy".into(), expected: Decision::Ask },
            Example { command: "tofu apply".into(), expected: Decision::Ask },
            Example { command: "terragrunt apply".into(), expected: Decision::Ask },
        ],
    });

    // terragrunt run apply/destroy, stack run apply/destroy
    rules.push(Rule {
        command: "terragrunt".into(),
        matchers: vec![ArgMatcher::Positional(vec!["run".into(), "^(apply|destroy)$".into()])],
        decision: Decision::Ask,
        reason: Some("Infra change requires confirmation".into()),
        examples: vec![],
    });
    rules.push(Rule {
        command: "terragrunt".into(),
        matchers: vec![ArgMatcher::Positional(vec!["stack".into(), "run".into(), "^(apply|destroy)$".into()])],
        decision: Decision::Ask,
        reason: Some("Infra change requires confirmation".into()),
        examples: vec![
            Example { command: "terragrunt run apply".into(), expected: Decision::Ask },
            Example { command: "terragrunt stack run apply".into(), expected: Decision::Ask },
        ],
    });

    // pipelines
    rules.push(Rule {
        command: "pipelines".into(),
        matchers: vec![],
        decision: Decision::Allow,
        reason: Some("Non-side-effecting Terragrunt repo analysis".into()),
        examples: vec![
            Example { command: "pipelines drift-detection determine-units --wd . --filter '*/*/platform/**'".into(), expected: Decision::Allow },
        ],
    });

    // terraform/tofu/terragrunt fallback: allow
    rules.push(Rule {
        command: vec!["terraform", "tofu", "terragrunt"].into(),
        matchers: vec![],
        decision: Decision::Allow,
        reason: None,
        examples: vec![
            Example { command: "terraform plan".into(), expected: Decision::Allow },
            Example { command: "terraform init".into(), expected: Decision::Allow },
            Example { command: "terragrunt plan".into(), expected: Decision::Allow },
            Example { command: "tofu plan".into(), expected: Decision::Allow },
        ],
    });

    // =========================================================================
    // Nix commands
    // =========================================================================

    rules.push(Rule {
        command: "nix".into(),
        matchers: vec![ArgMatcher::Positional(vec!["flake".into(), "update".into()])],
        decision: Decision::Ask,
        reason: Some("Flake update requires confirmation".into()),
        examples: vec![
            Example { command: "nix flake update".into(), expected: Decision::Ask },
        ],
    });

    rules.push(Rule {
        command: "nix".into(),
        matchers: vec![ArgMatcher::Positional(vec!["^(build|develop|eval|flake|hash|path-info|search|shell)$".into()])],
        decision: Decision::Allow,
        reason: None,
        examples: vec![
            Example { command: "nix build".into(), expected: Decision::Allow },
            Example { command: "nix eval .#foo".into(), expected: Decision::Allow },
            Example { command: "nix flake show".into(), expected: Decision::Allow },
            Example { command: "nix search nixpkgs hello".into(), expected: Decision::Allow },
            Example { command: "nix shell nixpkgs#hello".into(), expected: Decision::Allow },
            Example { command: "nix develop".into(), expected: Decision::Allow },
        ],
    });

    rules.push(allow(vec!["nix-env", "nix-prefetch-url", "nix-store"], ""));

    // darwin-rebuild/nixos-rebuild switch
    rules.push(Rule {
        command: vec!["darwin-rebuild", "nixos-rebuild"].into(),
        matchers: vec![ArgMatcher::Positional(vec!["switch".into()])],
        decision: Decision::Ask,
        reason: Some("System rebuild switch requires confirmation".into()),
        examples: vec![
            Example { command: "darwin-rebuild switch".into(), expected: Decision::Ask },
            Example { command: "nixos-rebuild switch".into(), expected: Decision::Ask },
        ],
    });

    // darwin-rebuild/nixos-rebuild fallback: allow
    rules.push(Rule {
        command: vec!["darwin-rebuild", "nixos-rebuild"].into(),
        matchers: vec![],
        decision: Decision::Allow,
        reason: None,
        examples: vec![
            Example { command: "darwin-rebuild build".into(), expected: Decision::Allow },
            Example { command: "darwin-rebuild check".into(), expected: Decision::Allow },
            Example { command: "nixos-rebuild build".into(), expected: Decision::Allow },
        ],
    });

    // =========================================================================
    // emacsclient
    // =========================================================================

    rules.push(Rule {
        command: "emacsclient".into(),
        matchers: vec![ArgMatcher::Anywhere(vec!["--eval".into(), "-e".into()])],
        decision: Decision::Ask,
        reason: Some("Lisp evaluation is dangerous".into()),
        examples: vec![
            Example { command: "emacsclient -e 1".into(), expected: Decision::Ask },
            Example { command: "emacsclient foo --eval 1".into(), expected: Decision::Ask },
        ],
    });

    rules.push(Rule {
        command: "emacsclient".into(),
        matchers: vec![],
        decision: Decision::Allow,
        reason: Some("Opening files in Emacs is safe".into()),
        examples: vec![
            Example { command: "emacsclient foo.txt".into(), expected: Decision::Allow },
            Example { command: "emacsclient -n foo.txt".into(), expected: Decision::Allow },
        ],
    });

    rules
}

fn builtin_wrappers() -> Vec<Wrapper> {
    vec![
        // Command prefixes (skip flags to find inner command)
        Wrapper { command: "nohup".into(), positional_args: vec![], kind: WrapperKind::AfterFlags },
        Wrapper { command: "env".into(), positional_args: vec![], kind: WrapperKind::AfterFlags },
        Wrapper { command: "nice".into(), positional_args: vec![], kind: WrapperKind::AfterFlags },
        Wrapper { command: "time".into(), positional_args: vec![], kind: WrapperKind::AfterFlags },
        Wrapper { command: "strace".into(), positional_args: vec![], kind: WrapperKind::AfterFlags },
        // mise exec -- <command>
        Wrapper { command: "mise".into(), positional_args: vec!["exec".into()], kind: WrapperKind::AfterDelimiter("--".into()) },
        // terragrunt exec -- <command>
        Wrapper { command: "terragrunt".into(), positional_args: vec!["exec".into()], kind: WrapperKind::AfterDelimiter("--".into()) },
        // nix shell/develop --command <cmd>
        Wrapper { command: "nix".into(), positional_args: vec!["shell".into()], kind: WrapperKind::AfterDelimiter("--command".into()) },
        Wrapper { command: "nix".into(), positional_args: vec!["develop".into()], kind: WrapperKind::AfterDelimiter("--command".into()) },
        // nix-shell --run <cmd>
        Wrapper { command: "nix-shell".into(), positional_args: vec![], kind: WrapperKind::AfterDelimiter("--run".into()) },
    ]
}

// Helper functions for building rules concisely

fn deny(command: impl Into<CommandMatcher>, reason: &str) -> Rule {
    Rule {
        command: command.into(),
        matchers: vec![],
        decision: Decision::Deny,
        reason: Some(reason.to_string()),
        examples: vec![],
    }
}

fn allow(command: impl Into<CommandMatcher>, reason: &str) -> Rule {
    Rule {
        command: command.into(),
        matchers: vec![],
        decision: Decision::Allow,
        reason: Some(reason.to_string()),
        examples: vec![],
    }
}

fn ask(command: impl Into<CommandMatcher>, reason: &str) -> Rule {
    Rule {
        command: command.into(),
        matchers: vec![],
        decision: Decision::Ask,
        reason: Some(reason.to_string()),
        examples: vec![],
    }
}

impl From<&str> for CommandMatcher {
    fn from(s: &str) -> Self {
        CommandMatcher::Exact(s.to_string())
    }
}

impl From<Vec<&str>> for CommandMatcher {
    fn from(v: Vec<&str>) -> Self {
        CommandMatcher::List(v.into_iter().map(|s| s.to_string()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_not_empty() {
        let config = builtin_config();
        assert!(!config.rules.is_empty());
        assert!(!config.wrappers.is_empty());
        assert!(config.security.blocked_paths.len() > 0);
    }
}
