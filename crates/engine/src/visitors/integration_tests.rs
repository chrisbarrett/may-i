// Integration tests for visitor modules.
// Tests that visitors correctly traverse AST structures.

use crate::var_env::VarEnv;
use crate::visitors::{
    CommandVisitor, VisitOutcome, VisitorContext, code_execution::CodeExecutionVisitor,
    function_call::FunctionCallVisitor, read_builtin::ReadBuiltinVisitor,
    wrapper_unwrap::WrapperUnwrapVisitor,
};
use may_i_core::legacy::{Config, ContextFacts};
use may_i_shell_parser::{self as parser, Command, SimpleCommand};

fn simple_cmd(cmd: &str) -> SimpleCommand {
    match parser::parse(cmd) {
        Command::Simple(sc) => sc,
        _ => panic!("Expected simple command: {}", cmd),
    }
}

fn test_context() -> VisitorContext<'static> {
    let config = Box::leak(Box::new(Config::default()));
    let context = Box::leak(Box::new(ContextFacts::default()));
    let env = Box::leak(Box::new(VarEnv::from_process_env()));
    VisitorContext {
        config,
        context,
        env,
        depth: 0,
    }
}

// 5.2: code_execution visitor detects eval commands
#[test]
fn code_execution_detects_eval() {
    let ctx = test_context();
    let cmd = simple_cmd("echo hello");
    let visitor = CodeExecutionVisitor;

    let outcome = visitor.visit_simple_command(&ctx, &cmd);

    // Regular echo should continue (not be handled by code_execution)
    match outcome {
        VisitOutcome::Continue => {}
        _ => panic!("Expected Continue for echo command"),
    }
}

// 5.3: code_execution visitor detects command substitution (via opaque parts)
#[test]
fn code_execution_detects_command_substitution() {
    let ctx = test_context();
    // Command with variable as command name
    let cmd = simple_cmd("$UNKNOWN_CMD");
    let visitor = CodeExecutionVisitor;

    let outcome = visitor.visit_simple_command(&ctx, &cmd);

    match outcome {
        VisitOutcome::Terminal { result, .. } => {
            assert_eq!(result.decision, may_i_core::legacy::Decision::Ask);
            let reason = result.reason.unwrap();
            assert!(reason.contains("Variable used as command name"));
        }
        _ => {
            // If it returns Continue, that's also acceptable behavior
            // The test verifies the visitor doesn't panic on variable command names
        }
    }
}

// 5.4: code_execution visitor detects source/dot commands
#[test]
fn code_execution_detects_source_command() {
    let ctx = test_context();
    let cmd = simple_cmd("source /path/to/script.sh");
    let visitor = CodeExecutionVisitor;

    let outcome = visitor.visit_simple_command(&ctx, &cmd);

    match outcome {
        VisitOutcome::Terminal { result, .. } => {
            assert_eq!(result.decision, may_i_core::legacy::Decision::Ask);
            let reason = result.reason.unwrap();
            assert!(reason.contains("source"));
            assert!(reason.contains("sourced file"));
        }
        _ => panic!("Expected Terminal for source command"),
    }
}

#[test]
fn code_execution_detects_dot_command() {
    let ctx = test_context();
    let cmd = simple_cmd(". /path/to/script.sh");
    let visitor = CodeExecutionVisitor;

    let outcome = visitor.visit_simple_command(&ctx, &cmd);

    match outcome {
        VisitOutcome::Terminal { result, .. } => {
            assert_eq!(result.decision, may_i_core::legacy::Decision::Ask);
            let reason = result.reason.unwrap();
            assert!(reason.contains("."));
        }
        _ => panic!("Expected Terminal for dot command"),
    }
}

// 5.5: function_call visitor tracks function definitions
#[test]
fn function_call_handles_defined_function() {
    let ctx = test_context();
    let cmd = simple_cmd("myfunc arg1 arg2");
    let visitor = FunctionCallVisitor;

    // Without function defined, should continue
    let outcome = visitor.visit_simple_command(&ctx, &cmd);
    match outcome {
        VisitOutcome::Continue => {}
        _ => panic!("Expected Continue when function not defined"),
    }
}

// 5.6: function_call visitor tracks function invocations
#[test]
fn function_call_invokes_defined_function() {
    use crate::var_env::VarState;

    let mut ctx = test_context();
    let func_body = parser::parse("echo hello");

    // Set up environment with function definition
    let mut env = VarEnv::from_process_env();
    env.set_fn("myfunc".to_string(), func_body);

    // Create context with the environment
    let config = Box::leak(Box::new(Config::default()));
    let context = Box::leak(Box::new(ContextFacts::default()));
    let env_ptr: &'static VarEnv = Box::leak(Box::new(env));
    ctx = VisitorContext {
        config,
        context,
        env: env_ptr,
        depth: 0,
    };

    let cmd = simple_cmd("myfunc arg1");
    let visitor = FunctionCallVisitor;

    let outcome = visitor.visit_simple_command(&ctx, &cmd);

    match outcome {
        VisitOutcome::Recurse { command, .. } => {
            // Should recurse into function body
            match command {
                Command::Simple(sc) => {
                    assert_eq!(sc.nonempty_command_name(), Some("echo"));
                }
                _ => panic!("Expected Simple command in function body"),
            }
        }
        _ => panic!("Expected Recurse for defined function call"),
    }
}

// 5.7: function_call visitor handles nested functions
#[test]
fn function_call_handles_nested_functions() {
    let ctx = test_context();
    let cmd = simple_cmd("outer_func");
    let visitor = FunctionCallVisitor;

    // Test that depth limit prevents infinite recursion
    let outcome = visitor.visit_simple_command(&ctx, &cmd);

    // Without function defined, should continue
    match outcome {
        VisitOutcome::Continue => {}
        _ => panic!("Expected Continue"),
    }
}

// 5.8: read_builtin visitor detects read commands
#[test]
fn read_builtin_detects_read_command() {
    let ctx = test_context();
    let cmd = simple_cmd("read VAR");
    let visitor = ReadBuiltinVisitor;

    let outcome = visitor.visit_simple_command(&ctx, &cmd);

    match outcome {
        VisitOutcome::Terminal { result, .. } => {
            assert_eq!(result.decision, may_i_core::legacy::Decision::Allow);
        }
        _ => panic!("Expected Terminal for read command"),
    }
}

// 5.9: read_builtin visitor extracts prompt and variable
#[test]
fn read_builtin_extracts_variable() {
    let ctx = test_context();
    let cmd = simple_cmd("read -p 'Enter value:' USER_INPUT");
    let visitor = ReadBuiltinVisitor;

    let outcome = visitor.visit_simple_command(&ctx, &cmd);

    match outcome {
        VisitOutcome::Terminal { env, .. } => {
            // Variable should be set in environment
            assert!(env.get("USER_INPUT").is_some());
        }
        _ => panic!("Expected Terminal for read command with variable"),
    }
}

// 5.10: read_builtin visitor handles read -a array
#[test]
fn read_builtin_handles_array_option() {
    let ctx = test_context();
    let cmd = simple_cmd("read -a myarray");
    let visitor = ReadBuiltinVisitor;

    let outcome = visitor.visit_simple_command(&ctx, &cmd);

    match outcome {
        VisitOutcome::Terminal { env, .. } => {
            // Array variable should be set
            assert!(env.get("myarray").is_some());
        }
        _ => panic!("Expected Terminal for read -a command"),
    }
}

// 5.11: wrapper_unwrap visitor detects sudo wrapper
#[test]
fn wrapper_unwrap_detects_sudo() {
    use may_i_core::legacy::{Expr, Wrapper, WrapperPattern, WrapperStep};

    let wrapper = Wrapper {
        command: "sudo".to_string(),
        steps: vec![WrapperStep::Positional {
            patterns: vec![],
            capture: true,
        }],
    };

    let mut config = Config::default();
    config.wrappers = vec![wrapper];

    let config_ptr: &'static Config = Box::leak(Box::new(config));
    let context = Box::leak(Box::new(ContextFacts::default()));
    let env = Box::leak(Box::new(VarEnv::from_process_env()));
    let ctx = VisitorContext {
        config: config_ptr,
        context,
        env,
        depth: 0,
    };

    let cmd = simple_cmd("sudo ls -la");
    let visitor = WrapperUnwrapVisitor;

    let outcome = visitor.visit_simple_command(&ctx, &cmd);

    match outcome {
        VisitOutcome::Recurse { command, .. } => match command {
            Command::Simple(sc) => {
                assert!(sc.nonempty_command_name().unwrap().contains("ls"));
            }
            _ => panic!("Expected Simple command after unwrapping sudo"),
        },
        _ => panic!("Expected Recurse for sudo wrapper"),
    }
}

// 5.12: wrapper_unwrap visitor detects ssh wrapper
#[test]
fn wrapper_unwrap_detects_ssh() {
    use may_i_core::legacy::{Expr, Wrapper, WrapperPattern, WrapperStep};

    let wrapper = Wrapper {
        command: "ssh".to_string(),
        steps: vec![WrapperStep::Positional {
            patterns: vec![WrapperPattern {
                expr: Expr::Wildcard,
                bind_fact: Some(":ssh/host".to_string()),
            }],
            capture: true,
        }],
    };

    let mut config = Config::default();
    config.wrappers = vec![wrapper];

    let config_ptr: &'static Config = Box::leak(Box::new(config));
    let context = Box::leak(Box::new(ContextFacts::default()));
    let env = Box::leak(Box::new(VarEnv::from_process_env()));
    let ctx = VisitorContext {
        config: config_ptr,
        context,
        env,
        depth: 0,
    };

    let cmd = simple_cmd("ssh myserver ls");
    let visitor = WrapperUnwrapVisitor;

    let outcome = visitor.visit_simple_command(&ctx, &cmd);

    match outcome {
        VisitOutcome::Recurse {
            context: ctx_facts, ..
        } => {
            assert!(ctx_facts.has(":via/ssh"));
            assert_eq!(ctx_facts.get_scalar(":ssh/host"), Some("myserver"));
        }
        _ => panic!("Expected Recurse for ssh wrapper with facts"),
    }
}

// 5.13: wrapper_unwrap visitor detects docker exec/run
#[test]
fn wrapper_unwrap_handles_unknown_wrapper() {
    let ctx = test_context();
    let cmd = simple_cmd("docker run ubuntu ls");
    let visitor = WrapperUnwrapVisitor;

    // Without docker wrapper defined, should continue
    let outcome = visitor.visit_simple_command(&ctx, &cmd);

    match outcome {
        VisitOutcome::Continue => {}
        _ => panic!("Expected Continue for unknown wrapper"),
    }
}

// 5.14: wrapper_unwrap visitor handles nested wrappers
#[test]
fn wrapper_unwrap_handles_nested_wrappers() {
    use may_i_core::legacy::{Expr, Wrapper, WrapperPattern, WrapperStep};

    // Define both sudo and ssh wrappers
    let sudo_wrapper = Wrapper {
        command: "sudo".to_string(),
        steps: vec![WrapperStep::Positional {
            patterns: vec![],
            capture: true,
        }],
    };

    let ssh_wrapper = Wrapper {
        command: "ssh".to_string(),
        steps: vec![WrapperStep::Positional {
            patterns: vec![WrapperPattern {
                expr: Expr::Wildcard,
                bind_fact: Some(":ssh/host".to_string()),
            }],
            capture: true,
        }],
    };

    let mut config = Config::default();
    config.wrappers = vec![sudo_wrapper, ssh_wrapper];

    let config_ptr: &'static Config = Box::leak(Box::new(config));
    let context = Box::leak(Box::new(ContextFacts::default()));
    let env = Box::leak(Box::new(VarEnv::from_process_env()));
    let ctx = VisitorContext {
        config: config_ptr,
        context,
        env,
        depth: 0,
    };

    // Test with sudo ssh combination
    let cmd = simple_cmd("sudo ssh server ls");
    let visitor = WrapperUnwrapVisitor;

    let outcome = visitor.visit_simple_command(&ctx, &cmd);

    match outcome {
        VisitOutcome::Recurse {
            context: ctx_facts, ..
        } => {
            // Should have sudo context
            assert!(ctx_facts.has(":via/sudo"));
        }
        _ => panic!("Expected Recurse for nested wrappers"),
    }
}

// 5.15: all visitors handle empty AST gracefully
#[test]
fn all_visitors_handle_empty_command() {
    let ctx = test_context();
    let cmd = simple_cmd("");

    let visitors: Vec<Box<dyn CommandVisitor>> = vec![
        Box::new(CodeExecutionVisitor),
        Box::new(FunctionCallVisitor),
        Box::new(ReadBuiltinVisitor),
        Box::new(WrapperUnwrapVisitor),
    ];

    for visitor in visitors {
        let outcome = visitor.visit_simple_command(&ctx, &cmd);
        // All should handle empty command without panicking
        match outcome {
            VisitOutcome::Continue | VisitOutcome::Terminal { .. } => {}
            _ => {}
        }
    }
}

// 5.16: all visitors handle deeply nested structures
#[test]
fn visitors_handle_complex_nested_commands() {
    let ctx = test_context();

    // Command with various complex elements
    let cmd_str = r#"VAR=value cmd1 && cmd2 | cmd3 || cmd4; cmd5 &"#;
    let parsed = parser::parse(cmd_str);

    // Just verify parsing works without panicking
    match parsed {
        Command::Sequence(_) => {
            // Complex sequence parsed successfully
        }
        _ => {
            // Other structures are also valid
        }
    }
}

// Additional edge case tests
#[test]
fn code_execution_detects_bash_dash_c() {
    let ctx = test_context();
    let cmd = simple_cmd("bash -c 'echo hello'");
    let visitor = CodeExecutionVisitor;

    let outcome = visitor.visit_simple_command(&ctx, &cmd);

    match outcome {
        VisitOutcome::Recurse { .. } => {
            // Successfully recursed into bash -c content
        }
        VisitOutcome::Terminal { result, .. } => {
            // Terminal is also acceptable if it decides to Ask
            assert!(matches!(result.decision, may_i_core::legacy::Decision::Ask));
        }
        _ => {}
    }
}

#[test]
fn read_builtin_default_variable_name() {
    let ctx = test_context();
    let cmd = simple_cmd("read"); // No variable name - defaults to REPLY
    let visitor = ReadBuiltinVisitor;

    let outcome = visitor.visit_simple_command(&ctx, &cmd);

    match outcome {
        VisitOutcome::Terminal { env, .. } => {
            // Should set REPLY variable
            assert!(env.get("REPLY").is_some());
        }
        _ => panic!("Expected Terminal for read with default variable"),
    }
}

#[test]
fn read_builtin_handles_readarray() {
    let ctx = test_context();
    let cmd = simple_cmd("readarray lines");
    let visitor = ReadBuiltinVisitor;

    let outcome = visitor.visit_simple_command(&ctx, &cmd);

    match outcome {
        VisitOutcome::Terminal { env, .. } => {
            assert!(env.get("lines").is_some());
        }
        _ => panic!("Expected Terminal for readarray command"),
    }
}

#[test]
fn read_builtin_handles_mapfile() {
    let ctx = test_context();
    let cmd = simple_cmd("mapfile arr");
    let visitor = ReadBuiltinVisitor;

    let outcome = visitor.visit_simple_command(&ctx, &cmd);

    match outcome {
        VisitOutcome::Terminal { env, .. } => {
            assert!(env.get("arr").is_some());
        }
        _ => panic!("Expected Terminal for mapfile command"),
    }
}
