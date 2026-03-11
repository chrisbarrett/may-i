// Hook mode — read Claude Code hook payload from stdin, evaluate, respond.

use std::io::Read;

use may_i_config as config;
use may_i_engine as engine;
use miette::Context;

use crate::hook_harness::{HookRoute, route_hook};

pub fn cmd_hook(config_path: Option<&std::path::Path>) -> miette::Result<()> {
    let mut input = String::new();
    std::io::stdin()
        .take(65536)
        .read_to_string(&mut input)
        .map_err(|e| miette::miette!("{e}"))
        .wrap_err("Failed to read stdin")?;

    let payload: serde_json::Value = serde_json::from_str(&input)
        .map_err(|e| miette::miette!("{e}"))
        .wrap_err("Invalid JSON")?;

    let config_file = config::resolve_path(config_path)?;
    let config = config::load(&config_file)?;

    match route_hook(&payload)? {
        HookRoute::Silent => Ok(()),
        HookRoute::Evaluate {
            command,
            context,
            harness,
        } => {
            let result = engine::evaluate_with_context(&command, &config, &context);
            let response = harness.render_response(result);

            println!(
                "{}",
                serde_json::to_string(&response).expect("response serialization is infallible")
            );
            Ok(())
        }
    }
}
