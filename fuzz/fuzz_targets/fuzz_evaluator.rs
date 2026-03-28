#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use may_i_core::ast::Config;
use may_i_core::context::ContextFacts;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    command: String,
    args: Vec<String>,
    config: Config,
    facts: ContextFacts,
}

fuzz_target!(|input: FuzzInput| {
    // The evaluator must never panic on any valid input.
    let _ = may_i_engine::evaluate(
        &input.command,
        &input.args,
        &input.config,
        &input.facts,
    );
});
