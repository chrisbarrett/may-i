mod cli;
mod config;
mod defaults;
mod engine;
mod parser;
mod security;

fn main() {
    if let Err(e) = cli::run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
