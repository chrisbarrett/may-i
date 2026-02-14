mod cli;
mod config;
mod engine;
mod parser;
mod security;
mod types;

fn main() {
    if let Err(e) = cli::run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
