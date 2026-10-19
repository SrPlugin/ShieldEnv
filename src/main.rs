mod cli;

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    let arguments = cli::args::Cli::parse();
    match cli::commands::execute(arguments) {
        Ok(code) => code,
        Err(error) if error.is_broken_pipe() => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(cli::exit_code(&error))
        }
    }
}
