use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    bhwi_cli::hwi::run_cli(std::env::args()).await
}
