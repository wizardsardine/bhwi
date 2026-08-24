use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    // Python HWI crashes exit 1 with a traceback on stderr. Chain the default
    // hook so the panic message still reaches stderr, then force status 1
    // (instead of Rust's 101) from whichever thread panicked.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        std::process::exit(1);
    }));
    // Undocumented crash trigger so the exit-status contract test can provoke
    // a real panic in the built binary.
    if std::env::var_os("HWI_DEBUG_PANIC").is_some() {
        panic!("HWI_DEBUG_PANIC requested a crash");
    }
    bhwi_cli::hwi::run_cli(std::env::args()).await
}
