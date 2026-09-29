#[cfg(unix)]
fn main() -> anyhow::Result<()> {
    unix::main()
}

#[cfg(not(unix))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("bhwi-ipc serves a Unix socket and has no Windows transport yet")
}

#[cfg(unix)]
mod unix {
    use std::path::PathBuf;

    use anyhow::Result;
    use clap::Parser;

    #[derive(Parser, Debug)]
    #[command(author, version, about, long_about = None)]
    struct Args {
        /// Path of the Unix socket to serve. It is created readable by its owner alone.
        #[arg(long)]
        socket: PathBuf,
    }

    pub fn main() -> Result<()> {
        let args = Args::parse();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        // Device I/O and capnp-rpc are both !Send, so the whole server runs on
        // one thread.
        let local = tokio::task::LocalSet::new();
        // Binding registers the socket with the reactor, so it needs the
        // runtime to be entered.
        let listener = {
            let _guard = runtime.enter();
            bhwi_ipc::listener::bind(&args.socket)?
        };
        local.block_on(&runtime, bhwi_ipc::listener::serve(listener))
    }
}
