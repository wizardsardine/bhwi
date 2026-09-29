use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result};
use capnp_rpc::{RpcSystem, rpc_twoparty_capnp, twoparty};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use crate::bhwi_capnp::bhwi;
use crate::registry::Registry;
use crate::server::BhwiServer;

/// The socket is the whole access control: anyone who can open it can drive the
/// hardware wallet.
const SOCKET_MODE: u32 = 0o600;

const DESCRIPTOR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

/// A bound Unix socket, removed when dropped if it is still this listener's.
pub struct Listener {
    inner: UnixListener,
    owner: u32,
    path: std::path::PathBuf,
    inode: u64,
    _lock: std::fs::File,
}

impl Drop for Listener {
    fn drop(&mut self) {
        // Only if the path is still the socket this listener bound: someone may
        // have replaced it.
        let ours = std::fs::metadata(&self.path).is_ok_and(|current| current.ino() == self.inode);
        if ours {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Binds the socket at `path`, usable only by the current user.
pub fn bind(path: &Path) -> Result<Listener> {
    let lock = lock(path)?;
    // Binding a private path and linking it into place keeps the claim atomic.
    let staging = staging_path(path);
    let _ = std::fs::remove_file(&staging);
    let inner =
        UnixListener::bind(&staging).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(SOCKET_MODE))
        .with_context(|| format!("restricting {} to its owner", path.display()))?;

    let claimed = claim(&staging, path);
    // The listener keeps its socket through the link.
    let _ = std::fs::remove_file(&staging);
    claimed?;

    let metadata = std::fs::metadata(path)
        .with_context(|| format!("reading the owner of {}", path.display()))?;
    Ok(Listener {
        inner,
        owner: metadata.uid(),
        path: path.to_path_buf(),
        inode: metadata.ino(),
        _lock: lock,
    })
}

/// One server per socket: the one holding this lock, which the kernel releases
/// when that process exits.
fn lock(path: &Path) -> Result<std::fs::File> {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    let lock_path = path.with_file_name(name);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(SOCKET_MODE)
        .open(&lock_path)
        .with_context(|| format!("opening {}", lock_path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => {
            anyhow::bail!("{} is already served by a running bhwi-ipc", path.display())
        }
        Err(std::fs::TryLockError::Error(err)) => {
            Err(err).with_context(|| format!("locking {}", lock_path.display()))
        }
    }
}

fn staging_path(path: &Path) -> std::path::PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.staging", std::process::id()));
    path.with_file_name(name)
}

/// Under the lock, a socket already at `path` was left by a server that is gone.
fn claim(staging: &Path, path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_socket() => {
            anyhow::bail!("{} exists and is not a socket", path.display())
        }
        Ok(_) => std::fs::remove_file(path)
            .with_context(|| format!("removing the stale socket at {}", path.display()))?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).with_context(|| format!("inspecting {}", path.display())),
    }
    std::fs::hard_link(staging, path).with_context(|| format!("claiming {}", path.display()))
}

/// Accepts connections and serves the `Bhwi` capability on each.
pub async fn serve(listener: Listener) -> Result<()> {
    let registry = Registry::default();
    let mut waiting_for_descriptors = false;
    loop {
        let (stream, _) = match listener.inner.accept().await {
            Ok(accepted) => {
                waiting_for_descriptors = false;
                accepted
            }
            Err(err) if out_of_descriptors(&err) => {
                // Nothing frees a descriptor while this loop runs, so retrying
                // at once would spin.
                if !waiting_for_descriptors {
                    eprintln!("bhwi-ipc: out of file descriptors, still accepting: {err}");
                    waiting_for_descriptors = true;
                }
                tokio::time::sleep(DESCRIPTOR_BACKOFF).await;
                continue;
            }
            Err(err) if is_transient(&err) => continue,
            Err(err) => return Err(err).context("accepting a connection"),
        };
        // `bind` applies the umask, so the socket is briefly reachable by others.
        if stream.peer_cred().ok().map(|peer| peer.uid()) != Some(listener.owner) {
            continue;
        }
        serve_connection(stream, registry.clone());
    }
}

fn is_transient(err: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        err.kind(),
        ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset | ErrorKind::Interrupted
    )
}

fn out_of_descriptors(err: &std::io::Error) -> bool {
    // EMFILE and ENFILE, which share these values on Linux and macOS.
    const TOO_MANY_FILES: [i32; 2] = [24, 23];
    err.raw_os_error()
        .is_some_and(|code| TOO_MANY_FILES.contains(&code))
}

fn serve_connection(stream: UnixStream, registry: Registry) {
    let (reader, writer) = stream.into_split();
    let network = twoparty::VatNetwork::new(
        futures::io::BufReader::new(reader.compat()),
        futures::io::BufWriter::new(writer.compat_write()),
        rpc_twoparty_capnp::Side::Server,
        Default::default(),
    );
    let client: bhwi::Client = capnp_rpc::new_client(BhwiServer::new(registry));
    let rpc = RpcSystem::new(Box::new(network), Some(client.client));
    tokio::task::spawn_local(async move {
        // A client that disconnects mid-call ends its own RpcSystem, which is
        // not a server error.
        let _ = rpc.await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bhwi-ipc-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn a_regular_file_is_never_removed() {
        let dir = temp_dir("regular-file");
        let path = dir.join("notes.txt");
        std::fs::write(&path, b"keep me").unwrap();
        assert!(bind(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn a_stale_socket_is_taken_over() {
        let dir = temp_dir("stale-socket");
        let path = dir.join("bhwi.sock");
        // What a killed server leaves behind: std does not unlink on drop.
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        assert!(path.exists());
        bind(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn a_closed_listener_removes_its_socket() {
        let dir = temp_dir("closed-socket");
        let path = dir.join("bhwi.sock");
        drop(bind(&path).unwrap());
        assert!(!path.exists(), "the socket outlived its listener");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn a_held_lock_is_refused_even_when_its_socket_looks_stale() {
        let dir = temp_dir("held-lock");
        let path = dir.join("bhwi.sock");
        // A server between removing a stale socket and linking its own.
        let held = std::fs::File::create(dir.join("bhwi.sock.lock")).unwrap();
        held.try_lock().unwrap();
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        assert!(bind(&path).is_err());
        assert!(
            path.exists(),
            "a socket the starter did not own was removed"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn a_live_socket_is_refused() {
        let dir = temp_dir("live-socket");
        let path = dir.join("bhwi.sock");
        let _listener = bind(&path).unwrap();
        assert!(bind(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
