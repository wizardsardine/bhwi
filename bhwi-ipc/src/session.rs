use std::cell::Cell;

use bhwi_async::device::{Device as HwiDevice, DeviceType};
use bitcoin::Network;
use futures::lock::Mutex;

use crate::error::{ErrorCode, Failure};
use crate::prompt::Prompter;
use crate::registry::Lease;

/// The mutex serialises calls because a device cannot interleave two commands.
pub struct Session {
    /// The held device.
    pub device: Mutex<HwiDevice>,
    /// The device's type, readable without the lock.
    pub device_type: DeviceType,
    /// Whether the device is an emulator.
    pub is_emulated: bool,
    /// The selector's network.
    pub network: Network,
    /// The client's prompt for this device.
    pub prompter: Prompter,
    closed: Cell<bool>,
    _lease: Lease,
}

impl Session {
    /// Creates a session that keeps `lease` until it is dropped.
    pub fn new(device: HwiDevice, network: Network, prompter: Prompter, lease: Lease) -> Self {
        Self {
            device_type: device.device_type(),
            is_emulated: device.is_emulated(),
            device: Mutex::new(device),
            network,
            prompter,
            closed: Cell::new(false),
            _lease: lease,
        }
    }

    /// An interrupted exchange can leave a reply on its way, which the next
    /// command would read as its own.
    pub fn close(&self) {
        self.closed.set(true);
    }

    /// A command can be aborted while it waits for the device.
    async fn lock_open(&self) -> Result<futures::lock::MutexGuard<'_, HwiDevice>, Failure> {
        let device = self.device.lock().await;
        self.ensure_open()?;
        Ok(device)
    }

    /// Closes the session if the exchange is dropped before it ends.
    pub async fn exchange<T>(
        &self,
        exchange: impl AsyncFnOnce(&mut HwiDevice) -> Result<T, Failure>,
    ) -> Result<T, Failure> {
        let mut device = self.lock_open().await?;
        let unfinished = Unfinished(self);
        let outcome = exchange(&mut device).await;
        std::mem::forget(unfinished);
        if let Err(failure) = &outcome
            && matches!(
                failure.code,
                ErrorCode::Transport | ErrorCode::Disconnected | ErrorCode::Encryption
            )
        {
            self.close();
        }
        outcome
    }

    /// Fails with `notReady` once an interrupted exchange has closed the session.
    pub fn ensure_open(&self) -> Result<(), Failure> {
        if self.closed.get() {
            return Err(Failure::new(
                ErrorCode::NotReady,
                "the device was closed by an interrupted exchange",
            ));
        }
        Ok(())
    }
}

/// Closes its session when dropped; `exchange` forgets it once the exchange ends.
struct Unfinished<'a>(&'a Session);

impl Drop for Unfinished<'_> {
    fn drop(&mut self) {
        self.0.close();
    }
}

#[cfg(all(test, feature = "ledger"))]
pub(crate) mod tests {
    use std::future::pending;

    use async_trait::async_trait;
    use bhwi_async::{Ledger, Transport};
    use futures::FutureExt;

    use super::*;
    use crate::registry::Registry;

    struct Unreached;

    #[async_trait(?Send)]
    impl Transport for Unreached {
        type Error = std::io::Error;
        async fn exchange(&mut self, _: &[u8], _: bool) -> Result<Vec<u8>, Self::Error> {
            unreachable!("each test supplies the exchange itself")
        }
    }

    /// A session that holds the path `test` in `registry`.
    pub(crate) fn session_held_in(registry: &Registry, device_type: DeviceType) -> Session {
        let device = HwiDevice::new(
            "Ledger",
            device_type,
            "test",
            "test",
            Box::new(Ledger::new(Unreached)),
            false,
        );
        let lease = registry.claim("test").unwrap();
        Session::new(device, Network::Regtest, Prompter::default(), lease)
    }

    fn session() -> Session {
        session_held_in(&Registry::default(), DeviceType::Ledger)
    }

    #[test]
    fn a_dropped_exchange_closes_the_session() {
        let session = session();
        let mut call = Box::pin(session.exchange(async |_| pending::<Result<(), Failure>>().await));
        assert!(call.as_mut().now_or_never().is_none());
        drop(call);
        assert_eq!(session.ensure_open().unwrap_err().code, ErrorCode::NotReady);
    }

    #[test]
    fn a_call_dropped_before_it_holds_the_device_leaves_the_session_open() {
        let session = session();
        let held = session.device.lock().now_or_never().unwrap();
        let mut call = Box::pin(session.exchange(async |_| Ok(())));
        assert!(call.as_mut().now_or_never().is_none());
        drop(call);
        drop(held);
        assert!(session.ensure_open().is_ok());
    }

    #[test]
    fn only_a_failure_that_can_leave_a_reply_unread_closes_the_session() {
        for (code, closes) in [
            (ErrorCode::Transport, true),
            (ErrorCode::UserCancelled, false),
        ] {
            let session = session();
            let outcome = session
                .exchange(async |_| Err::<(), _>(Failure::new(code, "test")))
                .now_or_never()
                .unwrap();
            assert_eq!(outcome.unwrap_err().code, code);
            assert_eq!(session.ensure_open().is_err(), closes);
        }
    }
}
