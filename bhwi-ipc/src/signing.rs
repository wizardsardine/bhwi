use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};

use bhwi_async::DeviceContext;
#[cfg(feature = "ledger")]
use bhwi_async::signing::ledger::LedgerSigningError;
use bhwi_async::signing::{SignError, SignedPsbt, sign_psbt, sign_psbt_with_context};
use bitcoin::psbt::Psbt;
use tokio::task::{AbortHandle, JoinHandle};

use crate::bhwi_capnp::signing;
use crate::error::{self, ErrorCode, Failure};
use crate::session::Session;

/// One signing run, driven by its own task so that `abort` can cut it short
/// while `result` is still outstanding.
pub struct SigningServer {
    task: RefCell<Option<JoinHandle<Result<SignedPsbt, Failure>>>>,
    abort: AbortHandle,
    aborted: Cell<bool>,
    /// Only the running task holds the session, so the device is released when
    /// the run ends, not when the client drops this capability.
    session: Weak<Session>,
}

impl SigningServer {
    /// Starts signing `psbt` on the session's device in a local task.
    pub fn spawn(session: Rc<Session>, psbt: Psbt, context: Option<DeviceContext>) -> Self {
        let held = Rc::downgrade(&session);
        let network = session.network;
        let task = tokio::task::spawn_local(async move {
            session
                .exchange(async move |device| {
                    match context {
                        Some(context) => sign_psbt_with_context(device, psbt, context).await,
                        None => sign_psbt(device, psbt, network).await,
                    }
                    .map_err(sign_error)
                })
                .await
        });
        Self {
            abort: task.abort_handle(),
            task: RefCell::new(Some(task)),
            aborted: Cell::new(false),
            session: held,
        }
    }

    fn take_task(&self) -> Option<JoinHandle<Result<SignedPsbt, Failure>>> {
        self.task.borrow_mut().take()
    }

    fn cancel(&self) {
        if !self.abort.is_finished() {
            self.aborted.set(true);
            if let Some(session) = self.session.upgrade() {
                session.close();
            }
        }
        self.abort.abort();
    }
}

impl Drop for SigningServer {
    fn drop(&mut self) {
        self.cancel();
    }
}

impl signing::Server for SigningServer {
    async fn result(
        self: Rc<Self>,
        _: signing::ResultParams,
        mut results: signing::ResultResults,
    ) -> Result<(), capnp::Error> {
        let outcome = async {
            // A cut-short run reports that rather than looking like a repeated call.
            if self.aborted.get() {
                return Err(Failure::new(
                    ErrorCode::UserCancelled,
                    "signing was aborted",
                ));
            }
            let task = self.take_task().ok_or_else(|| {
                Failure::new(ErrorCode::BadArgument, "this signing run was already taken")
            })?;
            match task.await {
                Ok(outcome) => outcome,
                Err(err) if err.is_cancelled() => Err(Failure::new(
                    ErrorCode::UserCancelled,
                    "signing was aborted",
                )),
                Err(err) => Err(Failure::new(ErrorCode::Other, err)),
            }
        }
        .await;
        error::reply(
            results.get().init_result(),
            outcome,
            |builder, SignedPsbt { psbt, signed }| {
                let mut response = builder.init_ok();
                response.set_psbt(psbt.to_string());
                response.set_signed(signed);
                Ok(())
            },
        )
    }

    async fn abort(
        self: Rc<Self>,
        _: signing::AbortParams,
        _: signing::AbortResults,
    ) -> Result<(), capnp::Error> {
        self.cancel();
        Ok(())
    }
}

fn sign_error(err: SignError) -> Failure {
    match err {
        #[cfg(feature = "ledger")]
        SignError::Ledger(LedgerSigningError::BadArgument(message)) => error::bad_argument(message),
        #[cfg(feature = "ledger")]
        SignError::Ledger(LedgerSigningError::Device(err)) => error::device(&err),
        SignError::Device(err) => error::device(&err),
        other => Failure::new(ErrorCode::Other, other),
    }
}

#[cfg(all(test, feature = "ledger"))]
mod tests {
    use bhwi_async::device::DeviceType;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::{Transaction, Version};

    use super::*;
    use crate::registry::Registry;
    use crate::session::tests::session_held_in;

    #[tokio::test(flavor = "current_thread")]
    async fn a_finished_run_releases_the_device() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let registry = Registry::default();
                // Not a Ledger, so signing fails at once without reaching the transport.
                let session = Rc::new(session_held_in(&registry, DeviceType::Specter));
                let psbt = Psbt::from_unsigned_tx(Transaction {
                    version: Version::TWO,
                    lock_time: LockTime::ZERO,
                    input: Vec::new(),
                    output: Vec::new(),
                })
                .unwrap();
                let signing = SigningServer::spawn(session, psbt, None);
                let outcome = signing.take_task().unwrap().await;
                assert!(matches!(outcome, Ok(Err(_))));

                assert!(registry.claim("test").is_some());
                drop(signing);
            })
            .await;
    }
}
