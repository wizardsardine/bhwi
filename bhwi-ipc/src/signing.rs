use std::cell::RefCell;
use std::rc::Rc;

#[cfg(feature = "ledger")]
use bhwi_async::signing::ledger::LedgerSigningError;
use bhwi_async::signing::{SignError, SignedPsbt, sign_psbt, sign_psbt_with_context};
use bhwi_async::{DeviceContext, HWIDeviceError};
use bitcoin::psbt::Psbt;
use tokio::task::{AbortHandle, JoinHandle};

use crate::bhwi_capnp::signing;
use crate::error::{self, ErrorCode, Failure};
use crate::session::Session;

/// One signing run, driven by its own task so that `abort` can cut it short
/// while `result` is still outstanding.
pub struct SigningServer {
    task: RefCell<Option<JoinHandle<Result<SignedPsbt, SignError>>>>,
    abort: AbortHandle,
    session: Rc<Session>,
}

impl SigningServer {
    /// Starts signing `psbt` on the session's device in a local task.
    pub fn spawn(session: Rc<Session>, psbt: Psbt, context: Option<DeviceContext>) -> Self {
        let signing_session = session.clone();
        let network = session.network;
        let task = tokio::task::spawn_local(async move {
            let mut device = signing_session.device.lock().await;
            signing_session.ensure_open().map_err(|_| {
                SignError::Device(HWIDeviceError::new(std::io::Error::other(
                    "the device was closed by an aborted command",
                )))
            })?;
            match context {
                Some(context) => sign_psbt_with_context(&mut device, psbt, context).await,
                None => sign_psbt(&mut device, psbt, network).await,
            }
        });
        Self {
            abort: task.abort_handle(),
            task: RefCell::new(Some(task)),
            session,
        }
    }

    fn take_task(&self) -> Option<JoinHandle<Result<SignedPsbt, SignError>>> {
        self.task.borrow_mut().take()
    }

    fn cancel(&self) {
        if !self.abort.is_finished() {
            self.session.close();
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
            // `abort` closes the session, so a cut-short run reports that
            // rather than looking like a repeated call.
            self.session
                .ensure_open()
                .map_err(|_| Failure::new(ErrorCode::UserCancelled, "signing was aborted"))?;
            let task = self.take_task().ok_or_else(|| {
                Failure::new(ErrorCode::BadArgument, "this signing run was already taken")
            })?;
            match task.await {
                Ok(Ok(signed)) => Ok(signed),
                Ok(Err(err)) => Err(sign_error(err)),
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
