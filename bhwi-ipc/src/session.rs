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

    /// An aborted command leaves the device part-way through an exchange.
    pub fn close(&self) {
        self.closed.set(true);
    }

    /// A command can be aborted while it waits for the device.
    pub async fn lock_open(&self) -> Result<futures::lock::MutexGuard<'_, HwiDevice>, Failure> {
        let device = self.device.lock().await;
        self.ensure_open()?;
        Ok(device)
    }

    /// Fails with `notReady` once an aborted command has closed the session.
    pub fn ensure_open(&self) -> Result<(), Failure> {
        if self.closed.get() {
            return Err(Failure::new(
                ErrorCode::NotReady,
                "the device was closed by an aborted command",
            ));
        }
        Ok(())
    }
}
