//! Native HID discovery paths and report I/O.

use std::sync::Arc;

use async_hid::{
    AsyncHidRead, AsyncHidWrite, Device as HidDevice, DeviceId, DeviceReaderWriter, HidBackend,
};
use async_trait::async_trait;
use bhwi_async::transport::Channel;
use futures::stream::StreamExt;
use tokio::sync::Mutex;

/// Returns a discovery path suitable for [`crate::DeviceSelector::device_path`].
///
/// The path is `hid:VID:PID:SUFFIX`, with four-digit hexadecimal USB identifiers.
/// `SUFFIX` uses the serial number when available, otherwise an OS identifier
/// that may change after reconnecting the device.
pub fn hid_path(dev: &HidDevice) -> String {
    let suffix = dev.serial_number.clone().unwrap_or_else(|| os_id(&dev.id));
    format!("hid:{:04x}:{:04x}:{suffix}", dev.vendor_id, dev.product_id)
}

fn os_id(id: &DeviceId) -> String {
    match id {
        #[cfg(target_os = "windows")]
        DeviceId::UncPath(path) => format!("unc={path}"),
        #[cfg(target_os = "linux")]
        DeviceId::DevPath(path) => format!("dev={}", path.display()),
        #[cfg(target_os = "macos")]
        DeviceId::RegistryEntryId(entry) => format!("ioreg={entry:x}"),
        _ => "unknown".to_owned(),
    }
}

/// Returns the first currently enumerated HID device satisfying `matches`.
///
/// The bus is read again so a previously listed device may no longer be present.
/// This does not open the device.
pub async fn find_hid(
    matches: impl Fn(&HidDevice) -> bool,
) -> crate::NativeResult<Option<HidDevice>> {
    let backend = HidBackend::default();
    let mut devices = backend.enumerate().await?;
    while let Some(dev) = devices.next().await {
        if matches(&dev) {
            return Ok(Some(dev));
        }
    }
    Ok(None)
}

/// A native HID report channel backed by `async_hid`.
///
/// Writes prepend a zero report ID for unnumbered reports; callers provide only
/// the report payload. Reads return the input report bytes.
pub struct HidChannel {
    device: Arc<Mutex<DeviceReaderWriter>>,
}

impl HidChannel {
    /// Creates a channel from an already-open HID reader and writer.
    pub fn new(device: DeviceReaderWriter) -> Self {
        Self {
            device: Arc::new(Mutex::new(device)),
        }
    }
}

#[async_trait(?Send)]
impl Channel for HidChannel {
    async fn send(&self, data: &[u8]) -> Result<usize, std::io::Error> {
        // async-hid takes the report ID as byte 0; prepend 0x00 for unnumbered reports.
        let mut report = Vec::with_capacity(data.len() + 1);
        report.push(0x00);
        report.extend_from_slice(data);
        self.device
            .lock()
            .await
            .write_output_report(&report)
            .await
            .map_err(hid_io_error)?;
        Ok(data.len())
    }

    async fn receive(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error> {
        self.device
            .lock()
            .await
            .read_input_report(data)
            .await
            .map_err(hid_io_error)
    }
}

fn hid_io_error(error: async_hid::HidError) -> std::io::Error {
    match error {
        async_hid::HidError::Disconnected | async_hid::HidError::NotConnected => {
            std::io::Error::new(std::io::ErrorKind::NotConnected, error)
        }
        error => std::io::Error::other(error),
    }
}
