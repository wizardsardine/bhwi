use std::sync::Arc;

use async_hid::{
    AsyncHidRead, AsyncHidWrite, Device as HidDevice, DeviceId, DeviceReaderWriter, HidBackend,
};
use async_trait::async_trait;
use bhwi_async::transport::Channel;
use futures::stream::StreamExt;
use tokio::sync::Mutex;

/// A user passes this back with `--device-path`. A serial survives a replug and
/// two of the same model only share one if the firmware is broken. Without one
/// the OS identifier is all that tells two otherwise identical devices apart,
/// at the cost of changing on every replug.
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

/// The bus is read again at open time, since a listed device may be gone by then.
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

pub struct HidChannel {
    device: Arc<Mutex<DeviceReaderWriter>>,
}

impl HidChannel {
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
            .map_err(std::io::Error::other)?;
        Ok(data.len())
    }

    async fn receive(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error> {
        self.device
            .lock()
            .await
            .read_input_report(data)
            .await
            .map_err(std::io::Error::other)
    }
}
