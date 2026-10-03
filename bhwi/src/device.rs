//! USB identifiers and emulator endpoints used by device discovery.

/// USB selection information and an optional default emulator endpoint.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DeviceId {
    /// USB vendor ID.
    pub vid: u16,
    /// USB product ID, when specified.
    pub pid: Option<u16>,
    /// HID usage page identifying the device interface, when specified.
    pub usage_page: Option<u16>,
    /// Default emulator path or transport-prefixed endpoint, when available.
    pub emulator_path: Option<&'static str>,
}

impl DeviceId {
    /// Creates an identifier with only the USB vendor ID set.
    pub const fn new(vid: u16) -> DeviceId {
        DeviceId {
            vid,
            pid: None,
            usage_page: None,
            emulator_path: None,
        }
    }

    /// Sets the USB product ID.
    pub const fn with_pid(mut self, pid: u16) -> DeviceId {
        self.pid = Some(pid);
        self
    }

    /// Sets the HID usage page.
    pub const fn with_usage_page(mut self, usage_page: u16) -> DeviceId {
        self.usage_page = Some(usage_page);
        self
    }

    /// Sets the default emulator path or endpoint.
    pub const fn with_emulator_path(mut self, path: &'static str) -> DeviceId {
        self.emulator_path = Some(path);
        self
    }
}
