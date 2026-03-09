#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DeviceId {
    pub vid: u16,
    pub pid: Option<u16>,
    pub usage_page: Option<u16>,
    pub emulator_path: Option<&'static str>,
}

impl DeviceId {
    pub const fn new(vid: u16) -> DeviceId {
        DeviceId {
            vid,
            pid: None,
            usage_page: None,
            emulator_path: None,
        }
    }

    pub const fn with_pid(mut self, pid: u16) -> DeviceId {
        self.pid = Some(pid);
        self
    }

    pub const fn with_usage_page(mut self, usage_page: u16) -> DeviceId {
        self.usage_page = Some(usage_page);
        self
    }

    pub const fn with_emulator_path(mut self, path: &'static str) -> DeviceId {
        self.emulator_path = Some(path);
        self
    }
}
