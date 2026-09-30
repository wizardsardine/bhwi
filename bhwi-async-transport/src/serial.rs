use std::path::Path;

use crate::{NativeError, NativeResult};

// serialport-rs lists each macOS serial port under both its callout
// (`/dev/cu.*`) and dial-in (`/dev/tty.*`) node & skip the dial-in so the same
// device is not opened twice.
pub(crate) fn is_macos_dialin(port_name: &str) -> bool {
    port_name.starts_with("/dev/tty.")
}

pub(crate) fn require_tty_sysfs() -> NativeResult<()> {
    require_linux_tty_sysfs(
        cfg!(target_os = "linux"),
        Path::new("/sys/class/tty").exists(),
    )
}

fn require_linux_tty_sysfs(is_linux: bool, sysfs_exists: bool) -> NativeResult<()> {
    if is_linux && !sysfs_exists {
        return Err(NativeError::SerialSysfsMissing);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::require_linux_tty_sysfs;

    #[test]
    fn absent_linux_tty_sysfs_errors_before_port_enumeration() {
        let result = require_linux_tty_sysfs(true, false).map(|_| panic!("enumerator invoked"));

        assert_eq!(
            result.unwrap_err().to_string(),
            "serial port enumeration unavailable: /sys/class/tty is missing"
        );
    }
}
