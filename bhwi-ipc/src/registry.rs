use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

/// A device cannot interleave two clients' commands, so a second caller is
/// refused rather than queued.
#[derive(Clone, Default)]
pub struct Registry(Rc<RefCell<HashSet<String>>>);

impl Registry {
    /// Claims the device at `path`, or returns `None` if another client holds it.
    pub fn claim(&self, path: &str) -> Option<Lease> {
        if !self.0.borrow_mut().insert(path.to_owned()) {
            return None;
        }
        Some(Lease {
            registry: self.clone(),
            path: path.to_owned(),
        })
    }
}

/// A claim on one device, released when dropped.
pub struct Lease {
    registry: Registry,
    path: String,
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.registry.0.borrow_mut().remove(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_has_one_holder_at_a_time() {
        let registry = Registry::default();
        let lease = registry.claim("hid:1").unwrap();
        assert!(registry.claim("hid:1").is_none());
        assert!(registry.claim("hid:2").is_some());
        drop(lease);
        assert!(registry.claim("hid:1").is_some());
    }
}
