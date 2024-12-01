pub mod ledger;
pub mod pinserver;
pub mod webhid;
pub mod webserial;

use std::str::FromStr;

use async_trait::async_trait;
use bhwi_async::{
    transport::ledger::hid::{LedgerTransportHID, LEDGER_VID},
    Jade, Ledger, HWI as AsyncHWI,
};
use bitcoin::Network;
use log::Level;
use pinserver::PinServer;
use wasm_bindgen::prelude::*;
use webhid::WebHidDevice;
use webserial::WebSerialDevice;

#[wasm_bindgen]
pub fn initialize_logging(level: &str) {
    console_error_panic_hook::set_once();
    // Attempt to parse the log level from the string, default to Info if invalid
    let log_level = Level::from_str(level).unwrap_or(Level::Info);

    console_log::init_with_level(log_level).expect("error initializing log");
}

#[async_trait(?Send)]
pub trait HWI {
    async fn unlock(&self, network: &str) -> Result<(), JsValue>;
    async fn get_master_fingerprint(&self) -> Result<String, JsValue>;
}

#[async_trait(?Send)]
impl<T: AsyncHWI> HWI for T {
    async fn unlock(&self, network: &str) -> Result<(), JsValue> {
        let network = Network::from_str(network).map_err(|e| JsValue::from_str(&e.to_string()))?;
        self.unlock(network)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to unlock: {:?}", e)))
    }
    async fn get_master_fingerprint(&self) -> Result<String, JsValue> {
        self.get_master_fingerprint()
            .await
            .map(|fp| fp.to_string())
            .map_err(|e| JsValue::from_str(&format!("Failed to get fingerprint: {:?}", e)))
    }
}

pub enum Device {
    Ledger(Ledger<LedgerTransportHID<webhid::WebHidDevice>>),
    Jade(Jade<WebSerialDevice, PinServer>),
}

impl<'a> AsRef<dyn HWI + 'a> for Device {
    fn as_ref(&self) -> &(dyn HWI + 'a) {
        match self {
            Device::Ledger(l) => l,
            Device::Jade(j) => j,
        }
    }
}

#[wasm_bindgen]
pub struct Client {
    device: Option<Device>,
}

#[wasm_bindgen]
impl Client {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Client {
        Client { device: None }
    }

    #[wasm_bindgen]
    pub async fn connect_ledger(&mut self, on_close_cb: JsValue) -> Result<(), JsValue> {
        let device = WebHidDevice::get_webhid_device("Ledger", LEDGER_VID, None, on_close_cb)
            .await
            .ok_or(JsValue::from_str("Failed to connect to ledger"))?;
        self.device = Some(Device::Ledger(Ledger::new(LedgerTransportHID::new(device))));
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn unlock(&self, network: &str) -> Result<(), JsValue> {
        match &self.device {
            Some(d) => d.as_ref().unlock(network).await,
            None => Err(JsValue::from_str("Device not connected")),
        }
    }

    #[wasm_bindgen]
    pub async fn get_master_fingerprint(&self) -> Result<String, JsValue> {
        match &self.device {
            Some(d) => d.as_ref().get_master_fingerprint().await,
            None => Err(JsValue::from_str("Device not connected")),
        }
    }
}
