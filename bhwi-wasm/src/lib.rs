pub mod ledger;
pub mod pinserver;
pub mod webhid;
pub mod webserial;

use std::str::FromStr;

use async_trait::async_trait;
use bhwi_async::{
    coldcard::Coldcard,
    transport::coldcard_hid::{ColdcardTransportHID, COLDCARD_VID},
    transport::ledger_hid::{LedgerTransportHID, LEDGER_VID},
    Jade, Ledger, HWI as AsyncHWI,
};
use bitcoin::{bip32::DerivationPath, Network};
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
    async fn unlock(&mut self, network: &str) -> Result<(), JsValue>;
    async fn get_mfg(&mut self) -> Result<String, JsValue>;
    async fn get_xpub(&mut self, path: &str, display: bool) -> Result<String, JsValue>;
}

#[async_trait(?Send)]
impl<T: AsyncHWI> HWI for T {
    async fn unlock(&mut self, network: &str) -> Result<(), JsValue> {
        let n = Network::from_str(network).map_err(|e| JsValue::from_str(&e.to_string()))?;
        self.unlock(n)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to unlock: {:?}", e)))
    }

    async fn get_mfg(&mut self) -> Result<String, JsValue> {
        self.get_master_fingerprint()
            .await
            .map(|fp| fp.to_string())
            .map_err(|e| JsValue::from_str(&format!("Failed to get fingerprint: {:?}", e)))
    }

    async fn get_xpub(&mut self, path: &str, display: bool) -> Result<String, JsValue> {
        let p = DerivationPath::from_str(path)
            .map_err(|e| JsValue::from_str(&format!("Failed to get fingerprint: {:?}", e)))?;
        self.get_extended_pubkey(p, display)
            .await
            .map(|xpub| xpub.to_string())
            .map_err(|e| JsValue::from_str(&format!("Failed to get fingerprint: {:?}", e)))
    }
}

pub enum Device {
    Ledger(Ledger<LedgerTransportHID<webhid::WebHidDevice>>),
    Coldcard(Coldcard<ColdcardTransportHID<webhid::WebHidDevice>>),
    Jade(Jade<WebSerialDevice, PinServer>),
}

impl<'a> AsRef<dyn HWI + 'a> for Device {
    fn as_ref(&self) -> &(dyn HWI + 'a) {
        match self {
            Device::Coldcard(l) => l,
            Device::Ledger(l) => l,
            Device::Jade(j) => j,
        }
    }
}

impl<'a> AsMut<dyn HWI + 'a> for Device {
    fn as_mut(&mut self) -> &mut (dyn HWI + 'a) {
        match self {
            Device::Coldcard(l) => l,
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
    pub async fn connect_coldcard(&mut self, on_close_cb: JsValue) -> Result<(), JsValue> {
        let device = WebHidDevice::get_webhid_device("Coldcard", COLDCARD_VID, None, on_close_cb)
            .await
            .ok_or(JsValue::from_str("Failed to connect to coldcard"))?;
        let mut rng = rand_core::OsRng;
        self.device = Some(Device::Coldcard(Coldcard::new(
            ColdcardTransportHID::new(device),
            &mut rng,
        )));
        Ok(())
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
    pub async fn connect_jade(
        &mut self,
        network: &str,
        on_close_cb: JsValue,
    ) -> Result<(), JsValue> {
        let network = Network::from_str(network).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let device = WebSerialDevice::get_webserial_device(115200, on_close_cb)
            .await
            .ok_or(JsValue::from_str("Failed to connect to jade"))?;
        self.device = Some(Device::Jade(Jade::new(network, device, PinServer {})));
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn unlock(&mut self, network: &str) -> Result<(), JsValue> {
        match &mut self.device {
            Some(d) => d.as_mut().unlock(network).await,
            None => Err(JsValue::from_str("Device not connected")),
        }
    }

    #[wasm_bindgen]
    pub async fn get_master_fingerprint(&mut self) -> Result<String, JsValue> {
        match &mut self.device {
            Some(d) => d.as_mut().get_mfg().await,
            None => Err(JsValue::from_str("Device not connected")),
        }
    }

    #[wasm_bindgen]
    pub async fn get_extended_pubkey(
        &mut self,
        path: &str,
        display: bool,
    ) -> Result<String, JsValue> {
        match &mut self.device {
            Some(d) => d.as_mut().get_xpub(path, display).await,
            None => Err(JsValue::from_str("Device not connected")),
        }
    }
}
