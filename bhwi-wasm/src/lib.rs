pub mod ledger;
pub mod pinserver;
pub mod webhid;
pub mod webserial;

use std::str::FromStr;

use async_trait::async_trait;
use bhwi::bitbox::{BITBOX02_PID, BITBOX02_VID};
use bhwi::ledger::{LedgerWalletPolicy, Version};
use bhwi::miniscript::descriptor::WalletPolicy;
use bhwi::{coldcard::COLDCARD_DEVICE_ID, ledger::LEDGER_DEVICE_ID};
use bhwi_async::{
    DeviceContext, DisplayAddress, HWI as AsyncHWI, Jade, Ledger, bitbox::BitBox,
    coldcard::Coldcard, transport::bitbox::hid::BitBoxTransportHID,
    transport::coldcard::hid::ColdcardTransportHID, transport::ledger::hid::LedgerTransportHID,
};
use bitcoin::{Network, address::AddressType, bip32::DerivationPath};
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
    async fn display_address(
        &mut self,
        address: DisplayAddress,
        context: Option<DeviceContext>,
    ) -> Result<String, JsValue>;
    async fn register_wallet(&mut self, name: &str, policy: &str) -> Result<Vec<u8>, JsValue>;
    async fn get_info(&mut self) -> Result<JsValue, JsValue>;
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

    async fn display_address(
        &mut self,
        address: DisplayAddress,
        context: Option<DeviceContext>,
    ) -> Result<String, JsValue> {
        AsyncHWI::display_address(self, address, context)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to display address: {:?}", e)))
    }

    async fn register_wallet(&mut self, name: &str, policy: &str) -> Result<Vec<u8>, JsValue> {
        AsyncHWI::register_wallet(self, name, policy)
            .await
            .map(|hmac| hmac.to_vec())
            .map_err(|e| JsValue::from_str(&format!("Failed to register wallet: {:?}", e)))
    }

    async fn get_info(&mut self) -> Result<JsValue, JsValue> {
        let info = AsyncHWI::get_info(self)
            .await
            .map_err(|e| JsValue::from_str(&format!("Failed to get info: {:?}", e)))?;
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"version".into(), &JsValue::from_str(&info.version)).unwrap();
        let networks = js_sys::Array::new();
        for n in &info.networks {
            networks.push(&JsValue::from_str(match n {
                Network::Bitcoin => "bitcoin",
                _ => "testnet",
            }));
        }
        js_sys::Reflect::set(&obj, &"networks".into(), &networks).unwrap();
        js_sys::Reflect::set(
            &obj,
            &"firmware".into(),
            &match &info.firmware {
                Some(f) => JsValue::from_str(f),
                None => JsValue::NULL,
            },
        )
        .unwrap();
        Ok(obj.into())
    }
}

#[allow(clippy::large_enum_variant)]
pub enum Device {
    Ledger(Ledger<LedgerTransportHID<webhid::WebHidDevice>>),
    Coldcard(Coldcard<ColdcardTransportHID<webhid::WebHidDevice>>),
    Jade(Jade<WebSerialDevice, PinServer>),
    BitBox(BitBox<BitBoxTransportHID<webhid::WebHidDevice>>),
}

impl<'a> AsRef<dyn HWI + 'a> for Device {
    fn as_ref(&self) -> &(dyn HWI + 'a) {
        match self {
            Device::Coldcard(l) => l,
            Device::Ledger(l) => l,
            Device::Jade(j) => j,
            Device::BitBox(b) => b,
        }
    }
}

impl<'a> AsMut<dyn HWI + 'a> for Device {
    fn as_mut(&mut self) -> &mut (dyn HWI + 'a) {
        match self {
            Device::Coldcard(l) => l,
            Device::Ledger(l) => l,
            Device::Jade(j) => j,
            Device::BitBox(b) => b,
        }
    }
}

#[derive(Default)]
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
        let device =
            WebHidDevice::get_webhid_device("Coldcard", COLDCARD_DEVICE_ID.vid, None, on_close_cb)
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
    pub async fn connect_bitbox(
        &mut self,
        network: &str,
        on_close_cb: JsValue,
        on_pairing_code_cb: JsValue,
    ) -> Result<(), JsValue> {
        let network = Network::from_str(network).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let device = WebHidDevice::get_webhid_device(
            "BitBox02",
            BITBOX02_VID,
            Some(BITBOX02_PID),
            on_close_cb,
        )
        .await
        .ok_or(JsValue::from_str("Failed to connect to bitbox"))?;
        let mut bb = BitBox::new(BitBoxTransportHID::new(device), None).with_network(network);
        // The pairing code hook fires synchronously inside `unlock`; forward it to JS so the
        // website can render the code while the user confirms it on the device.
        bb.set_pairing_code_hook(Box::new(move |code| {
            if let Ok(f) = on_pairing_code_cb.clone().dyn_into::<js_sys::Function>() {
                let _ = f.call1(&JsValue::NULL, &JsValue::from_str(code));
            }
        }));
        self.device = Some(Device::BitBox(bb));
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn connect_ledger(&mut self, on_close_cb: JsValue) -> Result<(), JsValue> {
        let device =
            WebHidDevice::get_webhid_device("Ledger", LEDGER_DEVICE_ID.vid, None, on_close_cb)
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
    pub async fn get_info(&mut self) -> Result<JsValue, JsValue> {
        match &mut self.device {
            Some(d) => d.as_mut().get_info().await,
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

    #[wasm_bindgen]
    pub async fn register_wallet(
        &mut self,
        name: &str,
        policy: &str,
    ) -> Result<Option<String>, JsValue> {
        match &mut self.device {
            Some(Device::Ledger(l)) => {
                let hmac = AsyncHWI::register_wallet(l, name, policy)
                    .await
                    .map_err(|e| {
                        JsValue::from_str(&format!("Failed to register wallet: {:?}", e))
                    })?;
                Ok(Some(hex::encode(hmac)))
            }
            Some(d) => {
                d.as_mut().register_wallet(name, policy).await?;
                Ok(None)
            }
            None => Err(JsValue::from_str("Device not connected")),
        }
    }

    #[wasm_bindgen]
    pub async fn display_address_by_path(
        &mut self,
        path: &str,
        display: bool,
        address_format: Option<String>,
    ) -> Result<String, JsValue> {
        let path = DerivationPath::from_str(path)
            .map_err(|e| JsValue::from_str(&format!("Invalid derivation path: {:?}", e)))?;
        let address_format = address_format
            .map(|f| match f.as_str() {
                "legacy" => Ok(AddressType::P2pkh),
                "nested-segwit" => Ok(AddressType::P2sh),
                "native-segwit" => Ok(AddressType::P2wpkh),
                "taproot" => Ok(AddressType::P2tr),
                _ => Err(JsValue::from_str(&format!(
                    "Invalid address format: {f}. Expected: legacy, nested-segwit, native-segwit, taproot"
                ))),
            })
            .transpose()?;
        let address = DisplayAddress::ByPath {
            path,
            display,
            address_format,
        };
        match &mut self.device {
            Some(d) => d.as_mut().display_address(address, None).await,
            None => Err(JsValue::from_str("Device not connected")),
        }
    }

    #[wasm_bindgen]
    pub async fn display_address_by_descriptor(
        &mut self,
        descriptor_name: &str,
        index: u32,
        change: bool,
        display: bool,
        wallet_hmac_hex: Option<String>,
        wallet_descriptor: Option<String>,
    ) -> Result<String, JsValue> {
        // BitBox re-supplies the policy descriptor on every address display; Ledger needs the
        // registered policy plus its hmac; Coldcard/Jade resolve the wallet by name on-device.
        let context = match &self.device {
            Some(Device::BitBox(_)) => {
                let desc = wallet_descriptor.ok_or_else(|| {
                    JsValue::from_str("BitBox descriptor address requires wallet_descriptor")
                })?;
                Some(DeviceContext::BitBox { policy: desc })
            }
            Some(Device::Ledger(_)) => match (wallet_hmac_hex, wallet_descriptor) {
                (Some(hmac_hex), Some(desc)) => {
                    let hmac_bytes = hex::decode(&hmac_hex)
                        .map_err(|e| JsValue::from_str(&format!("Invalid hmac hex: {e}")))?;
                    let hmac: [u8; 32] = hmac_bytes
                        .try_into()
                        .map_err(|_| JsValue::from_str("hmac must be 32 bytes (64 hex chars)"))?;
                    let wallet_policy: WalletPolicy = desc.parse().map_err(|e| {
                        JsValue::from_str(&format!("Invalid wallet descriptor: {e}"))
                    })?;
                    let ledger_policy = LedgerWalletPolicy::new(
                        descriptor_name.to_string(),
                        Version::V2,
                        wallet_policy,
                    );
                    Some(DeviceContext::Ledger {
                        wallet_policy: ledger_policy,
                        wallet_hmac: Some(hmac),
                    })
                }
                (None, None) => None,
                _ => {
                    return Err(JsValue::from_str(
                        "Both wallet_hmac_hex and wallet_descriptor must be provided together",
                    ));
                }
            },
            _ => None,
        };
        let address = DisplayAddress::ByDescriptor {
            index,
            change,
            display,
            descriptor_name: descriptor_name.to_string(),
        };
        match &mut self.device {
            Some(d) => d.as_mut().display_address(address, context).await,
            None => Err(JsValue::from_str("Device not connected")),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("WASM error: {0}")]
pub struct WasmError(String);

impl From<JsValue> for WasmError {
    fn from(value: JsValue) -> Self {
        Self(value.as_string().unwrap_or_else(|| format!("{:?}", value)))
    }
}
