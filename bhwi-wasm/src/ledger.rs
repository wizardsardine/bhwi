use super::webhid::WebHidDevice;
use async_trait::async_trait;
use bhwi_async::{
    ledger::Ledger,
    transport::ledger::hid::{LedgerTransportHID, ReadWrite, LEDGER_VID},
};
use wasm_bindgen::prelude::*;

#[async_trait(?Send)]
impl ReadWrite for WebHidDevice {
    async fn write(&self, data: &[u8]) -> Result<usize, std::io::Error> {
        let mut data = data.to_vec();
        self.write(&mut data).await;
        Ok(data.len())
    }
    async fn read(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error> {
        if let Some(array) = self.read().await {
            let length = array.len();
            data.copy_from_slice(&array);
            Ok(length)
        } else {
            Ok(0)
        }
    }
}

#[wasm_bindgen]
pub async fn connect_ledger(on_close_cb: JsValue) {
    if let Some(device) =
        WebHidDevice::get_webhid_device("Ledger", LEDGER_VID, None, on_close_cb).await
    {
        let l = Ledger::new(LedgerTransportHID::new(device));
        let fg = l.get_master_fingerprint().await.unwrap();
        log::info!("master_fingerpring: {}", fg)
    }
}
