use js_sys::Uint8Array;
use std::cell::RefCell;
use std::io;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    UsbDevice, UsbDirection, UsbInTransferResult, UsbOutTransferResult, UsbTransferStatus,
};

const CONFIGURATION_VALUE: u8 = 1;
const INTERFACE_NUMBER: u8 = 0;
const ENDPOINT_NUMBER: u8 = 1;
const REPORT_SIZE: u32 = 64;

#[wasm_bindgen]
pub struct WebUsbDevice {
    device: UsbDevice,
    on_close_cb: JsValue,
}

impl WebUsbDevice {
    pub async fn get_webusb_device(
        vendor_id: u16,
        product_id: Option<u16>,
        on_close_cb: JsValue,
    ) -> Option<WebUsbDevice> {
        let navigator = web_sys::window()?.navigator();
        let usb = navigator.usb();

        let filters = js_sys::Array::new();
        let filter = js_sys::Object::new();
        js_sys::Reflect::set(&filter, &"vendorId".into(), &JsValue::from(vendor_id)).unwrap();
        if let Some(product_id) = product_id {
            js_sys::Reflect::set(&filter, &"productId".into(), &JsValue::from(product_id)).unwrap();
        }
        filters.push(&filter.into());

        let options = js_sys::Object::new();
        js_sys::Reflect::set(&options, &"filters".into(), &filters.into()).unwrap();
        let options: JsValue = options.into();
        let device = match JsFuture::from(usb.request_device(&options.into())).await {
            Ok(device) => device.dyn_into::<UsbDevice>().ok()?,
            Err(_) => return None,
        };

        log::info!(
            "found usb device: {}",
            device.product_name().unwrap_or_default()
        );

        if JsFuture::from(device.open()).await.is_err() {
            return None;
        }
        if JsFuture::from(device.select_configuration(CONFIGURATION_VALUE))
            .await
            .is_err()
        {
            return None;
        }
        if JsFuture::from(device.claim_interface(INTERFACE_NUMBER))
            .await
            .is_err()
        {
            return None;
        }

        // Clears the halt and data toggle. Does not drain the IN FIFO; WebUSB has no timed read.
        let _ = JsFuture::from(device.clear_halt(UsbDirection::In, ENDPOINT_NUMBER)).await;

        let device_rc = Rc::new(RefCell::new(device.clone()));
        let on_close_cb_rc = Rc::new(RefCell::new(on_close_cb.clone()));
        let on_disconnect_closure = {
            let device_clone = device_rc.clone();
            let on_close_cb_clone = on_close_cb_rc.clone();
            Closure::wrap(Box::new(move |event: web_sys::UsbConnectionEvent| {
                let disconnected_device = event.device();
                if disconnected_device.vendor_id() == device_clone.borrow().vendor_id()
                    && disconnected_device.product_id() == device_clone.borrow().product_id()
                {
                    let on_close_cb_clone = on_close_cb_clone.borrow();
                    if !on_close_cb_clone.is_undefined()
                        && !on_close_cb_clone.is_null()
                        && let Ok(cb) = <wasm_bindgen::JsValue as Clone>::clone(&on_close_cb_clone)
                            .dyn_into::<js_sys::Function>()
                    {
                        cb.call0(&JsValue::NULL).unwrap();
                    }
                }
            }) as Box<dyn FnMut(_)>)
        };

        usb.add_event_listener_with_callback(
            "disconnect",
            on_disconnect_closure.as_ref().unchecked_ref(),
        )
        .unwrap();
        on_disconnect_closure.forget();

        Some(Self {
            device,
            on_close_cb,
        })
    }

    async fn clear_halt(&self, direction: UsbDirection) {
        if JsFuture::from(self.device.clear_halt(direction, ENDPOINT_NUMBER))
            .await
            .is_err()
        {
            log::error!("failed to clear halt on endpoint {ENDPOINT_NUMBER}");
        }
    }

    pub async fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        let result = JsFuture::from(self.device.transfer_in(ENDPOINT_NUMBER, REPORT_SIZE))
            .await
            .map_err(|e| io::Error::other(format!("usb transfer_in failed: {e:?}")))?
            .dyn_into::<UsbInTransferResult>()
            .map_err(|_| io::Error::other("unexpected usb transfer_in result"))?;

        match result.status() {
            UsbTransferStatus::Ok => {}
            UsbTransferStatus::Stall => {
                self.clear_halt(UsbDirection::In).await;
                return Err(io::Error::other("usb in endpoint stalled"));
            }
            status => {
                return Err(io::Error::other(format!(
                    "usb transfer_in status: {status:?}"
                )));
            }
        }

        let Some(view) = result.data() else {
            return Ok(0);
        };
        let length = view.byte_length().min(data.len());
        // `copy_to` asserts equal lengths, so the view must be the exact window.
        Uint8Array::new_with_byte_offset_and_length(
            &view.buffer(),
            view.byte_offset() as u32,
            length as u32,
        )
        .copy_to(&mut data[..length]);
        Ok(length)
    }

    pub async fn write(&self, data: &[u8]) -> io::Result<usize> {
        if !self.device.opened() {
            return Err(io::Error::other("usb connection is closed"));
        }
        let mut payload = data.to_vec();
        let promise = self
            .device
            .transfer_out_with_u8_slice(ENDPOINT_NUMBER, &mut payload)
            .map_err(|e| io::Error::other(format!("usb transfer_out rejected: {e:?}")))?;
        let result = JsFuture::from(promise)
            .await
            .map_err(|e| io::Error::other(format!("usb transfer_out failed: {e:?}")))?
            .dyn_into::<UsbOutTransferResult>()
            .map_err(|_| io::Error::other("unexpected usb transfer_out result"))?;

        match result.status() {
            UsbTransferStatus::Ok => Ok(result.bytes_written() as usize),
            UsbTransferStatus::Stall => {
                self.clear_halt(UsbDirection::Out).await;
                Err(io::Error::other("usb out endpoint stalled"))
            }
            status => Err(io::Error::other(format!(
                "usb transfer_out status: {status:?}"
            ))),
        }
    }
}

#[wasm_bindgen]
impl WebUsbDevice {
    #[wasm_bindgen]
    pub fn close(&mut self) {
        let close_future = JsFuture::from(self.device.close());
        let on_close_cb = self.on_close_cb.clone();

        wasm_bindgen_futures::spawn_local(async move {
            if close_future.await.is_err() {
                log::error!("failed to close usb device");
            }

            if !on_close_cb.is_undefined()
                && !on_close_cb.is_null()
                && let Ok(cb) = on_close_cb.dyn_into::<js_sys::Function>()
            {
                cb.call0(&JsValue::NULL).unwrap();
            }
        });
    }

    #[wasm_bindgen]
    pub fn valid(&self) -> bool {
        self.device.opened()
    }
}
