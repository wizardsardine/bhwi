use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::StreamExt;
use js_sys::Uint8Array;
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{HidDevice, HidDeviceRequestOptions};

#[wasm_bindgen]
struct WebHidDevice {
    device: HidDevice,
    on_close_cb: JsValue,
    msg_queue: UnboundedReceiver<Uint8Array>,
    write_tx: UnboundedSender<Uint8Array>,
}

#[wasm_bindgen]
impl WebHidDevice {
    #[wasm_bindgen]
    pub async fn get_webhid_device(
        name: &str,
        vendor_id: u16,
        product_id: u16,
        on_close_cb: JsValue,
    ) -> Option<WebHidDevice> {
        let navigator = web_sys::window()?.navigator();
        let hid = navigator.hid();

        let filters = js_sys::Array::new();
        let filter = js_sys::Object::new();
        js_sys::Reflect::set(&filter, &"vendorId".into(), &JsValue::from(vendor_id)).unwrap();
        js_sys::Reflect::set(&filter, &"productId".into(), &JsValue::from(product_id)).unwrap();
        filters.push(&filter.into());

        let devices = match JsFuture::from(
            hid.request_device(&HidDeviceRequestOptions::new(&filters.into())),
        )
        .await
        {
            Ok(devices) => devices.dyn_into::<js_sys::Array>().unwrap(),
            Err(_) => return None,
        };

        if devices.length() == 0 {
            return None;
        }

        let device = devices.get(0).dyn_into::<HidDevice>().unwrap();

        log::info!("found hid device: {}", device.product_name());
        if !device.product_name().contains(name) {
            return None;
        }

        // Open the device
        let open_future = JsFuture::from(device.open());
        if open_future.await.is_err() {
            return None;
        }

        let (tx, rx) = unbounded();

        let device_rc = Rc::new(RefCell::new(device.clone()));

        let on_input_report_closure = {
            let tx = tx.clone();
            Closure::wrap(Box::new(move |event: web_sys::HidInputReportEvent| {
                let data = Uint8Array::new(&event.data());
                tx.unbounded_send(data).unwrap();
            }) as Box<dyn FnMut(_)>)
        };

        device
            .add_event_listener_with_callback(
                "inputreport",
                on_input_report_closure.as_ref().unchecked_ref(),
            )
            .unwrap();
        on_input_report_closure.forget();

        // Add disconnect event listener
        let on_close_cb_rc = Rc::new(RefCell::new(on_close_cb.clone()));
        let on_disconnect_closure = {
            let device_clone = device_rc.clone();
            let on_close_cb_clone = on_close_cb_rc.clone();
            Closure::wrap(Box::new(move |event: web_sys::HidConnectionEvent| {
                let disconnected_device = event.device();
                if disconnected_device.vendor_id() == device_clone.borrow().vendor_id()
                    && disconnected_device.product_id() == device_clone.borrow().product_id()
                {
                    let on_close_cb_clone = on_close_cb_clone.borrow();
                    if !on_close_cb_clone.is_undefined() && !on_close_cb_clone.is_null() {
                        if let Ok(cb) = <wasm_bindgen::JsValue as Clone>::clone(&on_close_cb_clone)
                            .dyn_into::<js_sys::Function>()
                        {
                            cb.call0(&JsValue::NULL).unwrap();
                        }
                    }
                }
            }) as Box<dyn FnMut(_)>)
        };

        hid.add_event_listener_with_callback(
            "disconnect",
            on_disconnect_closure.as_ref().unchecked_ref(),
        )
        .unwrap();
        on_disconnect_closure.forget();

        // Return the WebHidDevice
        Some(Self {
            device,
            on_close_cb,
            msg_queue: rx,
            write_tx: tx,
        })
    }

    #[wasm_bindgen]
    pub async fn read(&mut self) -> Option<Uint8Array> {
        self.msg_queue.next().await
    }

    #[wasm_bindgen]
    pub async fn write(&self, data: &mut [u8]) {
        if self.device.opened() {
            let promise = JsFuture::from(self.device.send_report_with_u8_array(0, data));
            if promise.await.is_err() {
                log::error!("Failed to send report");
            }
        } else {
            log::error!("attempted write to a closed HID connection");
        }
    }

    #[wasm_bindgen]
    pub fn close(&mut self) {
        let close_future = JsFuture::from(self.device.close());
        let on_close_cb = self.on_close_cb.clone(); // Clone the JsValue for use in the async block

        wasm_bindgen_futures::spawn_local(async move {
            close_future.await.unwrap();

            // Check if `on_close_cb` is a valid function and call it
            if !on_close_cb.is_undefined() && !on_close_cb.is_null() {
                if let Ok(cb) = on_close_cb.dyn_into::<js_sys::Function>() {
                    cb.call0(&JsValue::NULL).unwrap();
                }
            }
        });
    }

    #[wasm_bindgen]
    pub fn valid(&self) -> bool {
        self.device.opened()
    }
}
