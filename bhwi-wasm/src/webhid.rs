//! Browser WebHID connections and queued input reports.

use futures::StreamExt;
use futures::channel::mpsc::{UnboundedReceiver, unbounded};
use js_sys::Uint8Array;
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::HidDevice;

/// An open WebHID connection with queued input reports and a close callback.
///
/// Its [`Channel`](bhwi_async::transport::Channel) implementation requires a
/// receive buffer matching the input report length. It reports sends as
/// successful even when [`write`](Self::write) logs a failure.
#[wasm_bindgen]
pub struct WebHidDevice {
    device: HidDevice,
    on_close_cb: JsValue,
    msg_queue: UnboundedReceiver<Vec<u8>>,
}

impl WebHidDevice {
    /// Requests permission for a matching HID device and opens the first selection.
    ///
    /// Requires a browser `Window` with WebHID support and permission to show the
    /// device chooser, normally from a user gesture in a secure context. The
    /// optional `name` must be a substring of the selected device's product name.
    /// Returns `None` without a window, on cancellation, on a name mismatch, or
    /// when opening fails. If `on_close_cb` is a function, disconnect events for
    /// the same vendor and product IDs call it with no arguments.
    ///
    /// # Panics
    ///
    /// Panics if browser values have unexpected types or event listeners cannot
    /// be installed. A throwing close callback also causes a panic.
    pub async fn get_webhid_device(
        name: Option<&str>,
        vendor_id: u16,
        product_id: Option<u16>,
        usage_page: Option<u16>,
        on_close_cb: JsValue,
    ) -> Option<WebHidDevice> {
        let navigator = web_sys::window()?.navigator();
        let hid = navigator.hid();

        let filters = js_sys::Array::new();
        let filter = js_sys::Object::new();
        js_sys::Reflect::set(&filter, &"vendorId".into(), &JsValue::from(vendor_id)).unwrap();
        if let Some(product_id) = product_id {
            js_sys::Reflect::set(&filter, &"productId".into(), &JsValue::from(product_id)).unwrap();
        }
        if let Some(usage_page) = usage_page {
            js_sys::Reflect::set(&filter, &"usagePage".into(), &JsValue::from(usage_page)).unwrap();
        }
        filters.push(&filter.into());

        let options = js_sys::Object::new();
        js_sys::Reflect::set(&options, &"filters".into(), &filters.into()).unwrap();
        let options: JsValue = options.into();
        let devices = match JsFuture::from(hid.request_device(&options.into())).await {
            Ok(devices) => devices.dyn_into::<js_sys::Array>().unwrap(),
            Err(_) => return None,
        };

        if devices.length() == 0 {
            return None;
        }

        let device = devices.get(0).dyn_into::<HidDevice>().unwrap();

        log::info!("found hid device: {}", device.product_name());
        if let Some(name) = name
            && !device.product_name().contains(name)
        {
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
                let data = event.data();
                let length = data.byte_length();
                let uint8_array = Uint8Array::new(&data.buffer());
                let mut vec = vec![0u8; length];
                uint8_array.copy_to(&mut vec[..]);
                tx.unbounded_send(vec).unwrap();
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
        })
    }
}

#[wasm_bindgen]
impl WebHidDevice {
    /// Waits for the next input report, returning `None` when the queue ends.
    ///
    /// No read timeout is imposed.
    // TODO: return error and maybe remove wasm_bindgen
    #[wasm_bindgen]
    pub async fn read(&mut self) -> Option<Vec<u8>> {
        self.msg_queue.next().await
    }

    /// Sends HID report zero, logging asynchronous failures or a closed connection.
    ///
    /// Failures are not returned to the caller.
    ///
    /// # Panics
    ///
    /// Panics if the browser rejects the send call synchronously.
    // TODO: return error and maybe remove wasm_bindgen
    #[wasm_bindgen]
    pub async fn write(&self, data: &[u8]) {
        if self.device.opened() {
            let uint8_array = js_sys::Uint8Array::from(data);
            let promise = JsFuture::from(
                self.device
                    .send_report_with_u8_array(0, &uint8_array)
                    .unwrap(),
            );
            if let Err(e) = promise.await {
                log::error!("Failed to send report: {:?}", e);
            }
        } else {
            log::error!("attempted write to a closed HID connection");
        }
    }

    /// Schedules closing the connection and calling a function-valued close callback.
    ///
    /// Returns before the browser finishes closing.
    ///
    /// # Panics
    ///
    /// The scheduled task panics if closing fails or the callback throws.
    #[wasm_bindgen]
    pub fn close(&mut self) {
        let close_future = JsFuture::from(self.device.close());
        let on_close_cb = self.on_close_cb.clone(); // Clone the JsValue for use in the async block

        wasm_bindgen_futures::spawn_local(async move {
            close_future.await.unwrap();

            // Check if `on_close_cb` is a valid function and call it
            if !on_close_cb.is_undefined()
                && !on_close_cb.is_null()
                && let Ok(cb) = on_close_cb.dyn_into::<js_sys::Function>()
            {
                cb.call0(&JsValue::NULL).unwrap();
            }
        });
    }

    /// Returns whether the browser currently reports the connection as open.
    #[wasm_bindgen]
    pub fn valid(&self) -> bool {
        self.device.opened()
    }
}
