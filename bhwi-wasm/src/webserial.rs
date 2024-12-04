use std::cell::RefCell;
use std::rc::Rc;

use async_trait::async_trait;
use bhwi_async::Transport;
use futures::future::{select, Either};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{ReadableStreamDefaultReader, SerialOptions, SerialPort, SerialPortRequestOptions};

#[wasm_bindgen]
pub struct WebSerialDevice {
    port: SerialPort,
    on_close_cb: JsValue,
}

#[wasm_bindgen]
impl WebSerialDevice {
    pub async fn get_webserial_device(
        baud_rate: u32,
        on_close_cb: JsValue,
    ) -> Option<WebSerialDevice> {
        let navigator = web_sys::window()?.navigator();
        let serial = navigator.serial();

        let options = SerialPortRequestOptions::new();

        let port = match JsFuture::from(serial.request_port_with_options(&options)).await {
            Ok(port) => port.dyn_into::<SerialPort>().unwrap(),
            Err(_) => return None,
        };

        log::info!("found serial device");

        let port_options = SerialOptions::new(baud_rate);
        let open_future = JsFuture::from(port.open(&port_options));
        if open_future.await.is_err() {
            return None;
        }

        // Add disconnect event listener
        let on_close_cb_rc = Rc::new(RefCell::new(on_close_cb.clone()));
        let on_disconnect_closure = {
            let on_close_cb_clone = on_close_cb_rc.clone();
            Closure::wrap(Box::new(move |_: web_sys::Event| {
                let on_close_cb_clone = on_close_cb_clone.borrow();
                if !on_close_cb_clone.is_undefined() && !on_close_cb_clone.is_null() {
                    if let Ok(cb) = <wasm_bindgen::JsValue as Clone>::clone(&on_close_cb_clone)
                        .dyn_into::<js_sys::Function>()
                    {
                        cb.call0(&JsValue::NULL).unwrap();
                    }
                }
            }) as Box<dyn FnMut(_)>)
        };

        serial
            .add_event_listener_with_callback(
                "disconnect",
                on_disconnect_closure.as_ref().unchecked_ref(),
            )
            .unwrap();
        on_disconnect_closure.forget();

        // Return the WebSerialDevice
        Some(Self { port, on_close_cb })
    }

    #[wasm_bindgen]
    pub async fn read(&self) -> Option<Vec<u8>> {
        let reader = self.port.readable().get_reader();
        let reader = reader
            .dyn_into::<ReadableStreamDefaultReader>()
            .expect("Failed to cast to ReadableStreamDefaultReader");
        // Function to create a timeout future
        fn create_timeout_future(timeout_ms: i32) -> JsFuture {
            let promise = js_sys::Promise::new(&mut |resolve, _| {
                let closure = Closure::wrap(Box::new(move || {
                    resolve.call0(&JsValue::UNDEFINED).unwrap();
                }) as Box<dyn FnMut()>);

                web_sys::window()
                    .unwrap()
                    .set_timeout_with_callback_and_timeout_and_arguments_0(
                        closure.as_ref().unchecked_ref(),
                        timeout_ms,
                    )
                    .unwrap();

                closure.forget(); // Avoid dropping the closure prematurely
            });
            JsFuture::from(promise)
        }

        let mut res = Vec::new();

        // Perform the first read without a timeout for the unlock;
        match JsFuture::from(reader.read()).await {
            Ok(chunk) => {
                let chunk = js_sys::Reflect::get(&chunk, &JsValue::from_str("value"))
                    .ok()
                    .and_then(|value| value.dyn_into::<Uint8Array>().ok());

                if let Some(uint8_array) = chunk {
                    let mut vec = vec![0u8; uint8_array.length() as usize];
                    uint8_array.copy_to(&mut vec[..]);

                    if !vec.is_empty() {
                        res.append(&mut vec);
                    }
                } else {
                    log::warn!("No valid chunk received on first read");
                    reader.release_lock();
                    return Some(res);
                }
            }
            Err(e) => {
                log::error!("Error while reading on first attempt: {:?}", e);
                reader.release_lock();
                return None;
            }
        }

        loop {
            match select(
                wasm_bindgen_futures::JsFuture::from(reader.read()),
                create_timeout_future(500),
            )
            .await
            {
                Either::Left((read_result, _)) => match read_result {
                    Ok(chunk) => {
                        let chunk = js_sys::Reflect::get(&chunk, &JsValue::from_str("value"))
                            .ok()
                            .and_then(|value| value.dyn_into::<Uint8Array>().ok());

                        if let Some(uint8_array) = chunk {
                            let mut vec = vec![0u8; uint8_array.length() as usize];
                            uint8_array.copy_to(&mut vec[..]);

                            if !vec.is_empty() {
                                res.append(&mut vec);
                            }
                        } else {
                            log::warn!("No valid chunk received");
                            break;
                        }
                    }
                    Err(e) => {
                        log::error!("Error while reading: {:?}", e);
                        break;
                    }
                },
                Either::Right((_, _)) => {
                    if !res.is_empty() {
                        break;
                    }
                }
            }
        }
        reader.release_lock();
        Some(res)
    }

    #[wasm_bindgen]
    pub async fn write(&self, data: &[u8]) -> Result<(), JsValue> {
        let writable = self.port.writable();
        let writer = writable.get_writer().unwrap();
        let uint8_array = Uint8Array::from(data);

        JsFuture::from(writer.write_with_chunk(&uint8_array.into())).await?;
        writer.release_lock();
        Ok(())
    }

    #[wasm_bindgen]
    pub fn close(&mut self) {
        let close_future = JsFuture::from(self.port.close());
        let on_close_cb = self.on_close_cb.clone();

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
}

#[async_trait(?Send)]
impl Transport for WebSerialDevice {
    type Error = JsValue;
    async fn exchange(&self, command: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.write(command).await?;
        Ok(self.read().await.unwrap())
    }
}
