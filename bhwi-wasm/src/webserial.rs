use std::cell::RefCell;
use std::rc::Rc;

use async_trait::async_trait;
use bhwi_async::Transport;
use futures::channel::mpsc::{unbounded, UnboundedReceiver};
use futures::{lock::Mutex, StreamExt};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{ReadableStreamDefaultReader, SerialOptions, SerialPort, SerialPortRequestOptions};

#[wasm_bindgen]
pub struct WebSerialDevice {
    port: SerialPort,
    on_close_cb: JsValue,
    msg_queue: Mutex<UnboundedReceiver<Vec<u8>>>,
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

        let (tx, rx) = unbounded();
        let port_rc = Rc::new(RefCell::new(port.clone()));

        // Continuously read data from the serial port
        wasm_bindgen_futures::spawn_local({
            let tx = tx.clone();
            let port = port_rc.clone();
            async move {
                let reader = port.borrow().readable().get_reader();
                let reader = reader
                    .dyn_into::<ReadableStreamDefaultReader>()
                    .expect("Failed to cast to ReadableStreamDefaultReader");
                loop {
                    // Attempt to read data
                    match wasm_bindgen_futures::JsFuture::from(reader.read()).await {
                        Ok(data) => {
                            // Convert the data to Uint8Array and then to Vec<u8>
                            let uint8_array = Uint8Array::new(&data);
                            let mut vec = vec![0u8; uint8_array.length() as usize];
                            uint8_array.copy_to(&mut vec[..]);

                            // Send the data through the channel
                            if tx.unbounded_send(vec).is_err() {
                                log::error!("Failed to send data to the receiver.");
                                break;
                            }
                        }
                        Err(e) => {
                            log::error!("Error while reading: {:?}", e);
                            break;
                        }
                    }
                }
                reader.release_lock();
            }
        });

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
        Some(Self {
            port,
            on_close_cb,
            msg_queue: Mutex::new(rx),
        })
    }

    #[wasm_bindgen]
    pub async fn read(&self) -> Option<Vec<u8>> {
        let mut queue = self.msg_queue.lock().await;
        queue.next().await
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
