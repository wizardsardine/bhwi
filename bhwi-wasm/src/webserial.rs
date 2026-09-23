use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bhwi_async::{
    Transport,
    transport::specter::{SpecterStream, SpecterStreamError},
};
use futures::future::{Either, select};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{ReadableStreamDefaultReader, SerialPort};

use crate::WasmError;

#[wasm_bindgen]
pub struct WebSerialDevice {
    port: SerialPort,
    on_close_cb: JsValue,
    pending_read: VecDeque<u8>,
}

#[wasm_bindgen]
impl WebSerialDevice {
    pub async fn get_webserial_device(
        baud_rate: u32,
        on_close_cb: JsValue,
    ) -> Option<WebSerialDevice> {
        let navigator = web_sys::window()?.navigator();
        let serial = navigator.serial();

        let options: JsValue = js_sys::Object::new().into();

        let port = match JsFuture::from(serial.request_port_with_options(&options.into())).await {
            Ok(port) => port.dyn_into::<SerialPort>().unwrap(),
            Err(_) => return None,
        };

        log::info!("found serial device");

        let port_options = js_sys::Object::new();
        js_sys::Reflect::set(&port_options, &"baudRate".into(), &JsValue::from(baud_rate)).unwrap();
        let port_options: JsValue = port_options.into();
        let open_future = JsFuture::from(port.open(&port_options.into()));
        if open_future.await.is_err() {
            return None;
        }

        // Add disconnect event listener
        let on_close_cb_rc = Rc::new(RefCell::new(on_close_cb.clone()));
        let on_disconnect_closure = {
            let on_close_cb_clone = on_close_cb_rc.clone();
            Closure::wrap(Box::new(move |_: web_sys::Event| {
                let on_close_cb_clone = on_close_cb_clone.borrow();
                if !on_close_cb_clone.is_undefined()
                    && !on_close_cb_clone.is_null()
                    && let Ok(cb) = <wasm_bindgen::JsValue as Clone>::clone(&on_close_cb_clone)
                        .dyn_into::<js_sys::Function>()
                {
                    cb.call0(&JsValue::NULL).unwrap();
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
            pending_read: VecDeque::new(),
        })
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
            let _ = close_future.await;

            // Check if `on_close_cb` is a valid function and call it
            if !on_close_cb.is_undefined()
                && !on_close_cb.is_null()
                && let Ok(cb) = on_close_cb.dyn_into::<js_sys::Function>()
            {
                let _ = cb.call0(&JsValue::NULL);
            }
        });
    }
}

#[async_trait(?Send)]
impl Transport for WebSerialDevice {
    type Error = WasmError;
    async fn exchange(&mut self, command: &[u8], _encrypted: bool) -> Result<Vec<u8>, Self::Error> {
        self.write(command).await?;
        Ok(self.read().await.unwrap())
    }
}

struct TimeoutGuard {
    future: JsFuture,
    handle: Option<i32>,
    _callback: Closure<dyn FnMut()>,
}

impl TimeoutGuard {
    fn clear(&mut self) {
        if let (Some(window), Some(handle)) = (web_sys::window(), self.handle.take()) {
            window.clear_timeout_with_handle(handle);
        }
    }
}

impl Drop for TimeoutGuard {
    fn drop(&mut self) {
        self.clear();
    }
}

fn timeout_future(timeout: Duration) -> TimeoutGuard {
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    let resolver = Rc::new(RefCell::new(None));
    let resolver_for_promise = resolver.clone();
    let resolver_for_callback = resolver_for_promise.clone();
    let promise = js_sys::Promise::new(&mut move |resolve, _| {
        *resolver_for_callback.borrow_mut() = Some(resolve.clone());
    });
    let callback = Closure::wrap(Box::new(move || {
        if let Some(resolve) = resolver.borrow().as_ref() {
            let _ = resolve.call0(&JsValue::UNDEFINED);
        }
    }) as Box<dyn FnMut()>);
    let handle = web_sys::window().and_then(|window| {
        window
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                callback.as_ref().unchecked_ref(),
                timeout_ms,
            )
            .ok()
    });
    if handle.is_none()
        && let Some(resolve) = resolver_for_promise.borrow().as_ref()
    {
        let _ = resolve.call0(&JsValue::UNDEFINED);
    }
    TimeoutGuard {
        future: JsFuture::from(promise),
        handle,
        _callback: callback,
    }
}

struct ReaderGuard {
    reader: ReadableStreamDefaultReader,
    active: bool,
}

impl ReaderGuard {
    fn new(reader: ReadableStreamDefaultReader) -> Self {
        Self {
            reader,
            active: true,
        }
    }

    fn release(&mut self) {
        if self.active {
            self.reader.release_lock();
            self.active = false;
        }
    }

    fn cancel_and_release(&mut self) {
        if self.active {
            // The cancellation begins synchronously. The returned Promise cannot be
            // awaited from Drop, but the port is discarded after a failed exchange.
            let _ = self.reader.cancel();
            self.reader.release_lock();
            self.active = false;
        }
    }
}

impl Drop for ReaderGuard {
    fn drop(&mut self) {
        self.cancel_and_release();
    }
}

fn copy_pending(pending: &mut VecDeque<u8>, buffer: &mut [u8]) -> usize {
    let length = usize::min(buffer.len(), pending.len());
    for output in &mut buffer[..length] {
        *output = pending.pop_front().expect("pending bytes are available");
    }
    length
}

fn copy_chunk(pending: &mut VecDeque<u8>, buffer: &mut [u8], chunk: &[u8]) -> usize {
    let length = usize::min(buffer.len(), chunk.len());
    buffer[..length].copy_from_slice(&chunk[..length]);
    pending.extend(&chunk[length..]);
    length
}

fn specter_stream_error(error: JsValue) -> SpecterStreamError<WasmError> {
    let message = error.as_string().unwrap_or_default().to_ascii_lowercase();
    if message.contains("abort") || message.contains("cancel") {
        SpecterStreamError::Cancelled
    } else if message.contains("disconnect") || message.contains("closed") {
        SpecterStreamError::Disconnected
    } else {
        SpecterStreamError::Io(error.into())
    }
}

#[async_trait(?Send)]
impl SpecterStream for WebSerialDevice {
    type Error = WasmError;

    async fn write_all(&mut self, request: &[u8]) -> Result<(), SpecterStreamError<Self::Error>> {
        self.write(request).await.map_err(specter_stream_error)
    }

    async fn read_until(
        &mut self,
        buffer: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, SpecterStreamError<Self::Error>> {
        if !self.pending_read.is_empty() {
            return Ok(copy_pending(&mut self.pending_read, buffer));
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(SpecterStreamError::Timeout)?;
        let reader = self
            .port
            .readable()
            .get_reader()
            .dyn_into::<ReadableStreamDefaultReader>()
            .map_err(|error| SpecterStreamError::Io(JsValue::from(error).into()))?;

        let mut reader = ReaderGuard::new(reader);
        let mut timeout = timeout_future(remaining);
        let result = match select(JsFuture::from(reader.reader.read()), &mut timeout.future).await {
            Either::Left((result, _)) => Some(result),
            Either::Right((_, _)) => None,
        };
        timeout.clear();
        match result {
            Some(Ok(chunk)) => {
                reader.release();
                if js_sys::Reflect::get(&chunk, &JsValue::from_str("done"))
                    .ok()
                    .and_then(|done| done.as_bool())
                    .unwrap_or(false)
                {
                    return Err(SpecterStreamError::Disconnected);
                }
                let value = js_sys::Reflect::get(&chunk, &JsValue::from_str("value"))
                    .ok()
                    .and_then(|value| value.dyn_into::<Uint8Array>().ok())
                    .ok_or(SpecterStreamError::Disconnected)?;
                let mut bytes = vec![0; value.length() as usize];
                value.copy_to(&mut bytes);
                Ok(copy_chunk(&mut self.pending_read, buffer, &bytes))
            }
            Some(Err(error)) => {
                reader.release();
                Err(specter_stream_error(error))
            }
            None => {
                // Cancelling makes any delayed reply unusable, matching the poisoned
                // Specter transport state after an incomplete exchange.
                reader.cancel_and_release();
                Err(SpecterStreamError::Timeout)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{copy_chunk, copy_pending};
    use std::collections::VecDeque;

    #[test]
    fn preserves_bytes_after_a_transport_sized_read() {
        let input: Vec<u8> = (0..(16 * 1024 + 37))
            .map(|index| (index % 251) as u8)
            .collect();
        let mut pending = VecDeque::new();
        let mut first = [0; 16 * 1024];
        let mut second = [0; 37];

        assert_eq!(copy_chunk(&mut pending, &mut first, &input), first.len());
        assert_eq!(pending.len(), second.len());
        assert_eq!(copy_pending(&mut pending, &mut second), second.len());
        assert!(pending.is_empty());
        assert_eq!([first.as_slice(), second.as_slice()].concat(), input);
    }
}
