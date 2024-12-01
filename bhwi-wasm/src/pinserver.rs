use async_trait::async_trait;
use bhwi_async::HttpClient;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestInit, RequestMode, Response};

pub struct PinServer;

#[async_trait(?Send)]
impl HttpClient for PinServer {
    type Error = JsValue;
    async fn request(&self, url: &str, body: &[u8]) -> Result<Vec<u8>, Self::Error> {
        // Set up request parameters
        let opts = RequestInit::new();
        opts.set_method("POST");
        opts.set_mode(RequestMode::Cors); // Allows cross-origin requests
        opts.set_body(&js_sys::Uint8Array::from(body).into());

        // Create headers and set the Content-Type
        let headers = Headers::new()?;
        headers.set("Content-Type", "application/octet-stream")?;
        opts.set_headers(&headers);

        // Create a Request object
        let request = Request::new_with_str_and_init(url, &opts)?;

        // Use the window's fetch API
        let window = web_sys::window().unwrap();
        let fetch = window.fetch_with_request(&request);

        // Wait for the response
        let resp_value = JsFuture::from(fetch).await?;
        let resp: Response = resp_value.dyn_into().unwrap();

        // Ensure the response is OK
        if !resp.ok() {
            return Err(JsValue::from_str("Network error or non-OK response"));
        }

        // Parse the response as an array buffer and convert to Vec<u8>
        let buffer = JsFuture::from(resp.array_buffer()?).await?;
        let array = js_sys::Uint8Array::new(&buffer);
        let mut vec = vec![0; array.length() as usize];
        array.copy_to(&mut vec[..]);

        Ok(vec)
    }
}
