pub mod ledger;
pub mod webhid;

use log::Level;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn initialize_logging(level: &str) {
    console_error_panic_hook::set_once();
    // Attempt to parse the log level from the string, default to Info if invalid
    let log_level = Level::from_str(level).unwrap_or(Level::Info);

    console_log::init_with_level(log_level).expect("error initializing log");
}
