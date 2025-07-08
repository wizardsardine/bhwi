use bhwi_async::{Error as HWIError, HWI, HttpClient};
use bitcoin::{bip32::Fingerprint, Network};
use hidapi::HidApi;
use serialport::{available_ports, SerialPortType};
use async_trait::async_trait;

pub type Error = HWIError<(), ()>;

// Hardware wallet VID/PID constants (from bhwi-async transport modules)
const LEDGER_VID: u16 = 0x2c97;
const COLDCARD_VID: u16 = 0xd13e;
const JADE_DEVICE_IDS: [(u16, u16); 6] = [
    (0x10c4, 0xea60),
    (0x1a86, 0x55d4),
    (0x0403, 0x6001),
    (0x1a86, 0x7523),
    (0x303a, 0x4001),
    (0x303a, 0x1001),
];

pub async fn get_device_with_fingerprint(
    network: Network,
    fingerprint: Option<Fingerprint>,
) -> Result<Option<Box<dyn HWI<Error = Error>>>, Error> {
    for mut device in list(network).await? {
        if let Some(fingerprint) = fingerprint {
            if fingerprint == device.get_master_fingerprint().await? {
                return Ok(Some(device));
            }
        } else {
            return Ok(Some(device));
        }
    }
    Ok(None)
}

pub async fn list(_network: Network) -> Result<Vec<Box<dyn HWI<Error = Error> + Send>>, Error> {
    let devices: Vec<Box<dyn HWI<Error = Error> + Send>> = Vec::new();
    
    // For now, just enumerate what devices we find
    // TODO: Implement actual device creation and initialization
    // This requires proper transport layer implementation for each device type
    
    if let Ok(api) = HidApi::new() {
        // Enumerate HID devices
        for device_info in api.device_list() {
            let vid = device_info.vendor_id();
            let _pid = device_info.product_id();
            
            // Check for supported devices
            if vid == LEDGER_VID {
                // TODO: Create and initialize Ledger device
            }
            
            if vid == COLDCARD_VID {
                // TODO: Create and initialize Coldcard device
            }
        }
        
        // Enumerate serial devices for Jade
        if let Ok(ports) = available_ports() {
            for port in ports {
                if let SerialPortType::UsbPort(usb_info) = port.port_type {
                    if JADE_DEVICE_IDS.contains(&(usb_info.vid, usb_info.pid)) {
                        // TODO: Create and initialize Jade device
                    }
                }
            }
        }
    }
    
    Ok(devices)
}

pub struct SimpleHttpClient;

impl SimpleHttpClient {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait(?Send)]
impl HttpClient for SimpleHttpClient {
    type Error = std::io::Error;
    
    async fn request(&self, _url: &str, _request: &[u8]) -> Result<Vec<u8>, Self::Error> {
        // Mock implementation - you can implement the reqwest version yourself
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "HTTP client not implemented"))
    }
}
