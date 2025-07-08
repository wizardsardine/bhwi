use bhwi_async::{Error as HWIError, HttpClient};
use bitcoin::{bip32::Fingerprint, Network};
use hidapi::HidApi;
use serialport::{available_ports, SerialPortType};
use async_trait::async_trait;
use std::fmt;

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
) -> Result<Option<DeviceInfo>, Error> {
    let devices = list(network).await?;
    if let Some(target_fingerprint) = fingerprint {
        // For now, just return the first matching device type
        // In a full implementation, we'd connect and check fingerprints
        // For now, return None since we don't connect to devices to check fingerprints
        Ok(None)
    } else {
        Ok(devices.into_iter().next())
    }
}

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub device_type: DeviceType,
    pub path: String,
    pub vid: Option<u16>,
    pub pid: Option<u16>,
    pub fingerprint: Option<Fingerprint>,
}

#[derive(Debug, Clone)]
pub enum DeviceType {
    Ledger,
    Coldcard,
    Jade,
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeviceType::Ledger => write!(f, "Ledger"),
            DeviceType::Coldcard => write!(f, "Coldcard"),
            DeviceType::Jade => write!(f, "Jade"),
        }
    }
}

pub async fn list(_network: Network) -> Result<Vec<DeviceInfo>, Error> {
    let mut devices = Vec::new();
    
    if let Ok(api) = HidApi::new() {
        // Enumerate HID devices
        for device_info in api.device_list() {
            let vid = device_info.vendor_id();
            let pid = device_info.product_id();
            
            // Check for Ledger devices
            if vid == LEDGER_VID {
                devices.push(DeviceInfo {
                    device_type: DeviceType::Ledger,
                    path: device_info.path().to_string_lossy().to_string(),
                    vid: Some(vid),
                    pid: Some(pid),
                    fingerprint: None, // Would need to connect to get fingerprint
                });
            }
            
            // Check for Coldcard devices  
            if vid == COLDCARD_VID {
                devices.push(DeviceInfo {
                    device_type: DeviceType::Coldcard,
                    path: device_info.path().to_string_lossy().to_string(),
                    vid: Some(vid),
                    pid: Some(pid),
                    fingerprint: None, // Would need to connect to get fingerprint
                });
            }
        }
        
        // Enumerate serial devices for Jade
        if let Ok(ports) = available_ports() {
            for port in ports {
                if let SerialPortType::UsbPort(usb_info) = port.port_type {
                    if JADE_DEVICE_IDS.contains(&(usb_info.vid, usb_info.pid)) {
                        devices.push(DeviceInfo {
                            device_type: DeviceType::Jade,
                            path: port.port_name.clone(),
                            vid: Some(usb_info.vid),
                            pid: Some(usb_info.pid),
                            fingerprint: None, // Would need to connect to get fingerprint
                        });
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
