use bhwi_async::{
    Error as HWIError, HWI, HttpClient
};
use bitcoin::{bip32::Fingerprint, Network};
use hidapi::HidApi;
use serialport::{available_ports, SerialPortType};
use async_trait::async_trait;

pub type Error = HWIError<std::io::Error, std::io::Error>;

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

// Device info structure for enumeration
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub device_type: String,
    pub path: String,
    pub vid: Option<u16>,
    pub pid: Option<u16>,
}

// Mock HWI implementation for device enumeration
pub struct MockDevice {
    pub info: DeviceInfo,
}

#[async_trait(?Send)]
impl HWI for MockDevice {
    type Error = Error;
    
    async fn unlock(&mut self, _network: Network) -> Result<(), Self::Error> {
        Err(HWIError::HttpClient(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Mock device - not implemented"
        )))
    }
    
    async fn get_master_fingerprint(&mut self) -> Result<Fingerprint, Self::Error> {
        // For demo purposes, generate a mock fingerprint based on device type
        let fingerprint_bytes = match self.info.device_type.as_str() {
            "Ledger" => [0x12, 0x34, 0x56, 0x78],
            "Coldcard" => [0xAB, 0xCD, 0xEF, 0x01],
            "Jade" => [0x98, 0x76, 0x54, 0x32],
            _ => [0x00, 0x00, 0x00, 0x00],
        };
        Ok(Fingerprint::from(fingerprint_bytes))
    }
    
    async fn get_extended_pubkey(
        &mut self,
        _path: bitcoin::bip32::DerivationPath,
        _display: bool,
    ) -> Result<bitcoin::bip32::Xpub, Self::Error> {
        Err(HWIError::HttpClient(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Mock device - not implemented"
        )))
    }
}

pub async fn list(_network: Network) -> Result<Vec<Box<dyn HWI<Error = Error>>>, Error> {
    let mut devices: Vec<Box<dyn HWI<Error = Error>>> = Vec::new();
    
    if let Ok(api) = HidApi::new() {
        // Enumerate HID devices
        for device_info in api.device_list() {
            let vid = device_info.vendor_id();
            let pid = device_info.product_id();
            
            // Check for Ledger devices
            if vid == LEDGER_VID {
                let device_info = DeviceInfo {
                    device_type: "Ledger".to_string(),
                    path: device_info.path().to_string_lossy().to_string(),
                    vid: Some(vid),
                    pid: Some(pid),
                };
                let mock_device = MockDevice { info: device_info };
                devices.push(Box::new(mock_device));
            }
            
            // Check for Coldcard devices  
            if vid == COLDCARD_VID {
                let device_info = DeviceInfo {
                    device_type: "Coldcard".to_string(),
                    path: device_info.path().to_string_lossy().to_string(),
                    vid: Some(vid),
                    pid: Some(pid),
                };
                let mock_device = MockDevice { info: device_info };
                devices.push(Box::new(mock_device));
            }
        }
        
        // Enumerate serial devices for Jade
        if let Ok(ports) = available_ports() {
            for port in ports {
                if let SerialPortType::UsbPort(usb_info) = port.port_type {
                    if JADE_DEVICE_IDS.contains(&(usb_info.vid, usb_info.pid)) {
                        let device_info = DeviceInfo {
                            device_type: "Jade".to_string(),
                            path: port.port_name.clone(),
                            vid: Some(usb_info.vid),
                            pid: Some(usb_info.pid),
                        };
                        let mock_device = MockDevice { info: device_info };
                        devices.push(Box::new(mock_device));
                    }
                }
            }
        }
    }
    
    Ok(devices)
}

pub async fn get_device_with_fingerprint(
    network: Network,
    fingerprint: Option<Fingerprint>,
) -> Result<Option<Box<dyn HWI<Error = Error>>>, Error> {
    for mut device in list(network).await? {
        if let Some(target_fingerprint) = fingerprint {
            match device.get_master_fingerprint().await {
                Ok(device_fingerprint) => {
                    if device_fingerprint == target_fingerprint {
                        return Ok(Some(device));
                    }
                }
                Err(_) => continue, // Skip devices that can't be accessed
            }
        } else {
            return Ok(Some(device));
        }
    }
    Ok(None)
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