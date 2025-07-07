use bhwi_async::{Error as HWIError, HWI};
use bitcoin::{bip32::Fingerprint, Network};

pub type Error = HWIError<(), ()>;

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
    Ok(Vec::new())
}
