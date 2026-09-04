use std::{
    cell::Cell,
    io::{self, IsTerminal, Write},
    rc::Rc,
};

use anyhow::Result;
use async_hid::{Device as HidDevice, HidBackend};
use async_trait::async_trait;
use bhwi::{
    common::{self, HostRequest, HostResponse, PinMatrixRequestKind},
    keepkey::{
        DEFAULT_KEEPKEY_EMULATOR, KEEPKEY_HID_PID, KEEPKEY_HID_USAGE_PAGE, KEEPKEY_VID,
        KEEPKEY_WEBUSB_PID,
    },
};
use bhwi_async::{HostInteraction, KeepKey, transport::trezor::TrezorTransport};
use futures::stream::{StreamExt, TryStreamExt};

use crate::{
    Device, DeviceEnumerator, DeviceType,
    config::DeviceSelector,
    hid::HidChannel,
    hwi::PIN_MATRIX_DESCRIPTION,
    trezor::{
        EMULATOR_PROBE_TIMEOUT, emulator::EmulatorClient, emulator_socket, hid_path, webusb_path,
    },
    webusb::WebUsbChannel,
};

pub type KeepKeyHidDevice = KeepKey<TrezorTransport<HidChannel>>;
pub type KeepKeyWebUsbDevice = KeepKey<TrezorTransport<WebUsbChannel>>;
pub type KeepKeyEmulatorDevice = KeepKey<TrezorTransport<EmulatorClient>>;

pub struct KeepKeyDevice;

impl KeepKeyDevice {
    async fn hid_device(selector: &DeviceSelector, dev: HidDevice) -> Result<Device> {
        let path = hid_path(&dev);
        let opened = dev.open().await?;
        Device::new(
            "KeepKey",
            DeviceType::KeepKey,
            path,
            "keepkey",
            Box::new(
                KeepKeyHidDevice::new(TrezorTransport::new(HidChannel::new(opened)))
                    .with_network(selector.network)
                    .with_passphrase(selector.passphrase.clone())
                    .with_host_interaction(Box::new(CliHostInteraction)),
            ),
            false,
        )
        .await
    }

    async fn webusb_device(selector: &DeviceSelector, info: &nusb::DeviceInfo) -> Result<Device> {
        let channel = WebUsbChannel::open(info).await?;
        Device::new(
            "KeepKey",
            DeviceType::KeepKey,
            webusb_path(info),
            "keepkey",
            Box::new(
                KeepKeyWebUsbDevice::new(TrezorTransport::new(channel))
                    .with_network(selector.network)
                    .with_passphrase(selector.passphrase.clone())
                    .with_host_interaction(Box::new(CliHostInteraction)),
            ),
            false,
        )
        .await
    }

    async fn emulator_device(selector: &DeviceSelector, client: EmulatorClient) -> Result<Device> {
        Device::new(
            "KeepKey Emulator",
            DeviceType::KeepKey,
            DEFAULT_KEEPKEY_EMULATOR,
            "keepkey_simulator",
            Box::new(
                KeepKeyEmulatorDevice::new(TrezorTransport::new(client))
                    .with_network(selector.network)
                    .with_passphrase(selector.passphrase.clone())
                    .with_host_interaction(Box::new(CliHostInteraction)),
            ),
            true,
        )
        .await
    }
}

#[async_trait(?Send)]
impl DeviceEnumerator for KeepKeyDevice {
    async fn enumerate(selector: &DeviceSelector) -> Result<Vec<Device>> {
        if selector.include_emulators
            && selector.device_path.is_some()
            && matches_emulator(selector)
        {
            return Ok(
                if let Ok(client) = EmulatorClient::new(DEFAULT_KEEPKEY_EMULATOR).await
                    && client.ping(EMULATOR_PROBE_TIMEOUT).await
                {
                    vec![Self::emulator_device(selector, client).await?]
                } else {
                    Vec::new()
                },
            );
        }

        let selected_path = selector.device_path.as_deref();
        let mut devices = Vec::new();

        if uses_backend(selected_path, "hid:") {
            match HidBackend::default().enumerate().await {
                Ok(hid) => {
                    let found = hid
                        .map(Ok)
                        .try_filter_map(|dev| async move {
                            let path = hid_path(&dev);
                            if selector.matches(DeviceType::KeepKey, &path)
                                && dev.vendor_id == KEEPKEY_VID
                                && dev.product_id == KEEPKEY_HID_PID
                                && dev.usage_page == KEEPKEY_HID_USAGE_PAGE
                            {
                                candidate_result(
                                    selected_path,
                                    &path,
                                    Self::hid_device(selector, dev).await,
                                )
                            } else {
                                Ok(None)
                            }
                        })
                        .try_collect::<Vec<_>>()
                        .await?;
                    devices.extend(found);
                }
                Err(err) if selected_path.is_some() => return Err(err.into()),
                Err(_) => {}
            }
        }

        if uses_backend(selected_path, "webusb:") {
            match nusb::list_devices().await {
                Ok(usb) => {
                    for info in usb.filter(|info| {
                        info.vendor_id() == KEEPKEY_VID && info.product_id() == KEEPKEY_WEBUSB_PID
                    }) {
                        let path = webusb_path(&info);
                        if !selector.matches(DeviceType::KeepKey, &path) {
                            continue;
                        }
                        if let Some(device) = candidate_result(
                            selected_path,
                            &path,
                            Self::webusb_device(selector, &info).await,
                        )? {
                            devices.push(device);
                        }
                    }
                }
                Err(err) if selected_path.is_some() => return Err(err.into()),
                Err(_) => {}
            }
        }

        if selector.include_emulators
            && matches_emulator(selector)
            && let Ok(client) = EmulatorClient::new(DEFAULT_KEEPKEY_EMULATOR).await
            && client.ping(EMULATOR_PROBE_TIMEOUT).await
        {
            devices.push(Self::emulator_device(selector, client).await?);
        }

        Ok(devices)
    }
}

fn uses_backend(selected_path: Option<&str>, prefix: &str) -> bool {
    selected_path.is_none_or(|path| path.starts_with(prefix))
}

fn candidate_result<T>(
    selected_path: Option<&str>,
    path: &str,
    result: Result<T>,
) -> Result<Option<T>> {
    match result {
        Ok(device) => Ok(Some(device)),
        Err(err) if selected_path.is_some() => Err(err),
        Err(err) => {
            eprintln!("Warning: skipping KeepKey at {path}: {err}");
            Ok(None)
        }
    }
}

fn matches_emulator(selector: &DeviceSelector) -> bool {
    selector.matches(DeviceType::KeepKey, DEFAULT_KEEPKEY_EMULATOR)
        || selector.matches(
            DeviceType::KeepKey,
            emulator_socket(DEFAULT_KEEPKEY_EMULATOR),
        )
}

struct CliHostInteraction;

#[async_trait(?Send)]
impl HostInteraction for CliHostInteraction {
    async fn respond(&mut self, request: &HostRequest) -> Result<HostResponse, common::Error> {
        let terminal = io::stdin().is_terminal();
        read_host_response(
            request,
            || {
                if terminal {
                    read_hidden_line()
                } else {
                    let mut response = String::new();
                    let read = io::stdin().read_line(&mut response)?;
                    if read == 0 {
                        Ok(None)
                    } else {
                        response.truncate(response.trim_end_matches(['\r', '\n']).len());
                        Ok(Some(response))
                    }
                }
            },
            |prompt| {
                eprint!("{prompt}");

                io::stderr().flush()
            },
        )
    }
}
struct HiddenOutput {
    line_completed: Rc<Cell<bool>>,
}

impl Write for HiddenOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.contains(&b'\n') {
            self.line_completed.set(true);
        }
        io::stderr().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stderr().flush()
    }
}

fn read_hidden_line() -> io::Result<Option<String>> {
    let line_completed = Rc::new(Cell::new(false));
    let response = rpassword::read_password_with_config(
        rpassword::ConfigBuilder::new()
            .output_writer(HiddenOutput {
                line_completed: Rc::clone(&line_completed),
            })
            .build(),
    )?;
    Ok(completed_hidden_line(response, line_completed.get()))
}

fn completed_hidden_line(response: String, line_completed: bool) -> Option<String> {
    line_completed.then_some(response)
}

fn read_host_response(
    request: &HostRequest,
    mut read: impl FnMut() -> io::Result<Option<String>>,
    mut write_prompt: impl FnMut(&str) -> io::Result<()>,
) -> Result<HostResponse, common::Error> {
    loop {
        write_prompt(&host_prompt(request)).map_err(host_io_error)?;
        let response = read()
            .map_err(host_io_error)?
            .ok_or(common::Error::UserCancelled)?;
        if let Some(response) = parse_host_response(request, response) {
            return Ok(response);
        }
    }
}

fn host_prompt(request: &HostRequest) -> String {
    match request {
        HostRequest::PinMatrix { kind } => match kind {
            PinMatrixRequestKind::Current => {
                format!("{PIN_MATRIX_DESCRIPTION}\nEnter current PIN positions:\n")
            }
            PinMatrixRequestKind::NewFirst => {
                format!("{PIN_MATRIX_DESCRIPTION}\nEnter new PIN positions:\n")
            }
            PinMatrixRequestKind::NewSecond => {
                format!("{PIN_MATRIX_DESCRIPTION}\nRe-enter new PIN positions:\n")
            }
            PinMatrixRequestKind::Unknown(code) => {
                format!("{PIN_MATRIX_DESCRIPTION}\nEnter PIN positions for request {code}:\n")
            }
        },
        HostRequest::RecoveryCharacter {
            word_position,
            character_position,
        } => format!(
            "Recovery word {word_position}, character {character_position} (letter/space/backspace/done):\n"
        ),
    }
}

fn parse_host_response(request: &HostRequest, response: String) -> Option<HostResponse> {
    match request {
        HostRequest::PinMatrix { .. }
            if !response.is_empty() && response.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            Some(HostResponse::PinPositions(response))
        }
        HostRequest::RecoveryCharacter { .. } => match response.as_str() {
            "space" => Some(HostResponse::RecoveryNextWord),
            "backspace" => Some(HostResponse::RecoveryDelete),
            "done" => Some(HostResponse::RecoveryDone),
            _ if response.len() == 1 && response.as_bytes()[0].is_ascii_lowercase() => Some(
                HostResponse::RecoveryCharacter(response.as_bytes()[0] as char),
            ),
            _ => None,
        },
        _ => None,
    }
}

fn host_io_error(error: io::Error) -> common::Error {
    if matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof | io::ErrorKind::Interrupted
    ) {
        common::Error::UserCancelled
    } else {
        common::Error::Device(format!("host interaction failed: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emulator_selector_accepts_prefixed_and_bare_paths() {
        for path in [DEFAULT_KEEPKEY_EMULATOR, "127.0.0.1:11044"] {
            let selector = DeviceSelector {
                device_type: Some(DeviceType::KeepKey),
                device_path: Some(path.to_owned()),
                include_emulators: true,
                ..DeviceSelector::default()
            };
            assert!(matches_emulator(&selector));
        }
    }

    #[test]
    fn physical_path_selects_only_matching_backend() {
        for (path, hid, webusb) in [
            (None, true, true),
            (Some("hid:2b24:0001:keepkey"), true, false),
            (Some("webusb:1:2"), false, true),
            (Some(DEFAULT_KEEPKEY_EMULATOR), false, false),
        ] {
            assert_eq!(uses_backend(path, "hid:"), hid);
            assert_eq!(uses_backend(path, "webusb:"), webusb);
        }
    }

    #[test]
    fn candidate_permission_errors_propagate_only_for_explicit_paths() {
        use anyhow::Context as _;

        for (backend, path, selected_path) in [
            ("HID", "hid:2b24:0001:keepkey", None),
            (
                "HID",
                "hid:2b24:0001:keepkey",
                Some("hid:2b24:0001:keepkey"),
            ),
            ("WebUSB", "webusb:1:2", None),
            ("WebUSB", "webusb:1:2", Some("webusb:1:2")),
        ] {
            let result = candidate_result(
                selected_path,
                path,
                Err::<(), _>(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("{backend} permission denied"),
                ))
                .context(format!("{backend} open failed")),
            );

            if selected_path.is_some() {
                let error = result.unwrap_err();
                assert_eq!(error.to_string(), format!("{backend} open failed"));
                assert_eq!(
                    error
                        .chain()
                        .find_map(|source| source.downcast_ref::<io::Error>())
                        .expect("permission error source")
                        .kind(),
                    io::ErrorKind::PermissionDenied
                );
            } else {
                assert!(result.unwrap().is_none());
            }
        }
    }

    #[test]
    fn pin_input_repeats_until_nonempty_ascii_digits() {
        let request = HostRequest::PinMatrix {
            kind: PinMatrixRequestKind::NewFirst,
        };
        let mut lines = [Some(""), Some("１２"), Some("12a"), Some("7913")].into_iter();
        let mut prompts = Vec::new();
        let response = read_host_response(
            &request,
            || Ok(lines.next().flatten().map(str::to_owned)),
            |prompt| {
                prompts.push(prompt.to_owned());
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(response, HostResponse::PinPositions("7913".to_owned()));
        assert_eq!(prompts.len(), 4);
        assert!(prompts.iter().all(|prompt| prompt.contains("new PIN")));
    }

    #[test]
    fn recovery_input_accepts_only_cipher_letters_and_actions() {
        let request = HostRequest::RecoveryCharacter {
            word_position: 4,
            character_position: 2,
        };
        for (input, expected) in [
            ("q", HostResponse::RecoveryCharacter('q')),
            ("space", HostResponse::RecoveryNextWord),
            ("backspace", HostResponse::RecoveryDelete),
            ("done", HostResponse::RecoveryDone),
        ] {
            assert_eq!(
                parse_host_response(&request, input.to_owned()),
                Some(expected)
            );
        }
        for input in ["Q", "qq", "", "delete", " space"] {
            assert_eq!(parse_host_response(&request, input.to_owned()), None);
        }
        let prompt = host_prompt(&request);
        assert!(prompt.contains("word 4"));
        assert!(prompt.contains("character 2"));
    }

    #[test]
    fn hidden_input_distinguishes_blank_lines_from_eof() {
        assert_eq!(
            completed_hidden_line(String::new(), true),
            Some(String::new())
        );
        assert_eq!(completed_hidden_line(String::new(), false), None);
    }

    #[test]
    fn host_input_eof_is_user_cancellation() {
        let request = HostRequest::PinMatrix {
            kind: PinMatrixRequestKind::Current,
        };
        assert!(matches!(
            read_host_response(&request, || Ok(None), |_| Ok(())),
            Err(common::Error::UserCancelled)
        ));
    }
}
