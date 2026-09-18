use std::{
    cell::Cell,
    io::{self, IsTerminal, Write},
    rc::Rc,
};

use async_trait::async_trait;
use bhwi::common::{self, HostRequest, HostResponse, PinMatrixRequestKind};
use bhwi_async::{HostInteraction, device::HostInteractionFactory};

use crate::hwi::PIN_MATRIX_DESCRIPTION;

/// A KeepKey asks for PIN positions, a passphrase or recovery characters while
/// a command is still running, so the answerer is attached before the device is
/// boxed.
pub fn cli_host_interaction() -> HostInteractionFactory {
    Rc::new(|| Box::new(CliHostInteraction))
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
