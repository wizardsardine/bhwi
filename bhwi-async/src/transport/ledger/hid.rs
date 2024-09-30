/*******************************************************************************
*   (c) 2022 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
use async_trait::async_trait;
use bhwi::ledger::apdu::{ApduCommand, ApduResponse};
use byteorder::{BigEndian, ReadBytesExt};
use futures::{
    io::{AsyncReadExt, AsyncWriteExt},
    lock::Mutex,
    AsyncRead, AsyncWrite,
};
use std::io::Cursor;

use crate::ledger::LedgerTransport;

const LEDGER_VID: u16 = 0x2c97;
const LEDGER_USAGE_PAGE: u16 = 0xFFA0;
const LEDGER_CHANNEL: u16 = 0x0101;
// for Windows compatability, we prepend the buffer with a 0x00
// so the actual buffer is 64 bytes
const LEDGER_PACKET_WRITE_SIZE: u8 = 65;
const LEDGER_PACKET_READ_SIZE: u8 = 64;

#[derive(Debug)]
pub enum LedgerHIDError {
    Comm(&'static str),
    Hid(std::io::Error),
}

impl From<std::io::Error> for LedgerHIDError {
    fn from(value: std::io::Error) -> Self {
        LedgerHIDError::Hid(value)
    }
}

async fn write_apdu<D: AsyncWrite + Unpin>(
    device: &mut D,
    channel: u16,
    apdu_command: &[u8],
) -> Result<(), LedgerHIDError> {
    let command_length = apdu_command.len();
    let mut in_data = Vec::with_capacity(command_length + 2);
    in_data.push(((command_length >> 8) & 0xFF) as u8);
    in_data.push((command_length & 0xFF) as u8);
    in_data.extend_from_slice(apdu_command);

    let mut buffer = vec![0u8; LEDGER_PACKET_WRITE_SIZE as usize];
    // Windows platform requires 0x00 prefix and Linux/Mac tolerate this as well
    buffer[0] = 0x00;
    buffer[1] = ((channel >> 8) & 0xFF) as u8; // channel big endian
    buffer[2] = (channel & 0xFF) as u8; // channel big endian
    buffer[3] = 0x05u8;

    for (sequence_idx, chunk) in in_data
        .chunks((LEDGER_PACKET_WRITE_SIZE - 6) as usize)
        .enumerate()
    {
        buffer[4] = ((sequence_idx >> 8) & 0xFF) as u8; // sequence_idx big endian
        buffer[5] = (sequence_idx & 0xFF) as u8; // sequence_idx big endian
        buffer[6..6 + chunk.len()].copy_from_slice(chunk);

        match device.write(&buffer).await {
            Ok(size) => {
                if size < buffer.len() {
                    return Err(LedgerHIDError::Comm(
                        "USB write error. Could not send whole message",
                    ));
                }
            }
            Err(e) => return Err(LedgerHIDError::Hid(e)),
        }
    }
    Ok(())
}

async fn read_apdu<D: AsyncRead + Unpin>(
    device: &mut D,
    channel: u16,
    apdu_answer: &mut Vec<u8>,
) -> Result<usize, LedgerHIDError> {
    let mut buffer = vec![0u8; LEDGER_PACKET_READ_SIZE as usize];
    let mut sequence_idx = 0u16;
    let mut expected_apdu_len = 0usize;

    loop {
        let res = device.read(&mut buffer).await?;

        if (sequence_idx == 0 && res < 7) || res < 5 {
            return Err(LedgerHIDError::Comm("Read error. Incomplete header"));
        }

        let mut rdr = Cursor::new(&buffer);

        let rcv_channel = rdr.read_u16::<BigEndian>()?;
        let rcv_tag = rdr.read_u8()?;
        let rcv_seq_idx = rdr.read_u16::<BigEndian>()?;

        if rcv_channel != channel {
            return Err(LedgerHIDError::Comm("Invalid channel"));
        }
        if rcv_tag != 0x05u8 {
            return Err(LedgerHIDError::Comm("Invalid tag"));
        }

        if rcv_seq_idx != sequence_idx {
            return Err(LedgerHIDError::Comm("Invalid sequence idx"));
        }

        if rcv_seq_idx == 0 {
            expected_apdu_len = rdr.read_u16::<BigEndian>()? as usize;
        }

        let available: usize = buffer.len() - rdr.position() as usize;
        let missing: usize = expected_apdu_len - apdu_answer.len();
        let end_p = rdr.position() as usize + std::cmp::min(available, missing);

        let new_chunk = &buffer[rdr.position() as usize..end_p];

        apdu_answer.extend_from_slice(new_chunk);

        if apdu_answer.len() >= expected_apdu_len {
            return Ok(apdu_answer.len());
        }

        sequence_idx += 1;
    }
}

pub struct LedgerTransportHID<C> {
    channel: Mutex<C>,
}

impl<C> LedgerTransportHID<C> {
    pub fn new(channel: C) -> Self {
        Self {
            channel: Mutex::new(channel),
        }
    }
}

#[async_trait(?Send)]
impl<C: AsyncRead + AsyncWrite + Unpin> LedgerTransport for LedgerTransportHID<C> {
    type Error = LedgerHIDError;

    async fn exchange(&self, command: &ApduCommand) -> Result<ApduResponse, Self::Error> {
        let mut channel = self.channel.lock().await;

        write_apdu(&mut *channel, LEDGER_CHANNEL, &command.encode()).await?;
        let mut answer: Vec<u8> = Vec::with_capacity(256);
        read_apdu(&mut *channel, LEDGER_CHANNEL, &mut answer).await?;

        ApduResponse::try_from(answer).map_err(|_| LedgerHIDError::Comm("response was too short"))
    }
}
