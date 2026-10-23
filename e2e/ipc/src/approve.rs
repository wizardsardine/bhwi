use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bhwi::keepkey::proto::DebugLinkState;
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket, UnixDatagram};
use tokio::time::{Instant, interval_at, timeout};

const PRESS_EVERY: Duration = Duration::from_millis(300);
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);

/// Stands in for the user at an emulator's confirmation screens. `None` in
/// [`approving`] is for emulators that confirm on their own.
#[derive(Clone, Copy)]
pub(crate) enum Approver {
    Trezor,
    Keepkey,
    Speculos,
    Specter,
    Coldcard,
}

pub(crate) async fn approving<C, F>(approver: Option<Approver>, command: C) -> Result<F::Output>
where
    C: FnOnce() -> F,
    F: Future,
{
    let approved = async {
        // Speculos rules only answer screens raised after they load, and a
        // request goes out as soon as it is sent.
        if let Some(Approver::Speculos) = approver {
            load_speculos_rules().await?;
        }
        let command = command();
        match approver {
            None | Some(Approver::Speculos) => Ok(command.await),
            Some(Approver::Trezor) => press_debuglink("127.0.0.1:21325", command).await,
            Some(Approver::Keepkey) => press_debuglink(KEEPKEY_DEBUGLINK, command).await,
            Some(Approver::Specter) => answer_specter(command).await,
            Some(Approver::Coldcard) => press_coldcard(command).await,
        }
    };
    timeout(APPROVAL_TIMEOUT, approved)
        .await
        .context("the device was still waiting for approval")?
}

// '?' report marker, "##", message type 100 (DebugLinkDecision) and payload
// length 2, both big-endian, then field 1 (the button) set to YES.
const DEBUGLINK_YES: [u8; 11] = [b'?', b'#', b'#', 0, 100, 0, 0, 0, 2, 0x08, 1];

async fn press_debuglink<F: Future>(addr: &str, command: F) -> Result<F::Output> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(addr).await?;
    let mut report = [0u8; 64];
    report[..DEBUGLINK_YES.len()].copy_from_slice(&DEBUGLINK_YES);
    tokio::pin!(command);
    let mut presses = interval_at(Instant::now() + PRESS_EVERY, PRESS_EVERY);
    loop {
        tokio::select! {
            output = &mut command => return Ok(output),
            _ = presses.tick() => {
                socket.send(&report).await?;
            }
        }
    }
}

const KEEPKEY_MAIN: &str = "127.0.0.1:11044";
const KEEPKEY_DEBUGLINK: &str = "127.0.0.1:11045";

/// What a KeepKey shows while it waits for host-side PIN or recovery input.
pub(crate) async fn keepkey_state() -> Result<DebugLinkState> {
    // DebugLinkGetState is 101, answered by DebugLinkState, 102.
    let (message_type, payload) = keepkey_exchange(KEEPKEY_DEBUGLINK, 101).await?;
    if message_type != 102 {
        bail!("the KeepKey debuglink answered message type {message_type}");
    }
    Ok(DebugLinkState::decode(payload.as_slice())?)
}

/// Locks the KeepKey, so the next session has to ask for its PIN.
pub(crate) async fn lock_keepkey() -> Result<()> {
    // ClearSession is 24, answered by Success, 2. The debuglink ignores it.
    let (message_type, _) = keepkey_exchange(KEEPKEY_MAIN, 24).await?;
    if message_type != 2 {
        bail!("the KeepKey did not confirm the lock: message type {message_type}");
    }
    Ok(())
}

/// Sends one payload-free message and reassembles the reply from its 64-byte
/// reports: '?' on every report, then "##", type and length on the first.
async fn keepkey_exchange(addr: &str, message_type: u16) -> Result<(u16, Vec<u8>)> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(addr).await?;
    let mut report = [0u8; 64];
    report[..5].copy_from_slice(&[b'?', b'#', b'#', 0, 0]);
    report[3..5].copy_from_slice(&message_type.to_be_bytes());
    socket.send(&report).await?;

    let mut frame = Vec::new();
    loop {
        let mut report = [0u8; 64];
        let received = timeout(Duration::from_secs(5), socket.recv(&mut report))
            .await
            .with_context(|| format!("the KeepKey at {addr} did not answer"))??;
        frame.extend_from_slice(&report[1..received]);
        if frame.len() >= 8 {
            let length = u32::from_be_bytes(frame[4..8].try_into()?) as usize;
            if frame.len() >= 8 + length {
                let reply_type = u16::from_be_bytes([frame[2], frame[3]]);
                return Ok((reply_type, frame[8..8 + length].to_vec()));
            }
        }
    }
}

// The first matching rule wins: the right button steps through review screens,
// both buttons accept.
const SPECULOS_RULES: &str = r#"{
  "version": 1,
  "rules": [
    {
      "regexp": "Review|Wallet|co-signer|Our|Their|Dummy|Key|key|Policy|Verify|Path|Address|Message|From|To|Amount|Fee|Output|Transaction|Account|Security risk|Unverified inputs",
      "actions": [["button", 2, true], ["button", 2, false]]
    },
    {
      "regexp": "Register account|Confirm|Accept|Approve|Sign|Continue anyway",
      "actions": [
        ["button", 1, true], ["button", 2, true],
        ["button", 2, false], ["button", 1, false]
      ]
    }
  ]
}"#;

async fn load_speculos_rules() -> Result<()> {
    let mut api = TcpStream::connect("127.0.0.1:5000")
        .await
        .context("connecting to the Speculos API")?;
    let request = format!(
        "POST /automation HTTP/1.1\r\nHost: 127.0.0.1:5000\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{SPECULOS_RULES}",
        SPECULOS_RULES.len()
    );
    api.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    api.read_to_end(&mut response).await?;
    let response = String::from_utf8_lossy(&response);
    let status = response.split_whitespace().nth(1).unwrap_or_default();
    if !status.starts_with('2') {
        bail!("Speculos refused the automation rules: {response}");
    }
    Ok(())
}

// The GUI writes one CRLF-terminated screen name per prompt and takes one
// "true"/"false" line back.
async fn answer_specter<F: Future>(command: F) -> Result<F::Output> {
    let mut gui = TcpStream::connect("127.0.0.1:8787")
        .await
        .context("connecting to the Specter GUI controller")?;
    // The GUI polls for a controller every 30ms; a screen raised before then
    // is never sent.
    tokio::time::sleep(Duration::from_millis(100)).await;
    tokio::pin!(command);
    let mut pending = Vec::new();
    let mut buffer = [0u8; 256];
    loop {
        tokio::select! {
            output = &mut command => return Ok(output),
            read = gui.read(&mut buffer) => {
                let read = read?;
                if read == 0 {
                    bail!("the Specter GUI closed the controller connection");
                }
                pending.extend_from_slice(&buffer[..read]);
                while let Some(end) = pending.windows(2).position(|pair| pair == b"\r\n") {
                    pending.drain(..end + 2);
                    gui.write_all(b"true\r\n").await?;
                }
            }
        }
    }
}

async fn press_coldcard<F: Future>(command: F) -> Result<F::Output> {
    let keys = ColdcardKeys::connect()?;
    tokio::pin!(command);
    let mut presses = interval_at(Instant::now() + PRESS_EVERY, PRESS_EVERY);
    let output = loop {
        tokio::select! {
            output = &mut command => break output,
            _ = presses.tick() => keys.press(b'y').await?,
        }
    };
    // A 'y' pressed before the prompt appeared opens the selected menu item.
    for _ in 0..3 {
        keys.press(b'x').await?;
    }
    Ok(output)
}

/// Accepts the screen a Coldcard raises after a command that returned before
/// the user answered, such as a wallet registration.
pub(crate) async fn accept_coldcard_prompt() -> Result<()> {
    let keys = ColdcardKeys::connect()?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    keys.press(b'y').await?;
    for _ in 0..3 {
        keys.press(b'x').await?;
    }
    Ok(())
}

/// A second simulator client beside the server's session. XKEY is only
/// accepted by the simulator, and only in the clear.
struct ColdcardKeys {
    socket: UnixDatagram,
    path: PathBuf,
}

impl ColdcardKeys {
    fn connect() -> Result<Self> {
        let path = PathBuf::from(format!(
            "/tmp/bhwi-ipc-e2e-keys-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let socket = UnixDatagram::bind(&path)?;
        socket
            .connect("/tmp/ckcc-simulator.sock")
            .context("connecting to the Coldcard simulator")?;
        Ok(Self { socket, path })
    }

    async fn press(&self, key: u8) -> Result<()> {
        let payload = [b'X', b'K', b'E', b'Y', key];
        let mut packet = [0u8; 64];
        // The payload length, with 0x80 marking the last packet of a message.
        packet[0] = 0x80 | payload.len() as u8;
        packet[1..=payload.len()].copy_from_slice(&payload);
        self.socket.send(&packet).await?;
        let mut reply = [0u8; 64];
        timeout(Duration::from_secs(5), self.socket.recv(&mut reply))
            .await
            .context("the Coldcard simulator did not answer a key press")??;
        Ok(())
    }
}

impl Drop for ColdcardKeys {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
