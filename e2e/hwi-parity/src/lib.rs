use std::{
    env,
    ffi::{OsStr, OsString},
    io::{Read, Write},
    path::Path,
    process::{Child, Command, ExitStatus, Output, Stdio},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use serde_json::Value;

pub mod signature;

#[derive(Clone, Debug)]
pub struct HwiBinary {
    label: &'static str,
    path: String,
}

#[derive(Clone)]
pub struct HwiOutput {
    pub status_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub json: Value,
}

#[derive(Clone)]
pub struct RawHwiOutput {
    pub status_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl HwiBinary {
    pub fn from_env(label: &'static str, var: &str, default: Option<&str>) -> Result<Self> {
        let path = match env::var(var) {
            Ok(path) => path,
            Err(_) => default
                .map(str::to_owned)
                .with_context(|| format!("{var} must point to the {label} hwi binary"))?,
        };
        Ok(Self { label, path })
    }

    pub fn reference() -> Result<Self> {
        Self::from_env("reference", "REFERENCE_HWI_BIN", Some("hwi-reference-bhwi"))
    }

    pub fn candidate() -> Result<Self> {
        Self::from_env("candidate", "HWI_BIN", None)
    }

    pub fn run<I, S>(&self, args: I) -> Result<HwiOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        parse_output(self.label, self.run_command(args, |_| {})?)
    }

    /// Like [`HwiBinary::run`] but tolerates non-JSON stdout, as `--help` produces.
    pub fn run_raw<I, S>(&self, args: I) -> Result<RawHwiOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self.run_command(args, |_| {})?;
        Ok(RawHwiOutput {
            status_code: output.status.code(),
            stdout: String::from_utf8(output.stdout)
                .with_context(|| format!("{} hwi wrote non-utf8 stdout", self.label))?,
            stderr: String::from_utf8(output.stderr)
                .with_context(|| format!("{} hwi wrote non-utf8 stderr", self.label))?,
        })
    }

    pub fn run_with_envs<I, S>(&self, args: I, envs: &[(&str, &str)]) -> Result<HwiOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self.run_command(args, |command| {
            command.envs(envs.iter().copied());
        })?;
        parse_output(self.label, output)
    }

    pub fn run_in_dir<I, S>(&self, args: I, cwd: &Path) -> Result<HwiOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self.run_command(args, |command| {
            command.current_dir(cwd);
        })?;
        parse_output(self.label, output)
    }

    pub fn run_with_stdin<I, S>(&self, args: I, stdin: &str) -> Result<HwiOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.run_with_stdin_and_envs(args, stdin, &[])
    }

    fn run_with_stdin_and_envs<I, S>(
        &self,
        args: I,
        stdin: &str,
        envs: &[(OsString, OsString)],
    ) -> Result<HwiOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let args = collect_args(args);
        let mut child = Command::new(&self.path)
            .args(&args)
            .envs(envs.iter().map(|(key, value)| (key, value)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to spawn {} hwi at {}", self.label, self.path))?;

        {
            let mut child_stdin = child
                .stdin
                .take()
                .with_context(|| format!("failed to open {} hwi stdin", self.label))?;
            child_stdin
                .write_all(stdin.as_bytes())
                .with_context(|| format!("failed to write {} hwi stdin", self.label))?;
        }

        parse_output(
            self.label,
            wait_with_timeout(child, self.label, &args, command_timeout())?,
        )
    }

    fn run_command<I, S>(&self, args: I, configure: impl FnOnce(&mut Command)) -> Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let args = collect_args(args);
        let mut command = Command::new(&self.path);
        command
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        configure(&mut command);
        let child = command
            .spawn()
            .with_context(|| format!("failed to spawn {} hwi at {}", self.label, self.path))?;
        wait_with_timeout(child, self.label, &args, command_timeout())
    }
}

fn collect_args<I, S>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    args.into_iter()
        .map(|arg| arg.as_ref().to_owned())
        .collect()
}

fn sensitive_command(args: &[OsString]) -> bool {
    args.iter().any(|arg| {
        matches!(
            arg.to_string_lossy().as_ref(),
            "signtx"
                | "sign-psbt"
                | "--psbt"
                | "--password"
                | "-p"
                | "--backup_passphrase"
                | "sendpin"
        )
    })
}

fn redacted_args(args: &[OsString]) -> Vec<OsString> {
    let mut redact_next = false;
    args.iter()
        .map(|arg| {
            if redact_next {
                redact_next = false;
                return OsString::from("<redacted>");
            }
            if matches!(
                arg.to_string_lossy().as_ref(),
                "--password" | "-p" | "--backup_passphrase" | "sendpin" | "signtx" | "--psbt"
            ) {
                redact_next = true;
            }
            arg.clone()
        })
        .collect()
}

fn command_timeout() -> Duration {
    const DEFAULT_SECS: u64 = 180;
    Duration::from_secs(
        env::var("HWI_PARITY_COMMAND_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_SECS),
    )
}

/// Waits for `child`, killing and reaping it once the deadline elapses or
/// `cancelled` asks the owner to stop.
fn wait_for_child(
    child: &mut Child,
    deadline: Instant,
    mut cancelled: impl FnMut() -> bool,
) -> std::io::Result<Option<ExitStatus>> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) => {}
            Err(error) => {
                kill_and_reap(child);
                return Err(error);
            }
        }
        if cancelled() || Instant::now() >= deadline {
            kill_and_reap(child);
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn kill_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn timeout_error(
    label: &str,
    args: &[OsString],
    timeout: Duration,
    stdout: &[u8],
    stderr: &[u8],
) -> anyhow::Error {
    let sensitive = sensitive_command(args);
    anyhow::anyhow!(
        "{label} hwi did not exit within {}s and was killed\nargs: {:?}\nstdout so far:\n{}\nstderr so far:\n{}",
        timeout.as_secs(),
        redacted_args(args),
        if sensitive {
            "<redacted>".to_owned()
        } else {
            String::from_utf8_lossy(stdout).into_owned()
        },
        if sensitive {
            "<redacted>".to_owned()
        } else {
            String::from_utf8_lossy(stderr).into_owned()
        }
    )
}

/// Waits for `child`, killing it once `timeout` elapses so a device that never
/// answers fails the test instead of hanging until CI is cancelled.
fn wait_with_timeout(
    mut child: Child,
    label: &str,
    args: &[OsString],
    timeout: Duration,
) -> Result<Output> {
    let stdout = reader_thread(child.stdout.take());
    let stderr = reader_thread(child.stderr.take());
    let wait = wait_for_child(&mut child, Instant::now() + timeout, || false);
    let stdout = join_reader(stdout);
    let stderr = join_reader(stderr);
    let Some(status) = wait? else {
        return Err(timeout_error(label, args, timeout, &stdout, &stderr));
    };

    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn reader_thread<R: Read + Send + 'static>(source: Option<R>) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        if let Some(mut source) = source {
            let _ = source.read_to_end(&mut buffer);
        }
        buffer
    })
}

fn join_reader(handle: JoinHandle<Vec<u8>>) -> Vec<u8> {
    handle.join().unwrap_or_default()
}

pub fn assert_json_parity<I, S>(args: I) -> Result<()>
where
    I: IntoIterator<Item = S> + Clone,
    S: AsRef<OsStr>,
{
    assert_json_parity_value(args)?;
    Ok(())
}

pub fn assert_json_parity_value<I, S>(args: I) -> Result<Value>
where
    I: IntoIterator<Item = S> + Clone,
    S: AsRef<OsStr>,
{
    let reference = HwiBinary::reference()?.run(args.clone())?;
    let candidate = HwiBinary::candidate()?.run(args)?;

    assert_success("reference", &reference)?;
    assert_success("candidate", &candidate)?;

    if reference.json != candidate.json {
        bail!(
            "HWI JSON mismatch\nreference:\n{}\ncandidate:\n{}",
            serde_json::to_string_pretty(&reference.json)?,
            serde_json::to_string_pretty(&candidate.json)?
        );
    }

    Ok(candidate.json)
}

fn parse_output(label: &str, output: Output) -> Result<HwiOutput> {
    let stdout = String::from_utf8(output.stdout)
        .with_context(|| format!("{label} hwi wrote non-utf8 stdout"))?;
    let stderr = String::from_utf8(output.stderr)
        .with_context(|| format!("{label} hwi wrote non-utf8 stderr"))?;
    let json = serde_json::from_str(stdout.trim())
        .with_context(|| format!("{label} hwi stdout was not JSON (output redacted)"))?;

    Ok(HwiOutput {
        status_code: output.status.code(),
        stdout,
        stderr,
        json,
    })
}

fn assert_success(label: &str, output: &HwiOutput) -> Result<()> {
    if output.status_code != Some(0) {
        bail!(
            "{label} hwi exited unsuccessfully with status {:?} (output redacted)",
            output.status_code
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt;
    use std::{
        fs,
        io::{BufRead, BufReader, Read, Write},
        net::UdpSocket,
        os::unix::net::UnixDatagram,
        path::{Path, PathBuf},
        str::FromStr,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc,
        },
        time::{Duration, Instant},
    };

    use bhwi_e2e_keepkey::debuglink::{
        DEFAULT_DEBUGLINK_ADDR as KEEPKEY_DEBUGLINK_ADDR, DEFAULT_MAIN_ADDR as KEEPKEY_MAIN_ADDR,
        DebugLink as KeepKeyDebugLink, KeepKeyHostInteraction, SYNTHETIC_MNEMONIC,
        lock_device as lock_keepkey,
    };
    use bhwi_e2e_trezor::debuglink::{DEFAULT_DEBUGLINK_ADDR, DebugButton, button_reports};

    use bitcoin::{
        Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Witness,
        absolute::LockTime,
        address::Address,
        base64::prelude::{BASE64_STANDARD, Engine as _},
        bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub},
        blockdata::{opcodes::all::OP_CHECKMULTISIG, script::Builder},
        key::TapTweak,
        psbt::{Input, Output as PsbtOutput, Psbt},
        secp256k1::{Message, Secp256k1},
        sighash::{Prevouts, SighashCache},
        transaction::Version as TxVersion,
    };

    const KEEPKEY_FINGERPRINT: &str = "95d8f670";
    const KEEPKEY_PIN: &str = "1234";
    const KEEPKEY_XPUB_44: &str = "tpubDCknDegFqAdP4V2AhHhs635DPe8N1aTjfKE9m2UFbdej8zmeNbtqDzK59SxnsYSRSx5uS3AujbwgANUiAk4oHmDNUKoGGkWWUY6c48WgjEx";
    const KEEPKEY_ENUMERATE_ERROR_PREFIX: &str =
        "Could not open client or get fingerprint information: ";

    fn normalize_keepkey_enumerate_error(mut value: Value) -> Value {
        if let Some(devices) = value.as_array_mut() {
            for device in devices {
                let Some(device) = device.as_object_mut() else {
                    continue;
                };
                if device.get("type").and_then(Value::as_str) != Some("keepkey") {
                    continue;
                }
                if let Some(Value::String(error)) = device.get_mut("error")
                    && error.starts_with(KEEPKEY_ENUMERATE_ERROR_PREFIX)
                {
                    error.replace_range(..KEEPKEY_ENUMERATE_ERROR_PREFIX.len(), "");
                }
            }
        }
        value
    }

    #[test]
    fn sensitive_hwi_arguments_are_redacted() {
        let args = ["--password", "secret", "signtx", "raw-psbt"].map(OsString::from);
        assert!(sensitive_command(&args));
        assert_eq!(
            redacted_args(&args),
            ["--password", "<redacted>", "signtx", "<redacted>"].map(OsString::from)
        );
    }

    #[test]
    fn normalize_keepkey_enumerate_error_preserves_unrelated_values() {
        let input = serde_json::json!([
            {
                "type": "keepkey",
                "error": "Could not open client or get fingerprint information: Passphrase too long",
                "code": -7,
                "sibling": {
                    "error": "Could not open client or get fingerprint information: nested"
                }
            },
            {
                "type": "keepkey",
                "error": "an unrelated KeepKey error",
                "code": -13
            },
            {
                "type": "trezor",
                "error": "Could not open client or get fingerprint information: unchanged",
                "code": -12
            },
            "unchanged"
        ]);
        let expected = serde_json::json!([
            {
                "type": "keepkey",
                "error": "Passphrase too long",
                "code": -7,
                "sibling": {
                    "error": "Could not open client or get fingerprint information: nested"
                }
            },
            {
                "type": "keepkey",
                "error": "an unrelated KeepKey error",
                "code": -13
            },
            {
                "type": "trezor",
                "error": "Could not open client or get fingerprint information: unchanged",
                "code": -12
            },
            "unchanged"
        ]);

        assert_eq!(normalize_keepkey_enumerate_error(input), expected);
    }

    #[test]
    fn commands_that_never_exit_are_killed() -> Result<()> {
        let mut child = Command::new("sh")
            .args(["-c", "exec sleep 30"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdout = reader_thread(child.stdout.take());
        let stderr = reader_thread(child.stderr.take());

        let status = wait_for_child(
            &mut child,
            Instant::now() + Duration::from_millis(200),
            || false,
        )?;

        assert!(status.is_none(), "a command that never exits must time out");
        assert!(
            child.try_wait()?.is_some(),
            "timed out child must be reaped"
        );
        assert!(join_reader(stdout).is_empty());
        assert!(join_reader(stderr).is_empty());
        Ok(())
    }

    #[test]
    fn reference_binary_enumerate_is_json_or_reports_clear_error() -> Result<()> {
        if env::var("REFERENCE_HWI_BIN").is_err() {
            return Ok(());
        }

        let output = HwiBinary::reference()?.run(["enumerate"])?;
        assert_success("reference", &output)?;
        assert_enumerate_array("reference", &output.json)?;
        Ok(())
    }

    #[test]
    fn candidate_usage_errors_match_reference() -> Result<()> {
        if env::var("HWI_BIN").is_err() {
            return Ok(());
        }

        let cases: [&[&str]; 7] = [
            &[],
            &["boguscmd"],
            &["getxpub"],
            &["--chain", "foo", "enumerate"],
            &["displayaddress"],
            &["getmasterxpub", "--addr-type", "bogus"],
            &["--bogus", "enumerate"],
        ];

        for case in cases {
            let args = case.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
            assert_usage_error_parity(args)
                .with_context(|| format!("usage error parity failed for args: {case:?}"))?;
        }

        Ok(())
    }

    #[test]
    fn candidate_validation_order_matches_reference() -> Result<()> {
        if env::var("HWI_BIN").is_err() {
            return Ok(());
        }

        // Unknown device type: the lookup decides. Without -d nothing can
        // match (-3); with -d upstream's get_client rejects the type (-4).
        // These hold whether or not an emulator is attached.
        let mut cases: Vec<(Vec<String>, i64)> = vec![
            (args(["-t", "bogus", "getxpub", "m/44h/1h/0h"]), -3),
            (args(["-t", "bogus", "signtx", "notapsbt"]), -3),
            (
                args(["-t", "bogus", "signmessage", "hello", "bad/path"]),
                -3,
            ),
            (
                args(["-t", "bogus", "-d", "/dev/bogus", "getxpub", "m/44h/1h/0h"]),
                -4,
            ),
        ];

        // With a device attached, argument validation runs after lookup:
        // invalid PSBTs are INVALID_TX (-5) and invalid paths BAD_ARGUMENT (-7).
        if let Some(device_type) = expected_device_type_from_env()? {
            let with_device = |rest: &[&str]| {
                let mut argv = args(["--emulators", "--chain", "test", "-t", &device_type]);
                argv.extend(rest.iter().map(|arg| (*arg).to_owned()));
                argv
            };
            cases.push((with_device(&["signtx", "notapsbt"]), -5));
            let bad_xpub_path_code = if device_type == "bitbox02" { -13 } else { -7 };
            cases.push((with_device(&["getxpub", "not_a_path"]), bad_xpub_path_code));
            cases.push((with_device(&["signmessage", "hello", "bad/path"]), -7));
            cases.push((with_device(&["displayaddress", "--path", "bad/path"]), -7));
        }

        for (case, expected_code) in cases {
            let reference = HwiBinary::reference()?.run(case.clone())?;
            let candidate = HwiBinary::candidate()?.run(case.clone())?;
            for (label, output) in [("reference", &reference), ("candidate", &candidate)] {
                assert_success(label, output)?;
                let code = output.json.get("code").and_then(Value::as_i64);
                if code != Some(expected_code) {
                    bail!(
                        "{label} hwi {case:?} expected code {expected_code}, got {code:?}\nstdout:\n{}",
                        output.stdout
                    );
                }
            }
        }

        Ok(())
    }

    #[test]
    fn candidate_help_and_version_status_matches_reference() -> Result<()> {
        if env::var("HWI_BIN").is_err() {
            return Ok(());
        }

        // `--version` prints plain text on stdout and exits 0 on both sides.
        for binary in [HwiBinary::reference()?, HwiBinary::candidate()?] {
            let output = binary.run_raw(["--version"])?;
            if output.status_code != Some(0) {
                bail!(
                    "{} hwi --version exited {:?}\nstdout:\n{}\nstderr:\n{}",
                    binary.label,
                    output.status_code,
                    output.stdout,
                    output.stderr
                );
            }
            if output.stdout.trim().is_empty() {
                bail!("{} hwi --version wrote no stdout", binary.label);
            }
        }

        // `--help` prints the `-17` JSON object on stdout and the help text on
        // stderr, exiting 0 (hwilib/_cli.py HWIHelpAction). The help body is
        // not compared: prog name and argparse/clap formatting differ.
        let expected = serde_json::json!({"error": "Help text requested", "code": -17});
        for args in [["--help"].as_slice(), ["getxpub", "--help"].as_slice()] {
            for binary in [HwiBinary::reference()?, HwiBinary::candidate()?] {
                let output = binary.run_raw(args.iter().copied())?;
                if output.status_code != Some(0) {
                    bail!(
                        "{} hwi {args:?} exited {:?}\nstdout:\n{}\nstderr:\n{}",
                        binary.label,
                        output.status_code,
                        output.stdout,
                        output.stderr
                    );
                }
                let json: Value =
                    serde_json::from_str(output.stdout.trim()).with_context(|| {
                        format!(
                            "{} hwi {args:?} stdout was not JSON\nstdout:\n{}",
                            binary.label, output.stdout
                        )
                    })?;
                if json != expected {
                    bail!(
                        "{} hwi {args:?} help JSON mismatch\nexpected: {expected}\ngot: {json}",
                        binary.label
                    );
                }
                if output.stderr.trim().is_empty() {
                    bail!("{} hwi {args:?} wrote no help text on stderr", binary.label);
                }
            }
        }

        Ok(())
    }

    #[test]
    fn candidate_enumerate_matches_reference() -> Result<()> {
        if env::var("HWI_BIN").is_err() {
            return Ok(());
        }

        let (args, expected_device_type) = enumerate_args_from_env()?;
        assert_enumerate_parity(args, expected_device_type.as_deref())?;
        Ok(())
    }

    #[test]
    fn candidate_keepkey_enumerate_contract_is_exact() -> Result<()> {
        if env::var("HWI_BIN").is_err()
            || expected_device_type_from_env()?.as_deref() != Some("keepkey")
        {
            return Ok(());
        }
        let command = args([
            "--emulators",
            "--chain",
            "test",
            "--device-type",
            "keepkey",
            "enumerate",
        ]);
        for binary in [HwiBinary::reference()?, HwiBinary::candidate()?] {
            let output = binary.run(command.clone())?;
            assert_success(binary.label, &output)?;
            let device = assert_enumerate_contains_device(binary.label, &output.json, "keepkey")?;
            assert_eq!(device["type"], "keepkey");
            assert_eq!(device["model"], "keepkey_simulator");
            assert_eq!(device["path"], KEEPKEY_MAIN_ADDR);
            assert_eq!(device["label"], "test");
            assert_eq!(device["fingerprint"], KEEPKEY_FINGERPRINT);
            assert_eq!(device["needs_pin_sent"], false);
            assert_eq!(device["needs_passphrase_sent"], false);
        }
        Ok(())
    }

    #[test]
    fn candidate_enumerate_accepts_python_hwi_global_args() -> Result<()> {
        if env::var("HWI_BIN").is_err() {
            return Ok(());
        }

        let Some(device_type) = expected_device_type_from_env()? else {
            return Ok(());
        };

        let (base_args, _) = enumerate_args_from_env()?;
        let reference = HwiBinary::reference()?.run(base_args)?;
        assert_success("reference", &reference)?;
        let reference_device =
            assert_enumerate_contains_device("reference", &reference.json, &device_type)?;
        let device_path = assert_string_field("reference", reference_device, "path")?.to_owned();
        let fingerprint =
            assert_string_field("reference", reference_device, "fingerprint")?.to_owned();

        for args in enumerate_python_hwi_arg_cases(&device_type, &device_path, &fingerprint) {
            assert_enumerate_parity(args.clone(), Some(&device_type))
                .with_context(|| format!("enumerate parity failed for args: {args:?}"))?;
        }

        assert_enumerate_stdin_parity(&device_type)?;
        Ok(())
    }

    #[test]
    fn candidate_getxpub_matches_reference() -> Result<()> {
        if env::var("HWI_BIN").is_err() {
            return Ok(());
        }

        let Some(device_type) = expected_device_type_from_env()? else {
            return Ok(());
        };

        for args in getxpub_arg_cases(&device_type) {
            assert_getxpub_parity(args.clone())
                .with_context(|| format!("getxpub parity failed for args: {args:?}"))?;
        }

        Ok(())
    }

    #[test]
    fn candidate_getmasterxpub_matches_reference() -> Result<()> {
        if env::var("HWI_BIN").is_err() {
            return Ok(());
        }

        let Some(device_type) = expected_device_type_from_env()? else {
            return Ok(());
        };

        for case in getmasterxpub_arg_cases(&device_type) {
            match case.expect {
                ExpectedResult::Success => assert_getmasterxpub_parity(case.args.clone())
                    .with_context(|| {
                        format!("getmasterxpub parity failed for args: {:?}", case.args)
                    })?,
                ExpectedResult::Error => {
                    assert_error_json_parity(case.args.clone()).with_context(|| {
                        format!(
                            "getmasterxpub error parity failed for args: {:?}",
                            case.args
                        )
                    })?
                }
            }
        }

        Ok(())
    }

    #[test]
    fn candidate_getdescriptors_matches_reference() -> Result<()> {
        if env::var("HWI_BIN").is_err() {
            return Ok(());
        }

        let Some(device_type) = expected_device_type_from_env()? else {
            return Ok(());
        };

        for args in getdescriptors_arg_cases(&device_type) {
            assert_getdescriptors_parity(args.clone())
                .with_context(|| format!("getdescriptors parity failed for args: {args:?}"))?;
        }
        if device_type == "keepkey" {
            let json = assert_json_parity_value(
                getdescriptors_arg_cases(&device_type)
                    .into_iter()
                    .next()
                    .expect("KeepKey descriptor case"),
            )?;
            for field in ["receive", "internal"] {
                let descriptors = json[field]
                    .as_array()
                    .context("KeepKey descriptor list is not an array")?;
                assert_eq!(descriptors.len(), 3, "{field} KeepKey descriptors");
                for prefix in ["pkh(", "sh(wpkh(", "wpkh("] {
                    assert!(
                        descriptors
                            .iter()
                            .filter_map(Value::as_str)
                            .any(|descriptor| descriptor.starts_with(prefix)),
                        "missing KeepKey {prefix} descriptor"
                    );
                }
                assert!(
                    descriptors
                        .iter()
                        .filter_map(Value::as_str)
                        .all(|descriptor| !descriptor.starts_with("tr("))
                );
            }
        }

        Ok(())
    }

    #[test]
    fn candidate_getkeypool_matches_reference() -> Result<()> {
        if env::var("HWI_BIN").is_err() {
            return Ok(());
        }

        let Some(device_type) = expected_device_type_from_env()? else {
            return Ok(());
        };

        for case in getkeypool_arg_cases(&device_type) {
            match case.expect {
                ExpectedResult::Success => assert_getkeypool_parity(case.args.clone())
                    .with_context(|| {
                        format!("getkeypool parity failed for args: {:?}", case.args)
                    })?,
                ExpectedResult::Error => {
                    assert_error_json_parity(case.args.clone()).with_context(|| {
                        format!("getkeypool error parity failed for args: {:?}", case.args)
                    })?
                }
            }
        }

        Ok(())
    }

    #[test]
    fn candidate_signtx_matches_reference() -> Result<()> {
        if env::var("HWI_BIN").is_err() {
            return Ok(());
        }

        let Some(device_type) = expected_device_type_from_env()? else {
            return Ok(());
        };

        if device_type == "ledger" {
            for wrapper in LedgerSinglesigWrapper::ALL {
                let case = build_singlesig_signtx_case(&device_type, wrapper)?;
                assert_signtx_parity(signtx_args(&device_type, &case.psbt), &case).with_context(
                    || format!("signtx Ledger {wrapper:?} singlesig parity failed"),
                )?;
            }
            for wrapper in LedgerMultisigWrapper::ALL {
                let case = build_ledger_multisig_signtx_case(&device_type, wrapper)?;
                assert_signtx_parity(signtx_args(&device_type, &case.psbt), &case)
                    .with_context(|| format!("signtx Ledger {wrapper:?} multisig parity failed"))?;
            }

            let mixed = build_ledger_mixed_policy_signtx_case(&device_type)?;
            assert_signtx_parity(signtx_args(&device_type, &mixed.psbt), &mixed)
                .context("signtx Ledger mixed-policy parity failed")?;
        } else if device_type == "keepkey" {
            for wrapper in [
                LedgerSinglesigWrapper::Legacy,
                LedgerSinglesigWrapper::ShWit,
                LedgerSinglesigWrapper::Wit,
            ] {
                let case = build_singlesig_signtx_case(&device_type, wrapper)?;
                assert_signtx_parity(signtx_args(&device_type, &case.psbt), &case)
                    .with_context(|| format!("signtx KeepKey {wrapper:?} parity failed"))?;
            }
            for wrapper in LedgerMultisigWrapper::ALL {
                let case = build_keepkey_multisig_signtx_case(&device_type, wrapper)?;
                assert_signtx_parity(signtx_args(&device_type, &case.psbt), &case).with_context(
                    || format!("signtx KeepKey {wrapper:?} multisig parity failed"),
                )?;
            }
            let mixed = build_mixed_singlesig_signtx_case(&device_type)?;
            assert_signtx_parity(signtx_args(&device_type, &mixed.psbt), &mixed)
                .context("signtx KeepKey mixed legacy/SegWit parity failed")?;
        } else {
            let singlesig = build_singlesig_signtx_case(&device_type, LedgerSinglesigWrapper::Wit)?;
            assert_signtx_parity(signtx_args(&device_type, &singlesig.psbt), &singlesig)
                .with_context(|| format!("signtx singlesig parity failed for {device_type}"))?;
        }

        Ok(())
    }

    #[test]
    fn candidate_signmessage_matches_reference() -> Result<()> {
        if env::var("HWI_BIN").is_err() {
            return Ok(());
        }

        let Some(device_type) = expected_device_type_from_env()? else {
            return Ok(());
        };

        for case in signmessage_arg_cases(&device_type)? {
            assert_signmessage_parity(
                signmessage_args(&device_type, case.message, case.path),
                &case,
            )
            .with_context(|| {
                format!(
                    "signmessage parity failed for {device_type}, message {:?}, path {}",
                    case.message, case.path
                )
            })?;
        }

        Ok(())
    }

    #[test]
    fn candidate_displayaddress_matches_reference() -> Result<()> {
        if env::var("HWI_BIN").is_err() {
            return Ok(());
        }

        let Some(device_type) = expected_device_type_from_env()? else {
            return Ok(());
        };

        for case in displayaddress_arg_cases(&device_type)? {
            assert_displayaddress_parity(&case).with_context(|| {
                format!("displayaddress parity failed for args: {:?}", case.args)
            })?;
        }

        Ok(())
    }

    #[test]
    fn candidate_cancel_codes_match_reference() -> Result<()> {
        if env::var("HWI_BIN").is_err() {
            return Ok(());
        }

        let Some(device_type) = expected_device_type_from_env()? else {
            return Ok(());
        };
        // Jade and BitBox reject automation is not wired; their cancel paths
        // are covered by protocol unit tests (docs/HWI_PARITY.md).
        if !matches!(device_type.as_str(), "ledger" | "coldcard" | "keepkey") {
            return Ok(());
        }

        // A signable PSBT so both sides reach the on-device prompt.
        let signtx_case = build_singlesig_signtx_case(&device_type, LedgerSinglesigWrapper::Wit)?;
        let cases = [
            ("signtx", signtx_args(&device_type, &signtx_case.psbt)),
            (
                "signmessage",
                signmessage_args(&device_type, "cancel me", "m/84'/1'/0'/0/0"),
            ),
            (
                "displayaddress",
                displayaddress_path_args(&device_type, "wit", "m/84h/1h/0h/0/0"),
            ),
        ];

        if device_type == "keepkey" {
            for (command, case) in cases {
                let refusal = spawn_debug_approval(
                    KEEPKEY_DEBUGLINK_ADDR,
                    DebugButton::No,
                    Instant::now() + command_timeout(),
                );
                let output = HwiBinary::candidate()?.run(case)?;
                drop(refusal);
                assert_success("candidate", &output)?;
                assert_eq!(
                    output.json,
                    ExpectedHwiError {
                        code: -14,
                        error: "authentication refused",
                    }
                    .json(),
                    "{command} refusal"
                );
                let healthy = HwiBinary::candidate()?.run(args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    "keepkey",
                    "getxpub",
                    "m/44h/1h/0h",
                ]))?;
                assert_success("candidate", &healthy)?;
                assert_eq!(healthy.json["xpub"], KEEPKEY_XPUB_44);
            }
            return Ok(());
        }

        // Pinned upstream behavior per device/command: Ledger's DenyError
        // bypasses ledger_exception (-13). A refused Coldcard signtx is
        // timing-dependent on both implementations: -14 when the refusal frame
        // answers an in-flight poll, or -7 "No active request" once the
        // cleared request errors on the next poll. The remaining Coldcard
        // commands raise CCUserRefused (-14).
        let expected_codes = |command: &str| -> &'static [i64] {
            match (device_type.as_str(), command) {
                ("ledger", _) => &[-13],
                ("coldcard", "signtx") => &[-7, -14],
                _ => &[-14],
            }
        };

        for (command, case) in cases {
            // Coldcard's `show` command returns the address in the immediate
            // response; the on-screen confirmation is fire-and-forget, so no
            // USB refusal path exists for displayaddress on this firmware.
            if device_type == "coldcard" && command == "displayaddress" {
                continue;
            }
            // Upstream's Coldcard client presses `y` on the simulator by
            // itself (coldcard.py `sim_keypress(b'y')` in every prompting
            // command), so a refusal can never be exercised through the
            // reference there. Coldcard cases are candidate-only with the
            // expected codes pinned from upstream source (CCUserRefused ->
            // -14; a refused signtx may also clear to -7).
            let labels: &[&str] = if device_type == "coldcard" {
                &["candidate"]
            } else {
                &["reference", "candidate"]
            };
            for &label in labels {
                let candidate_refuses_itself =
                    label == "candidate" && device_type == "coldcard" && command != "signtx";
                let mut refusal = None;
                match device_type.as_str() {
                    "ledger" => set_ledger_cancel_automation(command)?,
                    "coldcard" => {
                        // The simulator numpad is a queue: stray keypresses
                        // from earlier cases would be consumed by this prompt.
                        flush_coldcard_keypresses()?;
                        // The candidate CLI presses the refusal itself for the
                        // commands with built-in emulator approval.
                        if !candidate_refuses_itself {
                            refusal = Some(ColdcardRefusal::spawn());
                        }
                    }
                    _ => {}
                }
                let binary = if label == "reference" {
                    HwiBinary::reference()?
                } else {
                    HwiBinary::candidate()?
                };
                let output = if candidate_refuses_itself {
                    binary.run_with_envs(case.clone(), &[("HWI_COLDCARD_EMULATOR_REFUSE", "1")])?
                } else {
                    binary.run(case.clone())?
                };
                if let Some(refusal) = refusal.take() {
                    refusal.finish();
                }
                if device_type == "coldcard" {
                    // Drop refusals queued after the prompt was answered so
                    // they cannot leak into later cases or tests.
                    flush_coldcard_keypresses()?;
                }
                assert_success(label, &output)?;
                let expected = expected_codes(command);
                let code = output.json.get("code").and_then(Value::as_i64);
                if !code.is_some_and(|code| expected.contains(&code)) {
                    bail!(
                        "{label} hwi {command} cancel expected code in {expected:?}, got {code:?}\nstdout:\n{}",
                        output.stdout
                    );
                }
            }
        }

        Ok(())
    }

    #[test]
    fn candidate_backup_matches_reference() -> Result<()> {
        if env::var("HWI_BIN").is_err() {
            return Ok(());
        }

        let Some(device_type) = expected_device_type_from_env()? else {
            return Ok(());
        };

        for case in backup_arg_cases(&device_type) {
            match case.expect {
                ExpectedResult::Success => assert_backup_parity(&device_type, case.args.clone())
                    .with_context(|| format!("backup parity failed for args: {:?}", case.args))?,
                ExpectedResult::Error => {
                    assert_error_json_parity(case.args.clone()).with_context(|| {
                        format!("backup error parity failed for args: {:?}", case.args)
                    })?
                }
            }
        }

        Ok(())
    }

    fn assert_backup_parity(device_type: &str, args: Vec<String>) -> Result<()> {
        if device_type != "coldcard" {
            assert_json_parity(args)?;
            return Ok(());
        }

        let temp = temp_path("coldcard-backup")?;
        let reference_dir = temp.join("reference");
        let candidate_dir = temp.join("candidate");
        fs::create_dir_all(&reference_dir)?;
        fs::create_dir_all(&candidate_dir)?;

        store_coldcard_backup_password()?;

        let reference_approval = ColdcardBackupApproval::spawn();
        let reference = HwiBinary::reference()?.run_in_dir(args.clone(), &reference_dir);
        reference_approval.finish();
        let reference = reference?;

        let candidate_approval = ColdcardBackupApproval::spawn();
        let candidate = HwiBinary::candidate()?.run_in_dir(args, &candidate_dir);
        candidate_approval.finish();
        let candidate = candidate?;

        assert_success("reference", &reference)?;
        assert_success("candidate", &candidate)?;
        assert_eq!(reference.json, serde_json::json!({ "success": true }));
        assert_eq!(candidate.json, reference.json);
        assert_backup_artifact("reference", &reference_dir)?;
        assert_backup_artifact("candidate", &candidate_dir)?;

        Ok(())
    }

    fn assert_backup_artifact(label: &str, dir: &Path) -> Result<()> {
        let files = fs::read_dir(dir)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with("backup-") && name.ends_with(".7z")
            })
            .collect::<Vec<_>>();
        if files.len() != 1 {
            bail!(
                "{label} backup wrote {} matching artifacts in {}",
                files.len(),
                dir.display()
            );
        }

        let bytes = fs::read(files[0].path())?;
        if !bytes.starts_with(b"7z\xbc\xaf'\x1c") {
            bail!("{label} backup artifact does not look like a 7z file");
        }
        if bytes.len() <= 1024 {
            bail!("{label} backup artifact is unexpectedly small");
        }

        Ok(())
    }

    #[test]
    fn candidate_unsupported_device_actions_match_reference() -> Result<()> {
        if env::var("HWI_BIN").is_err() {
            return Ok(());
        }

        let Some(device_type) = expected_device_type_from_env()? else {
            return Ok(());
        };

        for case in unsupported_device_action_cases(&device_type) {
            assert_error_json_parity(case.args.clone()).with_context(|| {
                format!(
                    "unsupported device action parity failed for args: {:?}",
                    case.args
                )
            })?;
        }

        Ok(())
    }

    #[test]
    fn candidate_bitbox_management_matches_reference() -> Result<()> {
        if env::var("HWI_BIN").is_err()
            || expected_device_type_from_env()?.as_deref() != Some("bitbox02")
        {
            return Ok(());
        }

        let base = [
            "--emulators",
            "--chain",
            "test",
            "--device-type",
            "bitbox02",
        ];
        for command in [
            vec!["setup"],
            vec![
                "--interactive",
                "setup",
                "--backup_passphrase",
                "backup passphrase",
            ],
            vec!["--interactive", "setup", "--label", "Already initialized"],
            vec!["restore"],
            vec!["--interactive", "restore", "--word_count", "12"],
        ] {
            assert_error_json_parity(base.into_iter().chain(command).map(str::to_owned).collect())?;
        }

        // The reference toggles the setting once and the candidate toggles it back, so the
        // shared simulator is returned to its original state after the parity assertion.
        assert_json_parity(
            base.into_iter()
                .chain(["togglepassphrase"])
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        )?;
        Ok(())
    }

    struct KeepKeyPassphraseStateGuard {
        armed: bool,
    }

    impl KeepKeyPassphraseStateGuard {
        fn restore(mut self) -> Result<()> {
            self.restore_keepkey_passphrase_disabled()?;
            self.armed = false;
            Ok(())
        }

        fn restore_keepkey_passphrase_disabled(&self) -> Result<()> {
            let output = HwiBinary::reference()?.run(keepkey_enumerate_args(None))?;
            assert_success("reference", &output)?;
            let device = assert_enumerate_contains_device("reference", &output.json, "keepkey")?;
            let single_device = output
                .json
                .as_array()
                .is_some_and(|devices| devices.len() == 1);
            let passphrase_required = single_device
                && device.get("code").and_then(Value::as_i64) == Some(-12)
                && device.get("error").and_then(Value::as_str)
                    == Some(
                        "Could not open client or get fingerprint information: Passphrase needs to be specified before the fingerprint information can be retrieved",
                    )
                && device.get("needs_pin_sent").and_then(Value::as_bool) == Some(false)
                && device.get("needs_passphrase_sent").and_then(Value::as_bool) == Some(true)
                && device.get("fingerprint").is_none();
            if passphrase_required {
                let toggle = run_candidate_keepkey_approved(&["-p", "", "togglepassphrase"])?;
                if toggle.json != serde_json::json!({"success": true}) {
                    bail!("candidate hwi failed to disable KeepKey passphrases");
                }
                return Ok(());
            }

            let already_disabled = single_device
                && device.get("code").is_none()
                && device.get("error").is_none()
                && device.get("fingerprint").and_then(Value::as_str).is_some()
                && device.get("needs_pin_sent").and_then(Value::as_bool) == Some(false)
                && device.get("needs_passphrase_sent").and_then(Value::as_bool) == Some(false);
            if !already_disabled {
                bail!("could not establish the KeepKey passphrase state during cleanup");
            }
            Ok(())
        }
    }

    impl Drop for KeepKeyPassphraseStateGuard {
        fn drop(&mut self) {
            if self.armed {
                let _ = self.restore_keepkey_passphrase_disabled();
            }
        }
    }

    #[test]
    fn candidate_keepkey_management_matches_reference() -> Result<()> {
        if env::var("HWI_BIN").is_err()
            || expected_device_type_from_env()?.as_deref() != Some("keepkey")
        {
            return Ok(());
        }
        let base = ["--emulators", "--chain", "test", "--device-type", "keepkey"];
        for command in [
            vec!["setup"],
            vec!["--interactive", "setup", "--label", "Already initialized"],
            vec!["restore"],
            vec!["--interactive", "restore", "--word_count", "12"],
            vec!["promptpin"],
            vec!["sendpin", "1234"],
            vec!["backup"],
        ] {
            assert_error_json_parity(base.into_iter().chain(command).map(str::to_owned).collect())?;
        }

        let toggle = base
            .into_iter()
            .chain(["togglepassphrase"])
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let reference = HwiBinary::reference()?.run(toggle)?;
        let cleanup = KeepKeyPassphraseStateGuard { armed: true };
        assert_success("reference", &reference)?;
        assert_eq!(reference.json, serde_json::json!({"success": true}));

        let mut passphrase_fingerprints = Vec::new();
        for (index, password) in [
            None,
            Some(""),
            Some("fixture-passphrase-one"),
            Some("fixture-passphrase-two"),
        ]
        .into_iter()
        .enumerate()
        {
            let enumerate = keepkey_enumerate_args(password);
            let reference_enumerate = HwiBinary::reference()?.run(enumerate.clone())?;
            let approval = spawn_debug_approval(
                KEEPKEY_DEBUGLINK_ADDR,
                DebugButton::Yes,
                Instant::now() + command_timeout(),
            );
            let candidate_enumerate = HwiBinary::candidate()
                .and_then(|binary| binary.run(enumerate))
                .with_context(|| format!("candidate passphrase case {index}"))?;
            drop(approval);
            assert_success("reference", &reference_enumerate)?;
            assert_success("candidate", &candidate_enumerate)?;
            assert_enumerate_array("reference", &reference_enumerate.json)?;
            assert_enumerate_array("candidate", &candidate_enumerate.json)?;
            assert_eq!(
                normalize_keepkey_enumerate_error(reference_enumerate.json.clone()),
                normalize_keepkey_enumerate_error(candidate_enumerate.json.clone()),
                "KeepKey passphrase enumerate case {index}"
            );

            let device = assert_enumerate_contains_device(
                "candidate",
                &candidate_enumerate.json,
                "keepkey",
            )?;
            if password.is_none() {
                let reference_device = assert_enumerate_contains_device(
                    "reference",
                    &reference_enumerate.json,
                    "keepkey",
                )?;
                assert_eq!(reference_device["code"], -12);
                assert_eq!(
                    reference_device["error"],
                    "Could not open client or get fingerprint information: Passphrase needs to be specified before the fingerprint information can be retrieved"
                );
                assert_eq!(device["code"], -12);
                assert_eq!(
                    device["error"],
                    "Passphrase needs to be specified before the fingerprint information can be retrieved"
                );
            } else {
                passphrase_fingerprints
                    .push(assert_string_field("candidate", device, "fingerprint")?.to_owned());
            }
        }
        assert_eq!(passphrase_fingerprints[0], KEEPKEY_FINGERPRINT);
        assert_ne!(passphrase_fingerprints[1], passphrase_fingerprints[0]);
        assert_ne!(passphrase_fingerprints[2], passphrase_fingerprints[0]);
        assert_ne!(passphrase_fingerprints[1], passphrase_fingerprints[2]);

        let too_long = "x".repeat(51);
        let enumerate = keepkey_enumerate_args(Some(&too_long));
        let reference_error = HwiBinary::reference()?.run(enumerate.clone())?;
        let candidate_error = HwiBinary::candidate()?.run(enumerate)?;
        assert_success("reference", &reference_error)?;
        assert_success("candidate", &candidate_error)?;
        assert_enumerate_array("reference", &reference_error.json)?;
        assert_enumerate_array("candidate", &candidate_error.json)?;
        assert_eq!(
            normalize_keepkey_enumerate_error(reference_error.json.clone()),
            normalize_keepkey_enumerate_error(candidate_error.json.clone()),
            "51-byte KeepKey passphrase enumerate"
        );
        let reference_device =
            assert_enumerate_contains_device("reference", &reference_error.json, "keepkey")?;
        assert_eq!(reference_device["code"], -7);
        assert_eq!(
            reference_device["error"],
            "Could not open client or get fingerprint information: Passphrase too long"
        );
        let device =
            assert_enumerate_contains_device("candidate", &candidate_error.json, "keepkey")?;
        assert_eq!(device["code"], -7);
        assert_eq!(device["error"], "Passphrase too long");

        cleanup.restore()
    }

    struct KeepKeyInteractiveOutput {
        output: HwiOutput,
        pin_kinds: Vec<bhwi::common::PinMatrixRequestKind>,
        recovery_requests: usize,
    }

    fn keepkey_runtime() -> Result<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build KeepKey parity runtime")
    }

    fn keepkey_args(command: &[&str]) -> Vec<String> {
        [
            "--emulators",
            "--chain",
            "test",
            "--device-type",
            "keepkey",
            "--device-path",
            KEEPKEY_MAIN_ADDR,
        ]
        .into_iter()
        .chain(command.iter().copied())
        .map(str::to_owned)
        .collect()
    }

    fn keepkey_prompt_request(line: &str) -> Result<Option<bhwi::common::HostRequest>> {
        use bhwi::common::{HostRequest, PinMatrixRequestKind};

        let request = match line {
            "Enter current PIN positions:" => Some(HostRequest::PinMatrix {
                kind: PinMatrixRequestKind::Current,
            }),
            "Enter new PIN positions:" => Some(HostRequest::PinMatrix {
                kind: PinMatrixRequestKind::NewFirst,
            }),
            "Re-enter new PIN positions:" => Some(HostRequest::PinMatrix {
                kind: PinMatrixRequestKind::NewSecond,
            }),
            _ => None,
        };
        const PIN_DESCRIPTION: &str =
            "Use the numeric keypad to describe number positions. The layout is:
    7 8 9
    4 5 6
    1 2 3";
        if request.is_some() || PIN_DESCRIPTION.lines().any(|known| known == line) {
            return Ok(request);
        }
        const PREFIX: &str = "Recovery word ";
        const MIDDLE: &str = ", character ";
        const SUFFIX: &str = " (letter/space/backspace/done):";
        if let Some(value) = line
            .strip_prefix(PREFIX)
            .and_then(|line| line.strip_suffix(SUFFIX))
        {
            let (word, character) = value
                .split_once(MIDDLE)
                .context("invalid KeepKey recovery prompt")?;
            return Ok(Some(HostRequest::RecoveryCharacter {
                word_position: word.parse().context("invalid recovery word position")?,
                character_position: character
                    .parse()
                    .context("invalid recovery character position")?,
            }));
        }
        bail!("unexpected KeepKey host prompt")
    }

    fn run_candidate_keepkey_interactive(command: &[&str]) -> Result<KeepKeyInteractiveOutput> {
        let binary = HwiBinary::candidate()?;
        let args = keepkey_args(command);
        let runtime = keepkey_runtime()?;
        let mut interaction = runtime.block_on(KeepKeyHostInteraction::connect_default(
            KEEPKEY_PIN,
            SYNTHETIC_MNEMONIC,
        ))?;
        let mut child = Command::new(&binary.path)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn candidate KeepKey hwi")?;
        let timeout = command_timeout();
        let deadline = Instant::now() + timeout;
        let approval = spawn_debug_approval(KEEPKEY_DEBUGLINK_ADDR, DebugButton::Yes, deadline);
        let mut stdin = child.stdin.take().context("missing candidate hwi stdin")?;
        let stdout = child
            .stdout
            .take()
            .context("missing candidate hwi stdout")?;
        let stderr = child
            .stderr
            .take()
            .context("missing candidate hwi stderr")?;
        let stdout = reader_thread(Some(stdout));
        let (prompt_status_tx, prompt_status_rx) = mpsc::channel();
        let prompt = std::thread::spawn(move || {
            let interaction_result = (|| -> Result<_> {
                let mut reader = BufReader::new(stderr);
                let mut line = String::new();
                let mut pin_kinds = Vec::new();
                let mut recovery_requests = 0;
                loop {
                    line.clear();
                    if reader.read_line(&mut line)? == 0 {
                        return Ok((pin_kinds, recovery_requests));
                    }
                    let line = line.trim_end_matches(['\r', '\n']);
                    let Some(request) = keepkey_prompt_request(line)? else {
                        continue;
                    };
                    match &request {
                        bhwi::common::HostRequest::PinMatrix { kind } => pin_kinds.push(*kind),
                        bhwi::common::HostRequest::RecoveryCharacter { .. } => {
                            recovery_requests += 1;
                        }
                    }
                    let response = runtime
                        .block_on(interaction.response_line(&request))
                        .map_err(|_| anyhow::anyhow!("failed to answer KeepKey host prompt"))?;
                    stdin
                        .write_all(response.as_bytes())
                        .context("write KeepKey host response")?;
                    stdin.flush().context("flush KeepKey host response")?;
                }
            })();
            let _ = prompt_status_tx.send(interaction_result.is_err());
            interaction_result
        });

        let mut prompt_reported = false;
        let mut prompt_cancelled = false;
        let wait = wait_for_child(&mut child, deadline, || {
            if prompt_reported {
                return prompt_cancelled;
            }
            match prompt_status_rx.try_recv() {
                Ok(failed) => {
                    prompt_reported = true;
                    prompt_cancelled = failed;
                    failed
                }
                Err(mpsc::TryRecvError::Empty) => false,
                Err(mpsc::TryRecvError::Disconnected) => {
                    prompt_cancelled = true;
                    true
                }
            }
        });
        drop(approval);
        let stdout_bytes = join_reader(stdout);
        let interaction_result = match prompt.join() {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!("candidate KeepKey prompt worker panicked")),
        };
        let status = wait.context("wait for candidate KeepKey hwi")?;
        let status = match status {
            Some(status) => status,
            None if prompt_cancelled => match interaction_result {
                Err(error) => return Err(error),
                Ok(_) => bail!("candidate KeepKey prompt worker stopped"),
            },
            None => {
                let diagnostic_args = args
                    .iter()
                    .map(|arg| OsString::from(arg.as_str()))
                    .collect::<Vec<_>>();
                return Err(timeout_error(
                    "candidate",
                    &diagnostic_args,
                    timeout,
                    &stdout_bytes,
                    &[],
                ));
            }
        };
        let (pin_kinds, recovery_requests) = interaction_result?;
        let output = parse_output(
            "candidate",
            Output {
                status,
                stdout: stdout_bytes,
                stderr: Vec::new(),
            },
        )?;
        assert_success("candidate", &output)?;

        Ok(KeepKeyInteractiveOutput {
            output,
            pin_kinds,
            recovery_requests,
        })
    }

    fn run_candidate_keepkey_approved(command: &[&str]) -> Result<HwiOutput> {
        let approval = spawn_debug_approval(
            KEEPKEY_DEBUGLINK_ADDR,
            DebugButton::Yes,
            Instant::now() + command_timeout(),
        );
        let output = HwiBinary::candidate()?.run(keepkey_args(command));
        drop(approval);
        let output = output?;
        assert_success("candidate", &output)?;
        Ok(output)
    }

    fn keepkey_debug_pin() -> Result<String> {
        keepkey_runtime()?.block_on(async {
            KeepKeyDebugLink::connect_default()
                .await?
                .pin_positions(KEEPKEY_PIN)
                .await
                .map_err(anyhow::Error::from)
        })
    }

    fn lock_keepkey_device() -> Result<()> {
        keepkey_runtime()?.block_on(lock_keepkey(KEEPKEY_MAIN_ADDR))?;
        Ok(())
    }

    fn candidate_keepkey_send_pin(positions: String) -> Result<HwiOutput> {
        let mut args = keepkey_args(&["sendpin"]);
        args.push(positions);
        let output = HwiBinary::candidate()?.run(args)?;
        assert_success("candidate", &output)?;
        Ok(output)
    }

    fn keepkey_enumerate_args(password: Option<&str>) -> Vec<String> {
        let mut args = args(["--emulators", "--chain", "test"]);
        if let Some(password) = password {
            args.extend(["--password".to_owned(), password.to_owned()]);
        }
        args.extend([
            "--device-type".to_owned(),
            "keepkey".to_owned(),
            "--device-path".to_owned(),
            KEEPKEY_MAIN_ADDR.to_owned(),
            "enumerate".to_owned(),
        ]);
        args
    }

    fn candidate_keepkey_enumerate(password: Option<&str>) -> Result<HwiOutput> {
        let approval = spawn_debug_approval(
            KEEPKEY_DEBUGLINK_ADDR,
            DebugButton::Yes,
            Instant::now() + command_timeout(),
        );
        let output = HwiBinary::candidate()?.run(keepkey_enumerate_args(password));
        drop(approval);
        let output = output?;
        assert_success("candidate", &output)?;
        Ok(output)
    }

    #[test]
    fn keepkey_prompt_markers_are_exact() -> Result<()> {
        use bhwi::common::{HostRequest, PinMatrixRequestKind};
        assert_eq!(
            keepkey_prompt_request("Enter new PIN positions:")?,
            Some(HostRequest::PinMatrix {
                kind: PinMatrixRequestKind::NewFirst,
            })
        );
        assert_eq!(
            keepkey_prompt_request("Recovery word 3, character 4 (letter/space/backspace/done):")?,
            Some(HostRequest::RecoveryCharacter {
                word_position: 3,
                character_position: 4,
            })
        );
        assert!(keepkey_prompt_request("unexpected").is_err());
        Ok(())
    }
    fn candidate_keepkey_fingerprint(output: &HwiOutput) -> Result<&str> {
        let device = assert_enumerate_contains_device("candidate", &output.json, "keepkey")?;
        assert_string_field("candidate", device, "fingerprint")
    }

    #[test]
    #[ignore = "requires a fresh KeepKey emulator image"]
    fn candidate_keepkey_management_lifecycle() -> Result<()> {
        use bhwi::common::PinMatrixRequestKind;

        if env::var("HWI_BIN").is_err()
            || expected_device_type_from_env()?.as_deref() != Some("keepkey")
        {
            return Ok(());
        }
        let setup = run_candidate_keepkey_interactive(&[
            "--interactive",
            "setup",
            "--label",
            "BHWI KeepKey Parity",
        ])?;
        assert_success("candidate", &setup.output)?;
        assert_eq!(setup.output.json, serde_json::json!({"success": true}));
        assert_eq!(
            setup.pin_kinds.as_slice(),
            &[
                PinMatrixRequestKind::NewFirst,
                PinMatrixRequestKind::NewSecond
            ]
        );
        let enumerated = candidate_keepkey_enumerate(None)?;
        let device = assert_enumerate_contains_device("candidate", &enumerated.json, "keepkey")?;
        assert_eq!(device["label"], "BHWI KeepKey Parity");

        let wiped = run_candidate_keepkey_approved(&["wipe"])?;
        assert_success("candidate", &wiped)?;
        assert_eq!(wiped.json, serde_json::json!({"success": true}));
        let restored = run_candidate_keepkey_interactive(&[
            "--interactive",
            "restore",
            "--label",
            "BHWI KeepKey Parity Restored",
            "--word_count",
            "12",
        ])?;
        assert_success("candidate", &restored.output)?;
        assert_eq!(restored.output.json, serde_json::json!({"success": true}));
        assert_eq!(
            restored.pin_kinds.as_slice(),
            &[
                PinMatrixRequestKind::NewFirst,
                PinMatrixRequestKind::NewSecond
            ]
        );
        assert!(restored.recovery_requests >= 12);
        let enumerated = candidate_keepkey_enumerate(None)?;
        let device = assert_enumerate_contains_device("candidate", &enumerated.json, "keepkey")?;
        assert_eq!(device["fingerprint"], KEEPKEY_FINGERPRINT);
        assert_eq!(device["label"], "BHWI KeepKey Parity Restored");

        lock_keepkey_device()?;
        let locked = candidate_keepkey_enumerate(None)?;
        let device = assert_enumerate_contains_device("candidate", &locked.json, "keepkey")?;
        assert_eq!(device["code"], -12);
        assert_eq!(
            device["error"],
            "Keepkey is locked. Unlock by using 'promptpin' and then 'sendpin'."
        );
        let prompt = HwiBinary::candidate()?.run(keepkey_args(&["promptpin"]))?;
        assert_success("candidate", &prompt)?;
        assert_eq!(prompt.json, serde_json::json!({"success": true}));
        let correct = candidate_keepkey_send_pin(keepkey_debug_pin()?)?;
        assert_success("candidate", &correct)?;
        assert_eq!(correct.json, serde_json::json!({"success": true}));

        lock_keepkey_device()?;
        let toggle = run_candidate_keepkey_approved(&["togglepassphrase"])?;
        assert_eq!(toggle.json, serde_json::json!({"success": true}));
        let correct = candidate_keepkey_send_pin(keepkey_debug_pin()?)?;
        assert_success("candidate", &correct)?;
        assert_eq!(correct.json, serde_json::json!({"success": true}));
        let missing = candidate_keepkey_enumerate(None)?;
        let device = assert_enumerate_contains_device("candidate", &missing.json, "keepkey")?;
        assert_eq!(device["code"], -12);
        assert_eq!(
            device["error"],
            "Passphrase needs to be specified before the fingerprint information can be retrieved"
        );
        let empty = candidate_keepkey_enumerate(Some(""))?;
        let first = candidate_keepkey_enumerate(Some("fixture-passphrase-one"))?;
        let second = candidate_keepkey_enumerate(Some("fixture-passphrase-two"))?;
        assert_success("candidate", &empty)?;
        assert_success("candidate", &first)?;
        assert_success("candidate", &second)?;
        assert_eq!(candidate_keepkey_fingerprint(&empty)?, KEEPKEY_FINGERPRINT);
        assert_ne!(candidate_keepkey_fingerprint(&first)?, KEEPKEY_FINGERPRINT);
        assert_ne!(candidate_keepkey_fingerprint(&second)?, KEEPKEY_FINGERPRINT);
        assert_ne!(
            candidate_keepkey_fingerprint(&first)?,
            candidate_keepkey_fingerprint(&second)?
        );

        lock_keepkey_device()?;
        let toggle = run_candidate_keepkey_approved(&["togglepassphrase"])?;
        assert_eq!(toggle.json, serde_json::json!({"success": true}));
        let correct = candidate_keepkey_send_pin(keepkey_debug_pin()?)?;
        assert_success("candidate", &correct)?;
        assert_eq!(correct.json, serde_json::json!({"success": true}));
        let final_state = candidate_keepkey_enumerate(Some("ignored-when-disabled"))?;
        assert_eq!(
            candidate_keepkey_fingerprint(&final_state)?,
            KEEPKEY_FINGERPRINT
        );
        lock_keepkey_device()?;
        let prompt = HwiBinary::candidate()?.run(keepkey_args(&["promptpin"]))?;
        assert_success("candidate", &prompt)?;
        assert_eq!(prompt.json, serde_json::json!({"success": true}));
        let wrong = candidate_keepkey_send_pin("1111".into())?;
        assert_success("candidate", &wrong)?;
        assert_eq!(wrong.json, serde_json::json!({"success": false}));

        lock_keepkey_device()?;
        let prompt = HwiBinary::candidate()?.run(keepkey_args(&["promptpin"]))?;
        assert_success("candidate", &prompt)?;
        assert_eq!(prompt.json, serde_json::json!({"success": true}));
        let correct = candidate_keepkey_send_pin(keepkey_debug_pin()?)?;
        assert_success("candidate", &correct)?;
        assert_eq!(correct.json, serde_json::json!({"success": true}));
        let recovered = candidate_keepkey_enumerate(None)?;
        let device = assert_enumerate_contains_device("candidate", &recovered.json, "keepkey")?;
        assert_eq!(device["fingerprint"], KEEPKEY_FINGERPRINT);
        assert_eq!(device["needs_pin_sent"], false);

        Ok(())
    }

    struct RemoveDirectoryOnDrop(PathBuf);

    impl Drop for RemoveDirectoryOnDrop {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    #[ignore = "requires a fresh uninitialized KeepKey emulator"]
    fn reference_keepkey_restore_probe() -> Result<()> {
        if env::var("REFERENCE_HWI_BIN").is_err()
            || expected_device_type_from_env()?.as_deref() != Some("keepkey")
        {
            return Ok(());
        }

        let expected_uninitialized = serde_json::json!([{
            "type": "keepkey",
            "model": "keepkey_simulator",
            "path": KEEPKEY_MAIN_ADDR,
            "label": null,
            "needs_pin_sent": false,
            "needs_passphrase_sent": false,
            "error": "Not initialized",
            "code": -18
        }]);
        let reference = HwiBinary::reference()?;
        let before = reference.run(keepkey_enumerate_args(None))?;
        assert_success("reference", &before)?;
        assert_eq!(before.json, expected_uninitialized);

        let hook_dir = RemoveDirectoryOnDrop(temp_path("reference-keepkey-pin-hook")?);
        fs::write(
            hook_dir.0.join("sitecustomize.py"),
            r#"from hwilib.devices.trezorlib.debuglink import TrezorClientDebugLink

_original_init = TrezorClientDebugLink.__init__

def _init_with_pin_sequence(self, *args, **kwargs):
    _original_init(self, *args, **kwargs)
    self.use_pin_sequence(("1", "1"))

TrezorClientDebugLink.__init__ = _init_with_pin_sequence
"#,
        )
        .context("write pinned HWI KeepKey debug PIN hook")?;
        let mut python_paths = vec![hook_dir.0.clone()];
        if let Some(existing) = env::var_os("PYTHONPATH") {
            python_paths.extend(env::split_paths(&existing));
        }
        let pythonpath = env::join_paths(python_paths).context("build pinned HWI Python path")?;
        let process_env = [(OsString::from("PYTHONPATH"), pythonpath)];
        let recovery_words = format!("{}\n", SYNTHETIC_MNEMONIC.replace(' ', "\n"));
        let output = reference.run_with_stdin_and_envs(
            keepkey_args(&["--interactive", "restore", "--word_count", "12"]),
            &recovery_words,
            &process_env,
        )?;
        assert_success("reference", &output)?;
        assert_eq!(output.json, serde_json::json!({"error": "80", "code": -13}));

        let after = reference.run(keepkey_enumerate_args(None))?;
        assert_success("reference", &after)?;
        assert_eq!(after.json, expected_uninitialized);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn candidate_installudevrules_matches_reference_or_avoids_getlogin_failure() -> Result<()> {
        if env::var("HWI_BIN").is_err() {
            return Ok(());
        }

        let temp = temp_path("installudevrules")?;
        let fake_bin = temp.join("bin");
        let reference_rules = temp.join("reference-rules.d");
        let candidate_rules = temp.join("candidate-rules.d");
        fs::create_dir_all(&fake_bin)?;
        fs::create_dir_all(&reference_rules)?;
        fs::create_dir_all(&candidate_rules)?;
        write_fake_command(&fake_bin.join("udevadm"), 0)?;
        write_fake_command(&fake_bin.join("groupadd"), 0)?;
        write_fake_command(&fake_bin.join("usermod"), 0)?;

        let original_path = env::var("PATH").unwrap_or_default();
        let test_path = format!("{}:{original_path}", fake_bin.display());
        let envs = [("PATH", test_path.as_str()), ("USER", "bhwi-test")];

        let reference = HwiBinary::reference()?.run_with_envs(
            args([
                "installudevrules",
                "--location",
                reference_rules
                    .to_str()
                    .context("reference rules path is not utf8")?,
            ]),
            &envs,
        )?;
        let reference_getlogin_failure = is_upstream_getlogin_failure(&reference.json);
        if !reference_getlogin_failure {
            assert_success("reference", &reference)?;
        }

        let candidate = HwiBinary::candidate()?.run_with_envs(
            args([
                "installudevrules",
                "--location",
                candidate_rules
                    .to_str()
                    .context("candidate rules path is not utf8")?,
            ]),
            &envs,
        )?;
        assert_success("candidate", &candidate)?;

        if !reference_getlogin_failure && reference.json != candidate.json {
            bail!(
                "HWI installudevrules JSON mismatch\nreference:\n{}\ncandidate:\n{}",
                serde_json::to_string_pretty(&reference.json)?,
                serde_json::to_string_pretty(&candidate.json)?
            );
        }

        assert_udev_rule_dirs_match(&reference_rules, &candidate_rules)?;
        fs::remove_dir_all(temp).ok();
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn is_upstream_getlogin_failure(json: &Value) -> bool {
        json.get("code").and_then(Value::as_i64) == Some(-13)
            && json
                .get("error")
                .and_then(Value::as_str)
                .is_some_and(|error| {
                    error.starts_with("installudevrules failed: [Errno ")
                        && (error.contains("Inappropriate ioctl for device")
                            || error.contains("No such device or address"))
                })
    }

    fn assert_enumerate_parity(
        args: Vec<String>,
        expected_device_type: Option<&str>,
    ) -> Result<()> {
        let reference = HwiBinary::reference()?.run(args.clone())?;
        assert_success("reference", &reference)?;
        assert_enumerate_array("reference", &reference.json)?;

        let candidate = HwiBinary::candidate()?.run(args)?;
        assert_success("candidate", &candidate)?;
        assert_enumerate_array("candidate", &candidate.json)?;

        if let Some(device_type) = expected_device_type {
            let reference_device =
                assert_enumerate_contains_device("reference", &reference.json, device_type)?;
            let candidate_device =
                assert_enumerate_contains_device("candidate", &candidate.json, device_type)?;
            assert_enumerate_device_shape("reference", reference_device, None)?;
            assert_enumerate_device_shape("candidate", candidate_device, Some(reference_device))?;
        }

        if reference.json != candidate.json {
            bail!(
                "HWI JSON mismatch\nreference:\n{}\ncandidate:\n{}",
                serde_json::to_string_pretty(&reference.json)?,
                serde_json::to_string_pretty(&candidate.json)?
            );
        }

        Ok(())
    }

    fn assert_getmasterxpub_parity(args: Vec<String>) -> Result<()> {
        let reference = HwiBinary::reference()?.run(args.clone())?;
        assert_success("reference", &reference)?;
        assert_xpub_only_shape("reference", "getmasterxpub", &reference.json)?;

        let candidate = HwiBinary::candidate()?.run(args)?;
        assert_success("candidate", &candidate)?;
        assert_xpub_only_shape("candidate", "getmasterxpub", &candidate.json)?;

        if reference.json != candidate.json {
            bail!(
                "HWI getmasterxpub JSON mismatch\nreference:\n{}\ncandidate:\n{}",
                serde_json::to_string_pretty(&reference.json)?,
                serde_json::to_string_pretty(&candidate.json)?
            );
        }

        Ok(())
    }

    fn assert_getxpub_parity(args: Vec<String>) -> Result<()> {
        let expert = args.iter().any(|arg| arg == "--expert");
        let reference = HwiBinary::reference()?.run(args.clone())?;
        assert_success("reference", &reference)?;
        assert_getxpub_shape("reference", &reference.json, expert)?;

        let candidate = HwiBinary::candidate()?.run(args)?;
        assert_success("candidate", &candidate)?;
        assert_getxpub_shape("candidate", &candidate.json, expert)?;

        if reference.json != candidate.json {
            bail!(
                "HWI getxpub JSON mismatch\nreference:\n{}\ncandidate:\n{}",
                serde_json::to_string_pretty(&reference.json)?,
                serde_json::to_string_pretty(&candidate.json)?
            );
        }

        Ok(())
    }

    fn assert_getdescriptors_parity(args: Vec<String>) -> Result<()> {
        let reference = HwiBinary::reference()?.run(args.clone())?;
        assert_success("reference", &reference)?;
        assert_getdescriptors_shape("reference", &reference.json)?;

        let candidate = HwiBinary::candidate()?.run(args)?;
        assert_success("candidate", &candidate)?;
        assert_getdescriptors_shape("candidate", &candidate.json)?;

        if reference.json != candidate.json {
            bail!(
                "HWI getdescriptors JSON mismatch\nreference:\n{}\ncandidate:\n{}",
                serde_json::to_string_pretty(&reference.json)?,
                serde_json::to_string_pretty(&candidate.json)?
            );
        }

        Ok(())
    }

    fn assert_getkeypool_parity(args: Vec<String>) -> Result<()> {
        let reference = HwiBinary::reference()?.run(args.clone())?;
        assert_success("reference", &reference)?;
        assert_getkeypool_shape("reference", &reference.json)?;

        let candidate = HwiBinary::candidate()?.run(args)?;
        assert_success("candidate", &candidate)?;
        assert_getkeypool_shape("candidate", &candidate.json)?;

        if reference.json != candidate.json {
            bail!(
                "HWI getkeypool JSON mismatch\nreference:\n{}\ncandidate:\n{}",
                serde_json::to_string_pretty(&reference.json)?,
                serde_json::to_string_pretty(&candidate.json)?
            );
        }

        Ok(())
    }

    /// Usage-error text is not compared across sides: the reference reports the nix
    /// store script as its program name and lists argparse-specific choices.
    fn assert_usage_error_parity(args: Vec<String>) -> Result<()> {
        for binary in [HwiBinary::reference()?, HwiBinary::candidate()?] {
            let output = binary.run_raw(args.clone())?;
            if output.status_code != Some(2) {
                bail!(
                    "{} hwi did not exit 2 for a usage error\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
                    binary.label,
                    output.status_code,
                    output.stdout,
                    output.stderr
                );
            }

            let json: Value = serde_json::from_str(output.stdout.trim()).with_context(|| {
                format!(
                    "{} hwi usage error stdout was not JSON\nstdout:\n{}\nstderr:\n{}",
                    binary.label, output.stdout, output.stderr
                )
            })?;
            assert_error_shape(binary.label, &json)?;
            if json.get("code").and_then(Value::as_i64) != Some(-2) {
                bail!(
                    "{} hwi usage error code was not -2:\n{}",
                    binary.label,
                    serde_json::to_string_pretty(&json)?
                );
            }
            if json
                .get("error")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                bail!(
                    "{} hwi usage error message was empty:\n{}",
                    binary.label,
                    serde_json::to_string_pretty(&json)?
                );
            }

            if !output.stderr.to_lowercase().contains("usage:") {
                bail!(
                    "{} hwi usage error stderr had no usage text\nstderr:\n{}",
                    binary.label,
                    output.stderr
                );
            }
        }

        Ok(())
    }

    fn assert_error_json_parity(args: Vec<String>) -> Result<()> {
        let reference = HwiBinary::reference()?.run(args.clone())?;
        let candidate = HwiBinary::candidate()?.run(args)?;

        assert_success("reference", &reference)?;
        assert_success("candidate", &candidate)?;

        assert_error_shape("reference", &reference.json)?;
        assert_error_shape("candidate", &candidate.json)?;

        if reference.json != candidate.json {
            bail!(
                "HWI error JSON mismatch\nreference:\n{}\ncandidate:\n{}",
                serde_json::to_string_pretty(&reference.json)?,
                serde_json::to_string_pretty(&candidate.json)?
            );
        }

        Ok(())
    }

    fn assert_signmessage_parity(args: Vec<String>, case: &SignMessageCase) -> Result<()> {
        let device_type = arg_value(&args, "--device-type").map(str::to_owned);
        let approval = prepare_signmessage_run(&args)?;
        let reference = HwiBinary::reference()?.run(args.clone())?;
        drop(approval);
        assert_success("reference", &reference)?;
        assert_signmessage_shape("reference", &reference.json)?;
        let reference_payload = signmessage_payload("reference", &reference.json)?;
        signature::verify_message_signature(&case.pubkey, case.message, &reference_payload)
            .context("reference hwi signmessage signature failed cryptographic verification")?;

        let approval = prepare_signmessage_run(&args)?;
        let candidate = HwiBinary::candidate()?.run(args)?;
        drop(approval);
        assert_success("candidate", &candidate)?;
        assert_signmessage_shape("candidate", &candidate.json)?;
        let candidate_payload = signmessage_payload("candidate", &candidate.json)?;
        signature::verify_message_signature(&case.pubkey, case.message, &candidate_payload)
            .context("candidate hwi signmessage signature failed cryptographic verification")?;

        // BitBox02 signatures are nondeterministic, so both sides only have to verify.
        if device_type.as_deref() == Some("bitbox02") {
            return Ok(());
        }

        if reference.json != candidate.json {
            bail!(
                "HWI signmessage JSON mismatch\nreference:\n{}\ncandidate:\n{}",
                serde_json::to_string_pretty(&reference.json)?,
                serde_json::to_string_pretty(&candidate.json)?
            );
        }

        Ok(())
    }

    fn assert_displayaddress_parity(case: &DisplayAddressCase) -> Result<()> {
        let approval = prepare_displayaddress_case_run(case)?;
        let reference = HwiBinary::reference()?.run(case.args.clone())?;
        drop(approval);
        assert_displayaddress_result(
            "reference",
            &reference,
            if case.candidate_only_error.is_some() {
                ExpectedResult::Success
            } else {
                case.expect
            },
        )?;

        let approval = prepare_displayaddress_case_run(case)?;
        let candidate = HwiBinary::candidate()?.run(case.args.clone())?;
        drop(approval);
        if let Some(expected) = case.candidate_only_error {
            assert_success("candidate", &candidate)?;
            if candidate.json != expected.json() {
                bail!(
                    "candidate hwi displayaddress error mismatch\nexpected:\n{}\ngot:\n{}",
                    serde_json::to_string_pretty(&expected.json())?,
                    serde_json::to_string_pretty(&candidate.json)?
                );
            }
        } else {
            assert_displayaddress_result("candidate", &candidate, case.expect)?;
            if reference.json != candidate.json {
                bail!(
                    "HWI displayaddress JSON mismatch\nreference:\n{}\ncandidate:\n{}",
                    serde_json::to_string_pretty(&reference.json)?,
                    serde_json::to_string_pretty(&candidate.json)?
                );
            }
        }

        Ok(())
    }

    fn assert_displayaddress_result(
        label: &str,
        output: &HwiOutput,
        expect: ExpectedResult,
    ) -> Result<()> {
        match expect {
            ExpectedResult::Success => {
                assert_success(label, output)?;
                assert_displayaddress_shape(label, &output.json)
            }
            ExpectedResult::Error => {
                assert_success(label, output)?;
                assert_error_shape(label, &output.json)
            }
        }
    }

    fn assert_signtx_parity(args: Vec<String>, case: &SigntxCase) -> Result<()> {
        let approval = prepare_signtx_run(&args, case)?;
        let reference = HwiBinary::reference()?.run(args.clone())?;
        drop(approval);
        assert_success("reference", &reference)?;
        assert_signtx_shape("reference", &reference.json)?;
        let reference_psbt = assert_signed_psbt("reference", &reference.json, case)?;
        if arg_value(&args, "--device-type") == Some("keepkey") {
            separate_keepkey_signtx_runs()?;
        }

        let approval = prepare_signtx_run(&args, case)?;
        let candidate = HwiBinary::candidate()?.run(args)?;
        drop(approval);
        assert_success("candidate", &candidate)?;
        assert_signtx_shape("candidate", &candidate.json)?;
        let candidate_psbt = assert_signed_psbt("candidate", &candidate.json, case)?;

        assert_eq!(reference.json["signed"], candidate.json["signed"]);
        signature::assert_psbt_parity(&reference_psbt, &candidate_psbt)
            .context("reference and candidate signed PSBTs diverged")?;

        Ok(())
    }

    // KeepKey retains its transaction-input digest after internal-change and canceled
    // confirmations. Separate reference and candidate signing with two external outputs;
    // the second amount differs whether the first reset succeeds or hits retained state.
    fn separate_keepkey_signtx_runs() -> Result<()> {
        let mut separator = build_singlesig_signtx_case("keepkey", LedgerSinglesigWrapper::Legacy)?;
        separator
            .original
            .outputs
            .first_mut()
            .context("KeepKey signing separator has no output map")?
            .bip32_derivation
            .clear();

        for (attempt, value) in [48_000, 47_000].into_iter().enumerate() {
            separator
                .original
                .unsigned_tx
                .output
                .first_mut()
                .context("KeepKey signing separator has no transaction output")?
                .value = Amount::from_sat(value);
            separator.psbt = separator.original.to_string();
            let args = signtx_args("keepkey", &separator.psbt);
            let approval = prepare_signtx_run(&args, &separator)?;
            let output = HwiBinary::candidate()?.run(args);
            drop(approval);
            let output = output?;
            assert_success("candidate", &output)?;
            if attempt == 0
                && output.json
                    == serde_json::json!({"error": "authentication refused", "code": -14})
            {
                continue;
            }
            assert_signtx_shape("candidate", &output.json)?;
            assert_signed_psbt("candidate", &output.json, &separator)?;
        }
        Ok(())
    }

    fn assert_enumerate_stdin_parity(device_type: &str) -> Result<()> {
        let stdin = format!("--emulators --device-type {device_type} enumerate\n\n");
        let reference = HwiBinary::reference()?.run_with_stdin(["--stdin"], &stdin)?;
        assert_success("reference", &reference)?;
        assert_enumerate_array("reference", &reference.json)?;
        let reference_device =
            assert_enumerate_contains_device("reference", &reference.json, device_type)?;
        assert_enumerate_device_shape("reference", reference_device, None)?;

        let candidate = HwiBinary::candidate()?.run_with_stdin(["--stdin"], &stdin)?;
        assert_success("candidate", &candidate)?;
        assert_enumerate_array("candidate", &candidate.json)?;
        let candidate_device =
            assert_enumerate_contains_device("candidate", &candidate.json, device_type)?;
        assert_enumerate_device_shape("candidate", candidate_device, Some(reference_device))?;

        if reference.json != candidate.json {
            bail!(
                "HWI JSON mismatch for stdin enumerate\nreference:\n{}\ncandidate:\n{}",
                serde_json::to_string_pretty(&reference.json)?,
                serde_json::to_string_pretty(&candidate.json)?
            );
        }

        Ok(())
    }

    fn assert_signmessage_shape(label: &str, json: &Value) -> Result<()> {
        assert_exact_keys(label, "signmessage", json, &["signature"])?;
        let decoded = signmessage_payload(label, json)?;
        if decoded.len() != 65 {
            bail!(
                "{label} hwi signmessage signature was {} bytes, expected 65:\n{}",
                decoded.len(),
                serde_json::to_string_pretty(json)?
            );
        }
        Ok(())
    }

    fn signmessage_payload(label: &str, json: &Value) -> Result<Vec<u8>> {
        let signature = assert_string_json_field(label, json, "signature")?;
        BASE64_STANDARD
            .decode(signature)
            .with_context(|| format!("{label} hwi signmessage signature was not base64"))
    }

    fn assert_displayaddress_shape(label: &str, json: &Value) -> Result<()> {
        assert_exact_keys(label, "displayaddress", json, &["address"])?;
        assert_string_json_field(label, json, "address")?;
        Ok(())
    }

    fn assert_getdescriptors_shape(label: &str, json: &Value) -> Result<()> {
        assert_exact_keys(label, "getdescriptors", json, &["receive", "internal"])?;
        for field in ["receive", "internal"] {
            let Some(descriptors) = json.get(field).and_then(Value::as_array) else {
                bail!(
                    "{label} hwi getdescriptors field {field:?} was not an array:\n{}",
                    serde_json::to_string_pretty(json)?
                );
            };
            if descriptors.is_empty() {
                bail!(
                    "{label} hwi getdescriptors field {field:?} was empty:\n{}",
                    serde_json::to_string_pretty(json)?
                );
            }
            for descriptor in descriptors {
                let Some(descriptor) = descriptor.as_str() else {
                    bail!(
                        "{label} hwi getdescriptors field {field:?} contained a non-string:\n{}",
                        serde_json::to_string_pretty(json)?
                    );
                };
                if !descriptor.contains('#') || !descriptor.contains("/*") {
                    bail!(
                        "{label} hwi getdescriptors descriptor was not ranged with checksum: {descriptor}"
                    );
                }
                if descriptor.contains('\'') {
                    bail!(
                        "{label} hwi getdescriptors descriptor used apostrophe hardening instead of h: {descriptor}"
                    );
                }
            }
        }
        Ok(())
    }

    fn assert_getkeypool_shape(label: &str, json: &Value) -> Result<()> {
        let Some(entries) = json.as_array() else {
            bail!(
                "{label} hwi getkeypool output was not an array:\n{}",
                serde_json::to_string_pretty(json)?
            );
        };
        if entries.is_empty() {
            bail!(
                "{label} hwi getkeypool output was empty:\n{}",
                serde_json::to_string_pretty(json)?
            );
        }

        for entry in entries {
            assert_exact_keys(
                label,
                "getkeypool entry",
                entry,
                &[
                    "desc",
                    "range",
                    "timestamp",
                    "internal",
                    "keypool",
                    "active",
                    "watchonly",
                ],
            )?;
            let descriptor = assert_string_json_field(label, entry, "desc")?;
            if !descriptor.contains('#') || !descriptor.contains("/*") {
                bail!(
                    "{label} hwi getkeypool descriptor was not ranged with checksum: {descriptor}"
                );
            }
            if descriptor.contains('\'') {
                bail!(
                    "{label} hwi getkeypool descriptor used apostrophe hardening instead of h: {descriptor}"
                );
            }
            assert_range_field(label, entry)?;
            if entry.get("timestamp").and_then(Value::as_str) != Some("now") {
                bail!(
                    "{label} hwi getkeypool timestamp was not \"now\":\n{}",
                    serde_json::to_string_pretty(entry)?
                );
            }
            for field in ["internal", "keypool", "active", "watchonly"] {
                if entry.get(field).and_then(Value::as_bool).is_none() {
                    bail!(
                        "{label} hwi getkeypool field {field:?} was not a bool:\n{}",
                        serde_json::to_string_pretty(entry)?
                    );
                }
            }
            if entry.get("active") != entry.get("keypool") {
                bail!(
                    "{label} hwi getkeypool active did not match keypool:\n{}",
                    serde_json::to_string_pretty(entry)?
                );
            }
            if entry.get("watchonly").and_then(Value::as_bool) != Some(true) {
                bail!(
                    "{label} hwi getkeypool watchonly was not true:\n{}",
                    serde_json::to_string_pretty(entry)?
                );
            }
        }

        Ok(())
    }

    fn assert_signtx_shape(label: &str, json: &Value) -> Result<()> {
        let object = json
            .as_object()
            .with_context(|| format!("{label} hwi signtx output was not an object"))?;
        let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();
        if keys != ["psbt", "signed"] {
            bail!("{label} hwi signtx keys did not match");
        }
        if json
            .get("psbt")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            bail!("{label} hwi signtx field \"psbt\" was not a nonempty string");
        }
        if json.get("signed").and_then(Value::as_bool).is_none() {
            bail!("{label} hwi signtx field \"signed\" was not a bool");
        }
        Ok(())
    }

    fn assert_signed_psbt(label: &str, json: &Value, case: &SigntxCase) -> Result<Psbt> {
        if json.get("signed").and_then(Value::as_bool) != Some(true) {
            bail!("{label} hwi signtx did not report signed=true");
        }
        let signed_psbt = assert_string_json_field(label, json, "psbt")?;
        let signed_psbt = Psbt::from_str(signed_psbt)
            .with_context(|| format!("{label} hwi signtx returned invalid PSBT"))?;
        if signed_psbt.unsigned_tx != case.original.unsigned_tx {
            bail!("{label} hwi signtx changed the unsigned transaction");
        }
        if signed_psbt.inputs.len() != case.original.inputs.len() {
            bail!("{label} hwi signtx changed the input count");
        }
        for expected in &case.expected_signatures {
            assert_expected_signature(label, &signed_psbt, case, *expected)?;
        }
        Ok(signed_psbt)
    }

    fn assert_expected_signature(
        label: &str,
        signed: &Psbt,
        case: &SigntxCase,
        expected: ExpectedSignature,
    ) -> Result<()> {
        let input = &signed.inputs[expected.input_index];
        match expected.kind {
            ExpectedSignatureKind::Ecdsa => {
                let signature = input.partial_sigs.get(&expected.pubkey).with_context(|| {
                    format!(
                        "{label} hwi signtx did not add the expected device signature to input {}",
                        expected.input_index
                    )
                })?;
                if case.verify_signatures {
                    let mut cache = SighashCache::new(&case.original.unsigned_tx);
                    let (message, sighash_type) = case
                        .original
                        .sighash_ecdsa(expected.input_index, &mut cache)
                        .with_context(|| {
                            format!("calculate input {} sighash", expected.input_index)
                        })?;
                    if signature.sighash_type != sighash_type {
                        bail!(
                            "{label} hwi signtx used an unexpected sighash type on input {}",
                            expected.input_index
                        );
                    }
                    Secp256k1::verification_only()
                        .verify_ecdsa(&message, &signature.signature, &expected.pubkey.inner)
                        .with_context(|| {
                            format!(
                                "{label} hwi signtx returned an invalid signature on input {}",
                                expected.input_index
                            )
                        })?;
                }
            }
            ExpectedSignatureKind::TapKey => {
                let signature = input.tap_key_sig.as_ref().with_context(|| {
                    format!(
                        "{label} hwi signtx did not add the expected taproot signature to input {}",
                        expected.input_index
                    )
                })?;
                if case.verify_signatures {
                    let prevouts = case
                        .original
                        .inputs
                        .iter()
                        .enumerate()
                        .map(|(index, _)| case.original.spend_utxo(index).cloned())
                        .collect::<std::result::Result<Vec<_>, _>>()?;
                    let sighash = SighashCache::new(&case.original.unsigned_tx)
                        .taproot_key_spend_signature_hash(
                            expected.input_index,
                            &Prevouts::All(&prevouts),
                            signature.sighash_type,
                        )?;
                    let internal_key = expected.pubkey.inner.x_only_public_key().0;
                    let tweaked = internal_key
                        .tap_tweak(
                            &Secp256k1::verification_only(),
                            case.original.inputs[expected.input_index].tap_merkle_root,
                        )
                        .0
                        .to_x_only_public_key();
                    Secp256k1::verification_only()
                        .verify_schnorr(&signature.signature, &Message::from(sighash), &tweaked)
                        .with_context(|| {
                            format!(
                                "{label} hwi signtx returned an invalid taproot signature on input {}",
                                expected.input_index
                            )
                        })?;
                }
            }
        }
        Ok(())
    }

    fn assert_getxpub_shape(label: &str, json: &Value, expert: bool) -> Result<()> {
        let Some(object) = json.as_object() else {
            bail!(
                "{label} hwi getxpub output was not an object:\n{}",
                serde_json::to_string_pretty(json)?
            );
        };

        let expected: &[&str] = if expert {
            &[
                "xpub",
                "testnet",
                "private",
                "depth",
                "parent_fingerprint",
                "child_num",
                "chaincode",
                "pubkey",
            ]
        } else {
            &["xpub"]
        };
        assert_exact_keys(label, "getxpub", json, expected)?;
        assert_string_json_field(label, json, "xpub")?;

        if !expert {
            return Ok(());
        }

        if json.get("testnet").and_then(Value::as_bool).is_none() {
            bail!(
                "{label} hwi getxpub expert field \"testnet\" was not a bool:\n{}",
                serde_json::to_string_pretty(json)?
            );
        }
        if json.get("private").and_then(Value::as_bool) != Some(false) {
            bail!(
                "{label} hwi getxpub expert field \"private\" was not false:\n{}",
                serde_json::to_string_pretty(json)?
            );
        }
        assert_u64_json_field(label, json, "depth")?;
        assert_u64_json_field(label, json, "child_num")?;
        assert_lower_hex_string_field(label, json, "parent_fingerprint", 8)?;
        assert_lower_hex_string_field(label, json, "chaincode", 64)?;
        let pubkey = assert_lower_hex_string_field(label, json, "pubkey", 66)?;
        if !pubkey.starts_with("02") && !pubkey.starts_with("03") {
            bail!(
                "{label} hwi getxpub expert field \"pubkey\" was not compressed SEC hex:\n{}",
                serde_json::to_string_pretty(json)?
            );
        }

        for stale in ["version", "child_index", "chain_code"] {
            if object.contains_key(stale) {
                bail!(
                    "{label} hwi getxpub used stale expert field name {stale:?}:\n{}",
                    serde_json::to_string_pretty(json)?
                );
            }
        }

        Ok(())
    }

    fn assert_xpub_only_shape(label: &str, command: &str, json: &Value) -> Result<()> {
        if !json.is_object() {
            bail!(
                "{label} hwi {command} output was not an object:\n{}",
                serde_json::to_string_pretty(json)?
            );
        };
        assert_exact_keys(label, command, json, &["xpub"])?;
        assert_string_json_field(label, json, "xpub")?;
        Ok(())
    }

    fn assert_error_shape(label: &str, json: &Value) -> Result<()> {
        assert_exact_keys(label, "error", json, &["error", "code"])?;
        assert_string_json_field(label, json, "error")?;
        if json.get("code").and_then(Value::as_i64).is_none() {
            bail!(
                "{label} hwi error field \"code\" was not an integer:\n{}",
                serde_json::to_string_pretty(json)?
            );
        }
        Ok(())
    }

    fn assert_range_field(label: &str, json: &Value) -> Result<()> {
        let Some(range) = json.get("range").and_then(Value::as_array) else {
            bail!(
                "{label} hwi field \"range\" was not an array:\n{}",
                serde_json::to_string_pretty(json)?
            );
        };
        if range.len() != 2 || range.iter().any(|value| value.as_u64().is_none()) {
            bail!(
                "{label} hwi field \"range\" was not two unsigned integers:\n{}",
                serde_json::to_string_pretty(json)?
            );
        }
        Ok(())
    }

    fn assert_exact_keys(
        label: &str,
        command: &str,
        json: &Value,
        expected: &[&str],
    ) -> Result<()> {
        let object = json
            .as_object()
            .with_context(|| format!("{label} hwi {command} output was not an object"))?;
        let mut actual = object.keys().map(String::as_str).collect::<Vec<_>>();
        actual.sort_unstable();
        let mut expected = expected.to_vec();
        expected.sort_unstable();
        if actual != expected {
            bail!(
                "{label} hwi {command} keys did not match\nexpected: {:?}\nactual: {:?}\njson:\n{}",
                expected,
                actual,
                serde_json::to_string_pretty(json)?
            );
        }
        Ok(())
    }

    fn assert_string_json_field<'a>(label: &str, json: &'a Value, field: &str) -> Result<&'a str> {
        let Some(value) = json.get(field).and_then(Value::as_str) else {
            bail!(
                "{label} hwi field {field:?} was not a string:\n{}",
                serde_json::to_string_pretty(json)?
            );
        };

        if value.is_empty() {
            bail!(
                "{label} hwi field {field:?} was empty:\n{}",
                serde_json::to_string_pretty(json)?
            );
        }

        Ok(value)
    }

    fn assert_u64_json_field(label: &str, json: &Value, field: &str) -> Result<u64> {
        let Some(value) = json.get(field).and_then(Value::as_u64) else {
            bail!(
                "{label} hwi field {field:?} was not an unsigned integer:\n{}",
                serde_json::to_string_pretty(json)?
            );
        };
        Ok(value)
    }

    fn assert_lower_hex_string_field<'a>(
        label: &str,
        json: &'a Value,
        field: &str,
        expected_len: usize,
    ) -> Result<&'a str> {
        let value = assert_string_json_field(label, json, field)?;
        let valid = value.len() == expected_len
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !valid {
            bail!(
                "{label} hwi field {field:?} was not {expected_len} lowercase hex chars:\n{}",
                serde_json::to_string_pretty(json)?
            );
        }
        Ok(value)
    }

    fn assert_enumerate_array(label: &str, json: &Value) -> Result<()> {
        if !json.is_array() {
            bail!(
                "{label} hwi enumerate output was not an array:\n{}",
                serde_json::to_string_pretty(json)?
            );
        }
        Ok(())
    }

    fn assert_enumerate_contains_device<'a>(
        label: &str,
        json: &'a Value,
        device_type: &str,
    ) -> Result<&'a Value> {
        if let Some(device) = enumerate_device(json, device_type)? {
            return Ok(device);
        }

        bail!(
            "{label} hwi enumerate output did not include expected device type {device_type:?}:\n{}",
            serde_json::to_string_pretty(json)?
        );
    }

    fn enumerate_device<'a>(json: &'a Value, device_type: &str) -> Result<Option<&'a Value>> {
        let devices = json
            .as_array()
            .with_context(|| "HWI enumerate output was not an array")?;
        Ok(devices
            .iter()
            .find(|device| device.get("type").and_then(Value::as_str) == Some(device_type)))
    }

    fn assert_enumerate_device_shape(
        label: &str,
        device: &Value,
        reference: Option<&Value>,
    ) -> Result<()> {
        let Some(object) = device.as_object() else {
            bail!(
                "{label} hwi enumerate device entry was not an object:\n{}",
                serde_json::to_string_pretty(device)?
            );
        };

        assert_string_field(label, device, "type")?;
        assert_string_field(label, device, "model")?;
        assert_string_field(label, device, "path")?;
        assert_fingerprint_field(label, device)?;
        assert_false_field(label, device, "needs_pin_sent")?;
        assert_false_field(label, device, "needs_passphrase_sent")?;

        if object.contains_key("error") || object.contains_key("code") {
            bail!(
                "{label} hwi enumerate successful device entry included error fields:\n{}",
                serde_json::to_string_pretty(device)?
            );
        }

        if let Some(reference) = reference {
            assert_matching_optional_field(label, device, reference, "label")?;
            for field in [
                "type",
                "model",
                "path",
                "fingerprint",
                "needs_pin_sent",
                "needs_passphrase_sent",
            ] {
                if device.get(field) != reference.get(field) {
                    bail!(
                        "{label} hwi enumerate field {field:?} did not match reference\nreference:\n{}\ncandidate:\n{}",
                        serde_json::to_string_pretty(reference)?,
                        serde_json::to_string_pretty(device)?
                    );
                }
            }
        }

        Ok(())
    }

    fn assert_string_field<'a>(label: &str, device: &'a Value, field: &str) -> Result<&'a str> {
        let Some(value) = device.get(field).and_then(Value::as_str) else {
            bail!(
                "{label} hwi enumerate field {field:?} was not a string:\n{}",
                serde_json::to_string_pretty(device)?
            );
        };

        if value.is_empty() {
            bail!(
                "{label} hwi enumerate field {field:?} was empty:\n{}",
                serde_json::to_string_pretty(device)?
            );
        }

        Ok(value)
    }

    fn assert_fingerprint_field(label: &str, device: &Value) -> Result<()> {
        let fingerprint = assert_string_field(label, device, "fingerprint")?;
        let valid = fingerprint.len() == 8
            && fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !valid {
            bail!(
                "{label} hwi enumerate fingerprint was not 8 lowercase hex chars:\n{}",
                serde_json::to_string_pretty(device)?
            );
        }
        Ok(())
    }

    fn assert_false_field(label: &str, device: &Value, field: &str) -> Result<()> {
        if device.get(field).and_then(Value::as_bool) != Some(false) {
            bail!(
                "{label} hwi enumerate field {field:?} was not false:\n{}",
                serde_json::to_string_pretty(device)?
            );
        }
        Ok(())
    }

    fn assert_matching_optional_field(
        label: &str,
        device: &Value,
        reference: &Value,
        field: &str,
    ) -> Result<()> {
        if device.get(field) != reference.get(field) {
            bail!(
                "{label} hwi enumerate optional field {field:?} did not match reference presence/value\nreference:\n{}\ncandidate:\n{}",
                serde_json::to_string_pretty(reference)?,
                serde_json::to_string_pretty(device)?
            );
        }
        Ok(())
    }

    struct SigntxCase {
        psbt: String,
        original: Psbt,
        expected_signatures: Vec<ExpectedSignature>,
        ledger_registers_wallet: bool,
        verify_signatures: bool,
    }

    #[derive(Clone, Copy)]
    struct ExpectedSignature {
        input_index: usize,
        pubkey: PublicKey,
        kind: ExpectedSignatureKind,
    }

    #[derive(Clone, Copy)]
    enum ExpectedSignatureKind {
        Ecdsa,
        TapKey,
    }

    #[derive(Clone, Copy, Debug)]
    enum LedgerSinglesigWrapper {
        Legacy,
        ShWit,
        Wit,
        Tap,
    }

    impl LedgerSinglesigWrapper {
        const ALL: [Self; 4] = [Self::Legacy, Self::ShWit, Self::Wit, Self::Tap];

        fn purpose(self) -> u32 {
            match self {
                Self::Legacy => 44,
                Self::ShWit => 49,
                Self::Wit => 84,
                Self::Tap => 86,
            }
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum LedgerMultisigWrapper {
        Legacy,
        ShWit,
        Wit,
    }

    impl LedgerMultisigWrapper {
        const ALL: [Self; 3] = [Self::Legacy, Self::ShWit, Self::Wit];
    }

    struct SignMessageCase {
        message: &'static str,
        path: &'static str,
        pubkey: PublicKey,
    }

    fn build_singlesig_signtx_case(
        device_type: &str,
        wrapper: LedgerSinglesigWrapper,
    ) -> Result<SigntxCase> {
        let fingerprint = reference_fingerprint(device_type)?;
        let purpose = wrapper.purpose();
        let account_path = DerivationPath::from_str(&format!("m/{purpose}'/1'/0'"))?;
        let account_xpub = reference_xpub(device_type, &format!("m/{purpose}'/1'/0'"))?;
        let secp = Secp256k1::verification_only();
        let input_child_path = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(0)?,
            ChildNumber::from_normal_idx(0)?,
        ]);
        let change_child_path = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(1)?,
            ChildNumber::from_normal_idx(0)?,
        ]);
        let input_xpub = account_xpub.derive_pub(&secp, &input_child_path)?;
        let change_xpub = account_xpub.derive_pub(&secp, &change_child_path)?;
        let input_pubkey = PublicKey::new(input_xpub.public_key);
        let change_pubkey = PublicKey::new(change_xpub.public_key);
        let input_path = join_derivation_path(&account_path, &input_child_path);
        let change_path = join_derivation_path(&account_path, &change_child_path);
        let input_script = singlesig_script(wrapper, input_pubkey, &secp);
        let change_script = singlesig_script(wrapper, change_pubkey, &secp);
        let mut psbt = spending_psbt(input_script.clone(), change_script);
        let prev_tx = previous_tx(input_script.clone());
        let input_txout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: input_script,
        };
        if matches!(wrapper, LedgerSinglesigWrapper::Tap) {
            let input_xonly = input_pubkey.inner.x_only_public_key().0;
            let change_xonly = change_pubkey.inner.x_only_public_key().0;
            psbt.inputs[0] = Input {
                non_witness_utxo: Some(prev_tx),
                witness_utxo: Some(input_txout),
                tap_internal_key: Some(input_xonly),
                tap_key_origins: [(input_xonly, (Vec::new(), (fingerprint, input_path)))].into(),
                ..Default::default()
            };
            psbt.outputs[0] = PsbtOutput {
                tap_internal_key: Some(change_xonly),
                tap_key_origins: [(change_xonly, (Vec::new(), (fingerprint, change_path)))].into(),
                ..Default::default()
            };
        } else {
            let redeem_script = matches!(wrapper, LedgerSinglesigWrapper::ShWit)
                .then(|| Address::p2wpkh(&input_xpub.to_pub(), Network::Testnet).script_pubkey());
            let change_redeem_script = matches!(wrapper, LedgerSinglesigWrapper::ShWit)
                .then(|| Address::p2wpkh(&change_xpub.to_pub(), Network::Testnet).script_pubkey());
            psbt.inputs[0] = Input {
                non_witness_utxo: Some(prev_tx),
                witness_utxo: (!matches!(wrapper, LedgerSinglesigWrapper::Legacy))
                    .then_some(input_txout),
                redeem_script,
                bip32_derivation: [(input_pubkey.inner, (fingerprint, input_path))].into(),
                ..Default::default()
            };
            psbt.outputs[0] = PsbtOutput {
                redeem_script: change_redeem_script,
                bip32_derivation: [(change_pubkey.inner, (fingerprint, change_path))].into(),
                ..Default::default()
            };
        }

        Ok(SigntxCase {
            psbt: psbt.to_string(),
            original: psbt,
            expected_signatures: vec![ExpectedSignature {
                input_index: 0,
                pubkey: input_pubkey,
                kind: if matches!(wrapper, LedgerSinglesigWrapper::Tap) {
                    ExpectedSignatureKind::TapKey
                } else {
                    ExpectedSignatureKind::Ecdsa
                },
            }],
            ledger_registers_wallet: false,
            verify_signatures: true,
        })
    }

    fn singlesig_script(
        wrapper: LedgerSinglesigWrapper,
        pubkey: PublicKey,
        secp: &Secp256k1<bitcoin::secp256k1::VerifyOnly>,
    ) -> ScriptBuf {
        match wrapper {
            LedgerSinglesigWrapper::Legacy => {
                Address::p2pkh(pubkey, Network::Testnet).script_pubkey()
            }
            LedgerSinglesigWrapper::ShWit => Address::p2wpkh(
                &pubkey.try_into().expect("compressed key"),
                Network::Testnet,
            )
            .script_pubkey()
            .to_p2sh(),
            LedgerSinglesigWrapper::Wit => Address::p2wpkh(
                &pubkey.try_into().expect("compressed key"),
                Network::Testnet,
            )
            .script_pubkey(),
            LedgerSinglesigWrapper::Tap => Address::p2tr(
                secp,
                pubkey.inner.x_only_public_key().0,
                None,
                Network::Testnet,
            )
            .script_pubkey(),
        }
    }

    fn build_ledger_multisig_signtx_case(
        device_type: &str,
        wrapper: LedgerMultisigWrapper,
    ) -> Result<SigntxCase> {
        let fingerprint = reference_fingerprint(device_type)?;
        let account_path = match wrapper {
            LedgerMultisigWrapper::Legacy => "m/48'/1'/0'/0'",
            LedgerMultisigWrapper::ShWit => "m/48'/1'/0'/1'",
            LedgerMultisigWrapper::Wit => "m/48'/1'/0'/2'",
        };
        let device_xpub = reference_xpub(device_type, account_path)?;
        let device_path = DerivationPath::from_str(account_path)?;
        let secp = Secp256k1::new();
        let change_suffix = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(1)?,
            ChildNumber::from_normal_idx(0)?,
        ]);
        let (cosigner_fingerprint, cosigner_xpub, receive) =
            ledger_multisig_cosigner(&secp, device_xpub, fingerprint, &device_path)?;
        let change = sorted_multisig_keys(
            &secp,
            device_xpub,
            fingerprint,
            cosigner_xpub,
            cosigner_fingerprint,
            &device_path,
            &change_suffix,
        )?;
        let input_script = multisig_script(2, &receive);
        let change_script = multisig_script(2, &change);
        let input_script_pubkey = multisig_script_pubkey(wrapper, &input_script);
        let change_script_pubkey = multisig_script_pubkey(wrapper, &change_script);
        let mut psbt = spending_psbt(input_script_pubkey.clone(), change_script_pubkey);

        psbt.inputs[0] = Input {
            non_witness_utxo: Some(previous_tx(input_script_pubkey.clone())),
            witness_utxo: (!matches!(wrapper, LedgerMultisigWrapper::Legacy)).then_some(TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: input_script_pubkey,
            }),
            redeem_script: match wrapper {
                LedgerMultisigWrapper::Legacy => Some(input_script.clone()),
                LedgerMultisigWrapper::ShWit => Some(input_script.to_p2wsh()),
                LedgerMultisigWrapper::Wit => None,
            },
            witness_script: (!matches!(wrapper, LedgerMultisigWrapper::Legacy))
                .then_some(input_script),
            bip32_derivation: [
                (
                    receive[0].inner,
                    (receive[0].fingerprint, receive[0].derivation_path.clone()),
                ),
                (
                    receive[1].inner,
                    (receive[1].fingerprint, receive[1].derivation_path.clone()),
                ),
            ]
            .into(),
            ..Default::default()
        };
        psbt.outputs[0] = PsbtOutput {
            redeem_script: match wrapper {
                LedgerMultisigWrapper::Legacy => Some(change_script.clone()),
                LedgerMultisigWrapper::ShWit => Some(change_script.to_p2wsh()),
                LedgerMultisigWrapper::Wit => None,
            },
            witness_script: (!matches!(wrapper, LedgerMultisigWrapper::Legacy))
                .then_some(change_script),
            bip32_derivation: [
                (
                    change[0].inner,
                    (change[0].fingerprint, change[0].derivation_path.clone()),
                ),
                (
                    change[1].inner,
                    (change[1].fingerprint, change[1].derivation_path.clone()),
                ),
            ]
            .into(),
            ..Default::default()
        };
        psbt.xpub
            .insert(device_xpub, (fingerprint, device_path.clone()));
        psbt.xpub
            .insert(cosigner_xpub, (cosigner_fingerprint, device_path));

        let expected_pubkey = receive
            .iter()
            .find(|key| key.fingerprint == fingerprint)
            .map(|key| PublicKey::new(key.inner))
            .context("missing device multisig pubkey")?;

        Ok(SigntxCase {
            psbt: psbt.to_string(),
            original: psbt,
            expected_signatures: vec![ExpectedSignature {
                input_index: 0,
                pubkey: expected_pubkey,
                kind: ExpectedSignatureKind::Ecdsa,
            }],
            ledger_registers_wallet: true,
            verify_signatures: true,
        })
    }

    fn build_keepkey_multisig_signtx_case(
        device_type: &str,
        wrapper: LedgerMultisigWrapper,
    ) -> Result<SigntxCase> {
        let fingerprint = reference_fingerprint(device_type)?;
        let account_path = DerivationPath::from_str("m/48'/1'/0'/0'")?;
        let device_xpub = reference_xpub(device_type, "m/48'/1'/0'/0'")?;
        let secp = Secp256k1::new();
        let receive_suffix = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(0)?,
            ChildNumber::from_normal_idx(0)?,
        ]);
        let change_suffix = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(1)?,
            ChildNumber::from_normal_idx(0)?,
        ]);
        let cosigner_root = Xpriv::new_master(Network::Testnet, &[9u8; 32])?;
        let cosigner_fingerprint = cosigner_root.fingerprint(&secp);
        let cosigner_xpub =
            Xpub::from_priv(&secp, &cosigner_root.derive_priv(&secp, &account_path)?);
        let receive = sorted_multisig_keys(
            &secp,
            device_xpub,
            fingerprint,
            cosigner_xpub,
            cosigner_fingerprint,
            &account_path,
            &receive_suffix,
        )?;
        let change = sorted_multisig_keys(
            &secp,
            device_xpub,
            fingerprint,
            cosigner_xpub,
            cosigner_fingerprint,
            &account_path,
            &change_suffix,
        )?;
        let input_script = multisig_script(2, &receive);
        let change_script = multisig_script(2, &change);
        let input_script_pubkey = multisig_script_pubkey(wrapper, &input_script);
        let change_script_pubkey = multisig_script_pubkey(wrapper, &change_script);
        let mut psbt = spending_psbt(input_script_pubkey.clone(), change_script_pubkey);

        psbt.inputs[0] = Input {
            non_witness_utxo: Some(previous_tx(input_script_pubkey.clone())),
            witness_utxo: (!matches!(wrapper, LedgerMultisigWrapper::Legacy)).then_some(TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: input_script_pubkey,
            }),
            redeem_script: match wrapper {
                LedgerMultisigWrapper::Legacy => Some(input_script.clone()),
                LedgerMultisigWrapper::ShWit => Some(input_script.to_p2wsh()),
                LedgerMultisigWrapper::Wit => None,
            },
            witness_script: (!matches!(wrapper, LedgerMultisigWrapper::Legacy))
                .then_some(input_script),
            bip32_derivation: [
                (
                    receive[0].inner,
                    (receive[0].fingerprint, receive[0].derivation_path.clone()),
                ),
                (
                    receive[1].inner,
                    (receive[1].fingerprint, receive[1].derivation_path.clone()),
                ),
            ]
            .into(),
            ..Default::default()
        };
        psbt.outputs[0] = PsbtOutput {
            redeem_script: match wrapper {
                LedgerMultisigWrapper::Legacy => Some(change_script.clone()),
                LedgerMultisigWrapper::ShWit => Some(change_script.to_p2wsh()),
                LedgerMultisigWrapper::Wit => None,
            },
            witness_script: (!matches!(wrapper, LedgerMultisigWrapper::Legacy))
                .then_some(change_script),
            bip32_derivation: [
                (
                    change[0].inner,
                    (change[0].fingerprint, change[0].derivation_path.clone()),
                ),
                (
                    change[1].inner,
                    (change[1].fingerprint, change[1].derivation_path.clone()),
                ),
            ]
            .into(),
            ..Default::default()
        };

        let expected_pubkey = receive
            .iter()
            .find(|key| key.fingerprint == fingerprint)
            .map(|key| PublicKey::new(key.inner))
            .context("missing KeepKey multisig pubkey")?;
        Ok(SigntxCase {
            psbt: psbt.to_string(),
            original: psbt,
            expected_signatures: vec![ExpectedSignature {
                input_index: 0,
                pubkey: expected_pubkey,
                kind: ExpectedSignatureKind::Ecdsa,
            }],
            ledger_registers_wallet: false,
            verify_signatures: true,
        })
    }

    fn multisig_script_pubkey(wrapper: LedgerMultisigWrapper, script: &ScriptBuf) -> ScriptBuf {
        match wrapper {
            LedgerMultisigWrapper::Legacy => script.to_p2sh(),
            LedgerMultisigWrapper::ShWit => script.to_p2wsh().to_p2sh(),
            LedgerMultisigWrapper::Wit => script.to_p2wsh(),
        }
    }

    fn build_ledger_mixed_policy_signtx_case(device_type: &str) -> Result<SigntxCase> {
        let singlesig = build_singlesig_signtx_case(device_type, LedgerSinglesigWrapper::Wit)?;
        let multisig = build_ledger_multisig_signtx_case(device_type, LedgerMultisigWrapper::Wit)?;
        let mut single_input = singlesig.original.unsigned_tx.input[0].clone();
        let multi_input = multisig.original.unsigned_tx.input[0].clone();
        single_input.sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

        let unsigned_tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![single_input, multi_input],
            output: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: singlesig.original.unsigned_tx.output[0]
                    .script_pubkey
                    .clone(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;
        psbt.inputs = vec![
            singlesig.original.inputs[0].clone(),
            multisig.original.inputs[0].clone(),
        ];
        psbt.outputs = vec![singlesig.original.outputs[0].clone()];
        psbt.xpub = multisig.original.xpub.clone();

        let expected_signatures = vec![
            ExpectedSignature {
                input_index: 0,
                ..singlesig.expected_signatures[0]
            },
            ExpectedSignature {
                input_index: 1,
                ..multisig.expected_signatures[0]
            },
        ];
        Ok(SigntxCase {
            psbt: psbt.to_string(),
            original: psbt,
            expected_signatures,
            ledger_registers_wallet: true,
            verify_signatures: true,
        })
    }

    fn build_mixed_singlesig_signtx_case(device_type: &str) -> Result<SigntxCase> {
        let legacy = build_singlesig_signtx_case(device_type, LedgerSinglesigWrapper::Legacy)?;
        let witness = build_singlesig_signtx_case(device_type, LedgerSinglesigWrapper::Wit)?;
        let unsigned_tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                legacy.original.unsigned_tx.input[0].clone(),
                witness.original.unsigned_tx.input[0].clone(),
            ],
            output: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: witness.original.unsigned_tx.output[0].script_pubkey.clone(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;
        psbt.inputs = vec![
            legacy.original.inputs[0].clone(),
            witness.original.inputs[0].clone(),
        ];
        psbt.outputs = vec![witness.original.outputs[0].clone()];
        let expected_signatures = vec![
            ExpectedSignature {
                input_index: 0,
                ..legacy.expected_signatures[0]
            },
            ExpectedSignature {
                input_index: 1,
                ..witness.expected_signatures[0]
            },
        ];
        Ok(SigntxCase {
            psbt: psbt.to_string(),
            original: psbt,
            expected_signatures,
            ledger_registers_wallet: false,
            verify_signatures: true,
        })
    }

    fn ledger_multisig_cosigner<
        C: bitcoin::secp256k1::Signing + bitcoin::secp256k1::Verification,
    >(
        secp: &Secp256k1<C>,
        device_xpub: Xpub,
        device_fingerprint: Fingerprint,
        device_path: &DerivationPath,
    ) -> Result<(Fingerprint, Xpub, Vec<DerivedKey>)> {
        let receive_suffix = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(0)?,
            ChildNumber::from_normal_idx(0)?,
        ]);
        for seed in 1..=255 {
            let cosigner_master = Xpriv::new_master(bitcoin::NetworkKind::Test, &[seed; 32])?;
            let cosigner_fingerprint = cosigner_master.fingerprint(secp);
            let cosigner_xpriv = cosigner_master.derive_priv(secp, device_path)?;
            let cosigner_xpub = Xpub::from_priv(secp, &cosigner_xpriv);
            let receive = sorted_multisig_keys(
                secp,
                device_xpub,
                device_fingerprint,
                cosigner_xpub,
                cosigner_fingerprint,
                device_path,
                &receive_suffix,
            )?;
            if receive
                .first()
                .is_some_and(|key| key.fingerprint == device_fingerprint)
            {
                return Ok((cosigner_fingerprint, cosigner_xpub, receive));
            }
        }
        bail!("could not find deterministic Ledger multisig cosigner");
    }

    #[derive(Clone)]
    struct DerivedKey {
        inner: bitcoin::secp256k1::PublicKey,
        fingerprint: Fingerprint,
        derivation_path: DerivationPath,
    }

    fn sorted_multisig_keys<C: bitcoin::secp256k1::Verification>(
        secp: &Secp256k1<C>,
        device_xpub: Xpub,
        device_fingerprint: Fingerprint,
        cosigner_xpub: Xpub,
        cosigner_fingerprint: Fingerprint,
        account_path: &DerivationPath,
        suffix: &DerivationPath,
    ) -> Result<Vec<DerivedKey>> {
        let device = device_xpub.derive_pub(secp, suffix)?;
        let cosigner = cosigner_xpub.derive_pub(secp, suffix)?;
        let mut keys = vec![
            DerivedKey {
                inner: device.public_key,
                fingerprint: device_fingerprint,
                derivation_path: join_derivation_path(account_path, suffix),
            },
            DerivedKey {
                inner: cosigner.public_key,
                fingerprint: cosigner_fingerprint,
                derivation_path: join_derivation_path(account_path, suffix),
            },
        ];
        keys.sort_by_key(|key| key.inner.serialize());
        Ok(keys)
    }

    fn join_derivation_path(base: &DerivationPath, suffix: &DerivationPath) -> DerivationPath {
        let mut children = base.as_ref().to_vec();
        children.extend_from_slice(suffix.as_ref());
        DerivationPath::from(children)
    }

    fn multisig_script(threshold: i64, keys: &[DerivedKey]) -> ScriptBuf {
        let mut builder = Builder::new().push_int(threshold);
        for key in keys {
            builder = builder.push_slice(key.inner.serialize());
        }
        builder
            .push_int(keys.len() as i64)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script()
    }

    fn spending_psbt(input_script: ScriptBuf, change_script: ScriptBuf) -> Psbt {
        Psbt::from_unsigned_tx(Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: previous_tx(input_script).compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: change_script,
            }],
        })
        .expect("unsigned tx should become PSBT")
    }

    fn previous_tx(script_pubkey: ScriptBuf) -> Transaction {
        Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey,
            }],
        }
    }

    fn reference_fingerprint(device_type: &str) -> Result<Fingerprint> {
        let output = HwiBinary::reference()?.run(args([
            "--emulators",
            "--chain",
            "test",
            "--device-type",
            device_type,
            "enumerate",
        ]))?;
        assert_success("reference", &output)?;
        let device = assert_enumerate_contains_device("reference", &output.json, device_type)?;
        let fingerprint = assert_string_field("reference", device, "fingerprint")?;
        Fingerprint::from_str(fingerprint).context("reference fingerprint was invalid")
    }

    fn reference_xpub(device_type: &str, path: &str) -> Result<Xpub> {
        if device_type == "ledger" {
            // Ledger asks for confirmation before exporting non-standard paths,
            // including the BIP-48 legacy and nested multisig branches.
            set_ledger_automation(true)?;
        }
        let output = HwiBinary::reference()?.run(args([
            "--emulators",
            "--chain",
            "test",
            "--device-type",
            device_type,
            "getxpub",
            path,
        ]))?;
        assert_success("reference", &output)?;
        let xpub = assert_string_json_field("reference", &output.json, "xpub")?;
        Xpub::from_str(xpub).context("reference xpub was invalid")
    }

    fn signtx_args(device_type: &str, psbt: &str) -> Vec<String> {
        args([
            "--emulators",
            "--chain",
            "test",
            "--device-type",
            device_type,
            "signtx",
            psbt,
        ])
    }

    fn signmessage_arg_cases(device_type: &str) -> Result<Vec<SignMessageCase>> {
        let path = match device_type {
            "bitbox02" => "m/49'/1'/0'/0/10",
            "ledger" => "m/44'/1'/0'/0",
            "jade" | "coldcard" => "m/44'/1'/0'",
            "trezor" | "keepkey" => "m/44'/1'/0'/0/0",
            _ => bail!("unsupported signmessage device type {device_type:?}"),
        };
        let pubkey = PublicKey::new(reference_xpub(device_type, path)?.public_key);
        Ok(["hello", "hello world"]
            .into_iter()
            .map(|message| SignMessageCase {
                message,
                path,
                pubkey,
            })
            .collect())
    }

    fn displayaddress_arg_cases(device_type: &str) -> Result<Vec<DisplayAddressCase>> {
        let fingerprint = reference_fingerprint(device_type)?;
        let wit_xpub = reference_xpub(device_type, "m/84'/1'/0'")?;
        let sh_wit_xpub = reference_xpub(device_type, "m/49'/1'/0'")?;
        let fingerprint = fingerprint.to_string();
        let wit_xpub_string = wit_xpub.to_string();
        let wit_pubkey = lower_hex(&wit_xpub.public_key.serialize());
        let sh_wit_xpub = sh_wit_xpub.to_string();

        let mut cases = vec![
            DisplayAddressCase::success(displayaddress_path_args(
                device_type,
                "sh_wit",
                "m/49h/1h/0h/0/0",
            )),
            DisplayAddressCase::success(displayaddress_path_args(
                device_type,
                "wit",
                "m/84h/1h/0h/0/0",
            )),
            DisplayAddressCase::success(displayaddress_desc_args(
                device_type,
                &format!("wpkh([{fingerprint}/84h/1h/0h]{wit_xpub_string}/0/0)"),
            )),
            DisplayAddressCase::success(displayaddress_desc_args(
                device_type,
                &format!("wpkh([{fingerprint}/84h/1h/0h]{wit_pubkey}/0/0)"),
            )),
            DisplayAddressCase::success(displayaddress_desc_args(
                device_type,
                &format!("sh(wpkh([{fingerprint}/49h/1h/0h]{sh_wit_xpub}/0/0))"),
            )),
        ];

        if device_type != "bitbox02" {
            let legacy_xpub = reference_xpub(device_type, "m/44'/1'/0'")?.to_string();
            cases.insert(
                0,
                DisplayAddressCase::success(displayaddress_path_args(
                    device_type,
                    "legacy",
                    "m/44h/1h/0h/0/0",
                )),
            );
            cases.push(DisplayAddressCase::success(displayaddress_desc_args(
                device_type,
                &format!("pkh([{fingerprint}/44h/1h/0h]{legacy_xpub}/0/0)"),
            )));
        }

        cases.push(DisplayAddressCase::new(
            displayaddress_path_args(device_type, "tap", "m/86h/1h/0h/0/0"),
            if matches!(device_type, "bitbox02" | "ledger" | "trezor") {
                ExpectedResult::Success
            } else {
                ExpectedResult::Error
            },
        ));
        cases.push(DisplayAddressCase::error(displayaddress_desc_args(
            device_type,
            &format!("wpkh([00000000/84h/1h/0h]{wit_xpub_string}/0/0)"),
        )));
        cases.push(DisplayAddressCase::error(displayaddress_desc_args(
            device_type,
            &format!("wpkh([{fingerprint}/84h/1h/0h]not_an_xpub/0/0)"),
        )));
        if device_type == "keepkey" {
            cases.extend(keepkey_multisig_display_cases(device_type, &fingerprint)?);
        }
        if device_type == "coldcard" {
            for wallet in coldcard_multisig_display_wallets(device_type, &fingerprint)? {
                let args = displayaddress_desc_args(device_type, &wallet.display_descriptor);
                cases.push(DisplayAddressCase::registered(args.clone(), wallet));
                cases.push(DisplayAddressCase::unregistered(args));
            }
        }

        Ok(cases)
    }

    fn keepkey_multisig_display_cases(
        device_type: &str,
        fingerprint: &str,
    ) -> Result<Vec<DisplayAddressCase>> {
        const ORIGIN: &str = "48h/1h/0h/0h";
        let secp = Secp256k1::new();
        let account_path: DerivationPath = "m/48'/1'/0'/0'".parse()?;
        let child_path: DerivationPath = "m/0/0".parse()?;
        let device_xpub = reference_xpub(device_type, "m/48'/1'/0'/0'")?;
        let device_child = device_xpub.derive_pub(&secp, &child_path)?;
        let cosigner_root = Xpriv::new_master(Network::Testnet, &[9u8; 32])?;
        let cosigner_fingerprint = cosigner_root.fingerprint(&secp);
        let cosigner_xpub =
            Xpub::from_priv(&secp, &cosigner_root.derive_priv(&secp, &account_path)?);
        let cosigner_child = cosigner_xpub.derive_pub(&secp, &child_path)?;
        let derived = format!(
            "[{fingerprint}/{ORIGIN}/0/0]{},[{cosigner_fingerprint}/{ORIGIN}/0/0]{}",
            device_child.public_key, cosigner_child.public_key
        );
        let extended = format!(
            "[{fingerprint}/{ORIGIN}]{device_xpub}/0/0,[{cosigner_fingerprint}/{ORIGIN}]{cosigner_xpub}/0/0"
        );
        Ok(vec![
            DisplayAddressCase::success(displayaddress_desc_args(
                device_type,
                &format!("sh(sortedmulti(2,{derived}))"),
            )),
            DisplayAddressCase::success(displayaddress_desc_args(
                device_type,
                &format!("sh(wsh(sortedmulti(2,{derived})))"),
            )),
            DisplayAddressCase::success(displayaddress_desc_args(
                device_type,
                &format!("wsh(sortedmulti(2,{derived}))"),
            )),
            DisplayAddressCase::candidate_error(
                displayaddress_desc_args(device_type, &format!("wsh(sortedmulti(2,{extended}))")),
                ExpectedHwiError {
                    code: -9,
                    error: "unsupported display address: KeepKey multisig address display requires fully-derived public keys",
                },
            ),
            DisplayAddressCase::candidate_error(
                displayaddress_desc_args(device_type, &format!("wsh(multi(2,{derived}))")),
                ExpectedHwiError {
                    code: -9,
                    error: "unsupported display address: KeepKey does not support unsorted multisig address display",
                },
            ),
        ])
    }

    fn coldcard_multisig_display_wallets(
        device_type: &str,
        fingerprint: &str,
    ) -> Result<Vec<ColdcardDisplayWallet>> {
        let secp = Secp256k1::new();
        let child_path = DerivationPath::from_str("m/0/0")?;
        // The normal simulator accepts its own fingerprint once per wallet,
        // so use synthetic cosigners instead of the patched upstream fixture.
        let cosigner_masters = [
            Xpriv::new_master(Network::Testnet, &[17_u8; 32])?,
            Xpriv::new_master(Network::Testnet, &[34_u8; 32])?,
        ];
        let mut wallets = Vec::new();

        for (origin_path, wrapper) in [
            ("48h/1h/0h/0h", ColdcardDisplayWrapper::Legacy),
            ("48h/1h/0h/1h", ColdcardDisplayWrapper::ShWit),
            ("48h/1h/0h/2h", ColdcardDisplayWrapper::Wit),
        ] {
            let account_path = DerivationPath::from_str(&format!("m/{origin_path}"))?;
            let device_xpub = reference_xpub(device_type, &format!("m/{origin_path}"))?;
            let mut registration_keys =
                vec![format!("[{fingerprint}/{origin_path}]{device_xpub}/0/*")];
            let device_child = device_xpub.derive_pub(&secp, &child_path)?;
            let mut display_keys = vec![format!(
                "[{fingerprint}/{origin_path}/0/0]{}",
                device_child.public_key
            )];

            for master in &cosigner_masters {
                let cosigner_fingerprint = master.fingerprint(&secp);
                let account_xpriv = master.derive_priv(&secp, &account_path)?;
                let account_xpub = Xpub::from_priv(&secp, &account_xpriv);
                registration_keys.push(format!(
                    "[{cosigner_fingerprint}/{origin_path}]{account_xpub}/0/*"
                ));
                let child = account_xpub.derive_pub(&secp, &child_path)?;
                display_keys.push(format!(
                    "[{cosigner_fingerprint}/{origin_path}/0/0]{}",
                    child.public_key
                ));
            }

            wallets.push(ColdcardDisplayWallet {
                name: "hwi-display".to_owned(),
                registration_descriptor: wrapper.wrap(&registration_keys.join(",")),
                display_descriptor: wrapper.wrap(&display_keys.join(",")),
                fingerprint: fingerprint.to_owned(),
            });
        }

        Ok(wallets)
    }

    fn signmessage_args(device_type: &str, message: &str, path: &str) -> Vec<String> {
        args([
            "--emulators",
            "--chain",
            "test",
            "--device-type",
            device_type,
            "signmessage",
            message,
            path,
        ])
    }

    fn displayaddress_path_args(device_type: &str, addr_type: &str, path: &str) -> Vec<String> {
        args([
            "--emulators",
            "--chain",
            "test",
            "--device-type",
            device_type,
            "displayaddress",
            "--addr-type",
            addr_type,
            "--path",
            path,
        ])
    }

    fn displayaddress_desc_args(device_type: &str, descriptor: &str) -> Vec<String> {
        args([
            "--emulators",
            "--chain",
            "test",
            "--device-type",
            device_type,
            "displayaddress",
            "--desc",
            descriptor,
        ])
    }

    fn prepare_signmessage_run(args: &[String]) -> Result<Option<TrezorApproval>> {
        let Some(device_type) = arg_value(args, "--device-type") else {
            return Ok(None);
        };
        match device_type {
            "ledger" => set_ledger_signmessage_automation().map(|()| None),
            "coldcard" => {
                spawn_coldcard_approval();
                Ok(None)
            }
            "trezor" => Ok(Some(spawn_trezor_approval())),
            "keepkey" => Ok(Some(spawn_debug_approval(
                KEEPKEY_DEBUGLINK_ADDR,
                DebugButton::Yes,
                Instant::now() + command_timeout(),
            ))),
            _ => Ok(None),
        }
    }

    fn prepare_displayaddress_run(args: &[String]) -> Result<Option<TrezorApproval>> {
        let Some(device_type) = arg_value(args, "--device-type") else {
            return Ok(None);
        };
        match device_type {
            "ledger" => set_ledger_displayaddress_automation().map(|()| None),
            "coldcard" => {
                spawn_coldcard_approval();
                Ok(None)
            }
            "trezor" => Ok(Some(spawn_trezor_approval())),
            "keepkey" => Ok(Some(spawn_debug_approval(
                KEEPKEY_DEBUGLINK_ADDR,
                DebugButton::Yes,
                Instant::now() + command_timeout(),
            ))),
            _ => Ok(None),
        }
    }

    fn prepare_displayaddress_case_run(
        case: &DisplayAddressCase,
    ) -> Result<Option<TrezorApproval>> {
        match &case.coldcard_setup {
            ColdcardDisplaySetup::None => {}
            ColdcardDisplaySetup::Registered(wallet) => register_coldcard_wallet(wallet)?,
            ColdcardDisplaySetup::Unregistered => reset_coldcard_multisig()?,
        }
        if matches!(case.expect, ExpectedResult::Success) {
            return prepare_displayaddress_run(&case.args);
        }
        Ok(None)
    }

    fn register_coldcard_wallet(wallet: &ColdcardDisplayWallet) -> Result<()> {
        reset_coldcard_multisig()?;
        let bin = native_bhwi_bin()?;
        let mut child = Command::new(&bin)
            .args([
                "--network",
                "testnet",
                "--fingerprint",
                &wallet.fingerprint,
                "register-wallet",
                "--name",
                &wallet.name,
                "--descriptor",
                &wallet.registration_descriptor,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to spawn native bhwi at {}", bin.display()))?;

        let deadline = Instant::now() + Duration::from_secs(60);
        while child.try_wait()?.is_none() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                bail!("timed out waiting for Coldcard wallet registration acknowledgement");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            bail!(
                "native bhwi registration failed with status {}\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Coldcard acknowledges the enrollment request before the user-facing
        // confirmation is persisted, so approve and poll the simulator state.
        std::thread::sleep(Duration::from_millis(100));
        coldcard_control_exchange(b"XKEYy")?;
        for _ in 0..40 {
            if coldcard_multisig_settings()?.contains(&wallet.name) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        bail!(
            "Coldcard multisig registration was not persisted for {:?}",
            wallet.display_descriptor
        )
    }

    fn native_bhwi_bin() -> Result<PathBuf> {
        let path = match env::var_os("BHWI_BIN") {
            Some(path) => PathBuf::from(path),
            None => {
                let hwi = env::var_os("HWI_BIN").context("HWI_BIN must point to candidate hwi")?;
                PathBuf::from(hwi).with_file_name("bhwi")
            }
        };
        if !path.is_file() {
            bail!(
                "BHWI_BIN must point to the native bhwi binary used for Coldcard setup: {}",
                path.display()
            );
        }
        Ok(path)
    }

    fn reset_coldcard_multisig() -> Result<()> {
        coldcard_control_exchange(b"EXECsettings.set('multisig', []); settings.save()")?;
        Ok(())
    }

    fn coldcard_multisig_settings() -> Result<String> {
        let response = coldcard_control_exchange(b"EVALsettings.get('multisig', [])")?;
        let value = response
            .strip_prefix(b"biny")
            .context("unexpected Coldcard multisig settings response")?;
        String::from_utf8(value.to_vec()).context("Coldcard multisig settings were not UTF-8")
    }

    fn prepare_signtx_run(args: &[String], case: &SigntxCase) -> Result<Option<TrezorApproval>> {
        let Some(device_type) = arg_value(args, "--device-type") else {
            return Ok(None);
        };
        match device_type {
            "ledger" => set_ledger_automation(case.ledger_registers_wallet).map(|()| None),
            "coldcard" => {
                spawn_coldcard_approval();
                Ok(None)
            }
            "trezor" => Ok(Some(spawn_trezor_approval())),
            "keepkey" => Ok(Some(spawn_debug_approval(
                KEEPKEY_DEBUGLINK_ADDR,
                DebugButton::Yes,
                Instant::now() + command_timeout(),
            ))),
            _ => Ok(None),
        }
    }

    fn arg_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
        args.windows(2)
            .find(|pair| pair[0] == name)
            .map(|pair| pair[1].as_str())
    }

    fn set_ledger_automation(registers_wallet: bool) -> Result<()> {
        let automation = if registers_wallet {
            serde_json::from_str(include_str!("../../ledger/automations/hwi_speculos.json"))?
        } else {
            serde_json::from_str(include_str!("../../ledger/automations/sign_psbt.json"))?
        };
        post_speculos_automation(&automation)
    }

    fn set_ledger_signmessage_automation() -> Result<()> {
        let automation =
            serde_json::from_str(include_str!("../../ledger/automations/sign_message.json"))?;
        post_speculos_automation(&automation)
    }

    fn set_ledger_displayaddress_automation() -> Result<()> {
        let automation = serde_json::from_str(include_str!(
            "../../ledger/automations/display_address.json"
        ))?;
        post_speculos_automation(&automation)
    }

    fn post_speculos_automation(automation: &Value) -> Result<()> {
        let body = serde_json::to_vec(automation)?;
        let mut stream = std::net::TcpStream::connect("127.0.0.1:5000")
            .context("failed to connect to Speculos automation API")?;
        write!(
            stream,
            "POST /automation HTTP/1.1\r\nHost: 127.0.0.1:5000\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )?;
        stream.write_all(&body)?;
        stream.flush()?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        if !response.starts_with("HTTP/1.1 200") && !response.starts_with("HTTP/1.0 200") {
            bail!("Speculos automation API returned unexpected response: {response}");
        }
        Ok(())
    }

    fn spawn_coldcard_approval() {
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_secs(1));
            let _ = send_coldcard_approval();
        });
    }

    /// Presses the Coldcard refuse key until the command under test exits. A
    /// single press raced slow reference startup and stray queued keys.
    struct ColdcardRefusal {
        done: Arc<AtomicBool>,
        handle: std::thread::JoinHandle<()>,
    }

    impl ColdcardRefusal {
        fn spawn() -> Self {
            let done = Arc::new(AtomicBool::new(false));
            let refusing = Arc::clone(&done);
            let handle = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(120);
                while !refusing.load(Ordering::Relaxed) && Instant::now() < deadline {
                    let _ = coldcard_control_exchange(b"XKEYx");
                    std::thread::sleep(Duration::from_millis(500));
                }
            });
            Self { done, handle }
        }

        fn finish(self) {
            self.done.store(true, Ordering::Relaxed);
            let _ = self.handle.join();
        }
    }

    /// Drains the simulator's queued keypresses (`numpad` is a `Queue(64)`);
    /// the EXEC ends with a harmless QueueEmpty traceback once drained.
    fn flush_coldcard_keypresses() -> Result<()> {
        coldcard_control_exchange(b"EXECimport glob\nwhile 1: glob.numpad.get_nowait()")?;
        Ok(())
    }

    fn set_ledger_cancel_automation(command: &str) -> Result<()> {
        let automation = match command {
            "signtx" => include_str!("../../ledger/automations/sign_psbt_reject.json"),
            "signmessage" => include_str!("../../ledger/automations/sign_message_reject.json"),
            _ => include_str!("../../ledger/automations/display_address_reject.json"),
        };
        post_speculos_automation(&serde_json::from_str(automation)?)
    }

    /// Approves the Coldcard backup prompts until the command under test exits.
    /// A single pass raced the prompt: presses sent before it appeared were lost
    /// and the command then waited for input that never came again.
    struct ColdcardBackupApproval {
        done: Arc<AtomicBool>,
        handle: std::thread::JoinHandle<()>,
    }

    impl ColdcardBackupApproval {
        fn spawn() -> Self {
            let done = Arc::new(AtomicBool::new(false));
            let approving = Arc::clone(&done);
            let handle = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(120);
                while !approving.load(Ordering::Relaxed) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_secs(1));
                    if approving.load(Ordering::Relaxed) {
                        break;
                    }
                    let _ = send_coldcard_backup_approval();
                }
            });
            Self { done, handle }
        }

        fn finish(self) {
            self.done.store(true, Ordering::Relaxed);
            let _ = self.handle.join();
        }
    }

    struct TrezorApproval {
        stop: Arc<AtomicBool>,
        presser: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for TrezorApproval {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(presser) = self.presser.take() {
                let _ = presser.join();
            }
        }
    }

    fn spawn_debug_approval(
        addr: &'static str,
        button: DebugButton,
        deadline: Instant,
    ) -> TrezorApproval {
        let stop = Arc::new(AtomicBool::new(false));
        let pressing = stop.clone();
        let presser = std::thread::spawn(move || {
            while !pressing.load(Ordering::Relaxed) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(250));
                if pressing.load(Ordering::Relaxed)
                    || Instant::now() >= deadline
                    || send_debug_decision(addr, button).is_err()
                {
                    return;
                }
            }
        });
        TrezorApproval {
            stop,
            presser: Some(presser),
        }
    }

    fn spawn_trezor_approval() -> TrezorApproval {
        spawn_debug_approval(
            DEFAULT_DEBUGLINK_ADDR,
            DebugButton::Yes,
            Instant::now() + command_timeout(),
        )
    }

    fn send_debug_decision(addr: &str, button: DebugButton) -> Result<()> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.connect(addr)?;
        for report in button_reports(button) {
            socket.send(&report)?;
        }
        Ok(())
    }

    fn send_coldcard_approval() -> Result<()> {
        coldcard_control_exchange(b"XKEYy")?;
        Ok(())
    }

    /// Stores a backup password on the simulator so `backup` offers "use the
    /// same password as last time" instead of generating fresh words and
    /// quizzing them back (firmware shared/backups.py: a stored `bkpw` sets
    /// `skip_quiz`). The quiz shuffles three choices per question, so without
    /// this the harness can only guess, and a wrong guess costs a two second
    /// penalty pause before the question is asked again.
    fn store_coldcard_backup_password() -> Result<()> {
        coldcard_control_exchange(b"EXECsettings.set('bkpw','a'*32);settings.save()")?;
        Ok(())
    }

    fn send_coldcard_backup_approval() -> Result<()> {
        coldcard_control_exchange(b"XKEYy")?;
        Ok(())
    }

    fn coldcard_control_exchange(request: &[u8]) -> Result<Vec<u8>> {
        static SOCKET_COUNTER: AtomicUsize = AtomicUsize::new(0);
        let socket_id = SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed);
        let client_socket = format!(
            "/tmp/bhwi-hwi-parity-ckcc-{}-{socket_id}.sock",
            std::process::id()
        );
        let _ = std::fs::remove_file(&client_socket);
        let socket = UnixDatagram::bind(&client_socket)?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        socket.connect("/tmp/ckcc-simulator.sock")?;
        let response = coldcard_hid_exchange(&socket, request);
        drop(socket);
        let _ = std::fs::remove_file(client_socket);
        response
    }

    fn coldcard_hid_exchange(socket: &UnixDatagram, request: &[u8]) -> Result<Vec<u8>> {
        let mut packet = [0_u8; 64];
        packet[0] =
            0x80 | u8::try_from(request.len()).context("Coldcard test request too large")?;
        packet[1..1 + request.len()].copy_from_slice(request);
        socket.send(&packet)?;

        let mut response = Vec::new();
        let mut first = true;
        loop {
            let mut packet = [0_u8; 64];
            socket.recv(&mut packet)?;
            let flag = packet[0];
            let len = usize::from(flag & 0x3f);
            let is_fram = first && &packet[1..5] == b"fram";
            response.extend_from_slice(&packet[1..1 + len]);
            first = false;
            if flag & 0x80 != 0 || is_fram {
                break;
            }
        }
        Ok(response)
    }

    fn enumerate_args_from_env() -> Result<(Vec<String>, Option<String>)> {
        match expected_device_type_from_env()? {
            Some(device_type) => Ok((
                vec![
                    "--emulators".to_owned(),
                    "--device-type".to_owned(),
                    device_type.clone(),
                    "enumerate".to_owned(),
                ],
                Some(device_type),
            )),
            None => Ok((vec!["enumerate".to_owned()], None)),
        }
    }

    fn expected_device_type_from_env() -> Result<Option<String>> {
        match env::var("HWI_PARITY_DEVICE_TYPE") {
            Ok(device_type) => Ok(Some(normalize_device_type(&device_type)?)),
            Err(env::VarError::NotPresent) => Ok(None),
            Err(err) => Err(err).context("failed to read HWI_PARITY_DEVICE_TYPE"),
        }
    }

    fn getmasterxpub_arg_cases(device_type: &str) -> Vec<CommandCase> {
        let cases = vec![
            CommandCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "getmasterxpub",
                ]),
                expect: ExpectedResult::Success,
            },
            CommandCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--expert",
                    "--device-type",
                    device_type,
                    "getmasterxpub",
                ]),
                expect: ExpectedResult::Success,
            },
            CommandCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "getmasterxpub",
                    "--account",
                    "1",
                ]),
                expect: ExpectedResult::Success,
            },
            CommandCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "getmasterxpub",
                    "--addr-type",
                    "legacy",
                ]),
                expect: ExpectedResult::Success,
            },
            CommandCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "getmasterxpub",
                    "--addr-type",
                    "sh_wit",
                ]),
                expect: ExpectedResult::Success,
            },
            CommandCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "getmasterxpub",
                    "--addr-type",
                    "wit",
                ]),
                expect: ExpectedResult::Success,
            },
            CommandCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "getmasterxpub",
                    "--addr-type",
                    "tap",
                ]),
                expect: ExpectedResult::Success,
            },
        ];

        cases
    }

    fn getxpub_arg_cases(device_type: &str) -> Vec<Vec<String>> {
        if device_type == "bitbox02" {
            return vec![
                args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "getxpub",
                    "m/84h/1h/0h",
                ]),
                args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--expert",
                    "--device-type",
                    device_type,
                    "getxpub",
                    "m/49h/1h/0h/0/3",
                ]),
            ];
        }

        vec![
            args([
                "--emulators",
                "--chain",
                "test",
                "--device-type",
                device_type,
                "getxpub",
                "m/44h/1h/0h",
            ]),
            args([
                "--emulators",
                "--chain",
                "test",
                "--expert",
                "--device-type",
                device_type,
                "getxpub",
                "m/44h/1h/0h/0/3",
            ]),
        ]
    }

    fn getdescriptors_arg_cases(device_type: &str) -> Vec<Vec<String>> {
        vec![
            args([
                "--emulators",
                "--chain",
                "test",
                "--device-type",
                device_type,
                "getdescriptors",
            ]),
            args([
                "--emulators",
                "--chain",
                "test",
                "--device-type",
                device_type,
                "getdescriptors",
                "--account",
                "1",
            ]),
        ]
    }

    #[derive(Clone, Copy)]
    enum ExpectedResult {
        Success,
        Error,
    }

    #[derive(Clone, Copy)]
    struct ExpectedHwiError {
        code: i64,
        error: &'static str,
    }

    impl ExpectedHwiError {
        fn json(self) -> Value {
            serde_json::json!({"error": self.error, "code": self.code})
        }
    }

    struct CommandCase {
        args: Vec<String>,
        expect: ExpectedResult,
    }

    struct DisplayAddressCase {
        args: Vec<String>,
        expect: ExpectedResult,
        candidate_only_error: Option<ExpectedHwiError>,
        coldcard_setup: ColdcardDisplaySetup,
    }

    impl DisplayAddressCase {
        fn new(args: Vec<String>, expect: ExpectedResult) -> Self {
            Self {
                args,
                expect,
                candidate_only_error: None,
                coldcard_setup: ColdcardDisplaySetup::None,
            }
        }

        fn success(args: Vec<String>) -> Self {
            Self::new(args, ExpectedResult::Success)
        }

        fn error(args: Vec<String>) -> Self {
            Self::new(args, ExpectedResult::Error)
        }

        fn candidate_error(args: Vec<String>, expected: ExpectedHwiError) -> Self {
            Self {
                args,
                expect: ExpectedResult::Error,
                candidate_only_error: Some(expected),
                coldcard_setup: ColdcardDisplaySetup::None,
            }
        }

        fn registered(args: Vec<String>, wallet: ColdcardDisplayWallet) -> Self {
            Self {
                args,
                expect: ExpectedResult::Success,
                candidate_only_error: None,
                coldcard_setup: ColdcardDisplaySetup::Registered(wallet),
            }
        }

        fn unregistered(args: Vec<String>) -> Self {
            Self {
                args,
                expect: ExpectedResult::Error,
                candidate_only_error: None,
                coldcard_setup: ColdcardDisplaySetup::Unregistered,
            }
        }
    }

    enum ColdcardDisplaySetup {
        None,
        Registered(ColdcardDisplayWallet),
        Unregistered,
    }

    struct ColdcardDisplayWallet {
        name: String,
        registration_descriptor: String,
        display_descriptor: String,
        fingerprint: String,
    }

    #[derive(Clone, Copy)]
    enum ColdcardDisplayWrapper {
        Legacy,
        ShWit,
        Wit,
    }

    impl ColdcardDisplayWrapper {
        fn wrap(self, keys: &str) -> String {
            match self {
                Self::Legacy => format!("sh(sortedmulti(2,{keys}))"),
                Self::ShWit => format!("sh(wsh(sortedmulti(2,{keys})))"),
                Self::Wit => format!("wsh(sortedmulti(2,{keys}))"),
            }
        }
    }

    struct UnsupportedDeviceActionCase {
        args: Vec<String>,
    }

    fn getkeypool_arg_cases(device_type: &str) -> Vec<CommandCase> {
        let mut cases = vec![
            CommandCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "getkeypool",
                    "0",
                    "2",
                ]),
                expect: ExpectedResult::Success,
            },
            CommandCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "getkeypool",
                    "--internal",
                    "--nokeypool",
                    "--addr-type",
                    "sh_wit",
                    "--account",
                    "1",
                    "5",
                    "7",
                ]),
                expect: ExpectedResult::Success,
            },
            CommandCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "getkeypool",
                    "--keypool",
                    "--path",
                    "m/84h/1h/0h/0/*",
                    "0",
                    "1",
                ]),
                expect: ExpectedResult::Success,
            },
            CommandCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "getkeypool",
                    "--all",
                    "0",
                    "1",
                ]),
                expect: ExpectedResult::Success,
            },
        ];

        cases.push(CommandCase {
            args: args([
                "--emulators",
                "--chain",
                "test",
                "--device-type",
                device_type,
                "getkeypool",
                "--addr-type",
                "tap",
                "0",
                "1",
            ]),
            expect: if matches!(device_type, "ledger" | "trezor") {
                ExpectedResult::Success
            } else {
                ExpectedResult::Error
            },
        });

        cases
    }

    fn unsupported_device_action_cases(device_type: &str) -> Vec<UnsupportedDeviceActionCase> {
        if device_type == "bitbox02" {
            return Vec::new();
        }

        let mut cases = vec![
            UnsupportedDeviceActionCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "setup",
                ]),
            },
            UnsupportedDeviceActionCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "--interactive",
                    "setup",
                    "--label",
                    "HWI Test",
                    "--backup_passphrase",
                    "backup passphrase",
                ]),
            },
            UnsupportedDeviceActionCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "wipe",
                ]),
            },
            UnsupportedDeviceActionCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "restore",
                    "--word_count",
                    "12",
                    "--label",
                    "HWI Test",
                ]),
            },
            UnsupportedDeviceActionCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "--interactive",
                    "restore",
                    "-w",
                    "18",
                    "-l",
                    "HWI Test",
                ]),
            },
            UnsupportedDeviceActionCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "promptpin",
                ]),
            },
            UnsupportedDeviceActionCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "sendpin",
                    "1234",
                ]),
            },
            UnsupportedDeviceActionCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "togglepassphrase",
                ]),
            },
        ];

        if device_type != "coldcard" {
            cases.push(UnsupportedDeviceActionCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "backup",
                    "--label",
                    "HWI Test",
                    "--backup_passphrase",
                    "backup passphrase",
                ]),
            });
        }

        if matches!(device_type, "trezor" | "keepkey") {
            cases.retain(|case| {
                !case
                    .args
                    .iter()
                    .any(|arg| arg == "wipe" || arg == "togglepassphrase")
            });
        }

        cases
    }

    fn backup_arg_cases(device_type: &str) -> Vec<CommandCase> {
        if device_type == "coldcard" {
            return vec![
                CommandCase {
                    args: args([
                        "--emulators",
                        "--chain",
                        "test",
                        "--device-type",
                        device_type,
                        "backup",
                    ]),
                    expect: ExpectedResult::Success,
                },
                CommandCase {
                    args: args([
                        "--emulators",
                        "--chain",
                        "test",
                        "--device-type",
                        device_type,
                        "backup",
                        "--label",
                        "HWI Test",
                        "--backup_passphrase",
                        "backup passphrase",
                    ]),
                    expect: ExpectedResult::Success,
                },
            ];
        }

        if device_type == "bitbox02" {
            return vec![
                CommandCase {
                    args: args([
                        "--emulators",
                        "--chain",
                        "test",
                        "--device-type",
                        device_type,
                        "backup",
                    ]),
                    expect: ExpectedResult::Success,
                },
                CommandCase {
                    args: args([
                        "--emulators",
                        "--chain",
                        "test",
                        "--device-type",
                        device_type,
                        "backup",
                        "--label",
                        "HWI Test",
                    ]),
                    expect: ExpectedResult::Error,
                },
                CommandCase {
                    args: args([
                        "--emulators",
                        "--chain",
                        "test",
                        "--device-type",
                        device_type,
                        "backup",
                        "--backup_passphrase",
                        "backup passphrase",
                    ]),
                    expect: ExpectedResult::Error,
                },
                CommandCase {
                    args: args([
                        "--emulators",
                        "--chain",
                        "test",
                        "--device-type",
                        device_type,
                        "backup",
                        "--label",
                        "HWI Test",
                        "--backup_passphrase",
                        "backup passphrase",
                    ]),
                    expect: ExpectedResult::Error,
                },
            ];
        }

        if matches!(device_type, "trezor" | "keepkey") {
            return vec![CommandCase {
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "backup",
                ]),
                expect: ExpectedResult::Error,
            }];
        }

        Vec::new()
    }

    fn enumerate_python_hwi_arg_cases(
        device_type: &str,
        device_path: &str,
        fingerprint: &str,
    ) -> Vec<Vec<String>> {
        let mut cases = vec![
            args(["--emulators", "--device-type", device_type, "enumerate"]),
            args(["--emulators", "-t", device_type, "enumerate"]),
            args([
                "--emulators",
                "--device-type",
                device_type,
                "--device-path",
                device_path,
                "enumerate",
            ]),
            args([
                "--emulators",
                "--device-type",
                device_type,
                "-d",
                device_path,
                "enumerate",
            ]),
            args([
                "--emulators",
                "--device-type",
                device_type,
                "--fingerprint",
                fingerprint,
                "enumerate",
            ]),
            args([
                "--emulators",
                "--device-type",
                device_type,
                "-f",
                fingerprint,
                "enumerate",
            ]),
            args([
                "--emulators",
                "--debug",
                "--device-type",
                device_type,
                "enumerate",
            ]),
            args([
                "--emulators",
                "--expert",
                "--device-type",
                device_type,
                "enumerate",
            ]),
            args([
                "--emulators",
                "--interactive",
                "--device-type",
                device_type,
                "enumerate",
            ]),
            args([
                "--emulators",
                "-i",
                "--device-type",
                device_type,
                "enumerate",
            ]),
            args([
                "--emulators",
                "--password",
                "unused",
                "--device-type",
                device_type,
                "enumerate",
            ]),
            args([
                "--emulators",
                "-p",
                "unused",
                "--device-type",
                device_type,
                "enumerate",
            ]),
            args([
                "--emulators",
                "--chain",
                "test",
                "--device-type",
                device_type,
                "enumerate",
            ]),
        ];
        if device_type == "keepkey" {
            cases.push(args([
                "--emulators",
                "--device-type",
                device_type,
                "--device-path",
                device_path.strip_prefix("udp:").unwrap_or(device_path),
                "enumerate",
            ]));
        }
        cases
    }

    fn args<const N: usize>(items: [&str; N]) -> Vec<String> {
        items.into_iter().map(str::to_owned).collect()
    }

    fn temp_path(name: &str) -> Result<PathBuf> {
        let mut path = env::temp_dir();
        path.push(format!("bhwi-hwi-parity-{name}-{}", std::process::id()));
        if path.exists() {
            fs::remove_dir_all(&path)
                .with_context(|| format!("failed to clean {}", path.display()))?;
        }
        fs::create_dir_all(&path)
            .with_context(|| format!("failed to create {}", path.display()))?;
        Ok(path)
    }

    #[cfg(target_os = "linux")]
    fn write_fake_command(path: &Path, exit_code: i32) -> Result<()> {
        let shell = env::split_paths(&env::var_os("PATH").unwrap_or_default())
            .map(|directory| directory.join("sh"))
            .find(|candidate| candidate.is_file())
            .context("could not find sh on PATH")?;
        fs::write(path, format!("#!{}\nexit {exit_code}\n", shell.display()))
            .with_context(|| format!("failed to write {}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to chmod {}", path.display()))?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn assert_udev_rule_dirs_match(reference: &Path, candidate: &Path) -> Result<()> {
        let mut reference_files = rule_files(reference)?;
        let mut candidate_files = rule_files(candidate)?;
        reference_files.sort();
        candidate_files.sort();

        if reference_files != candidate_files {
            bail!(
                "udev rule file list mismatch\nreference: {:?}\ncandidate: {:?}",
                reference_files,
                candidate_files
            );
        }

        for file_name in reference_files {
            let reference_contents = fs::read(reference.join(&file_name))
                .with_context(|| format!("failed to read reference {file_name}"))?;
            let candidate_contents = fs::read(candidate.join(&file_name))
                .with_context(|| format!("failed to read candidate {file_name}"))?;
            if reference_contents != candidate_contents {
                bail!("udev rule file contents mismatch for {file_name}");
            }
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn rule_files(path: &Path) -> Result<Vec<String>> {
        fs::read_dir(path)
            .with_context(|| format!("failed to read {}", path.display()))?
            .map(|entry| {
                let entry = entry?;
                Ok(entry.file_name().to_string_lossy().into_owned())
            })
            .collect()
    }

    fn normalize_device_type(device_type: &str) -> Result<String> {
        let device_type = device_type.to_ascii_lowercase();
        match device_type.as_str() {
            "bitbox02" | "coldcard" | "jade" | "keepkey" | "ledger" | "trezor" => Ok(device_type),
            _ => bail!("unsupported HWI_PARITY_DEVICE_TYPE {device_type:?}"),
        }
    }

    fn lower_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}
