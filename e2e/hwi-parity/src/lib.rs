use std::{
    env,
    ffi::OsStr,
    io::Write,
    process::{Command, Output, Stdio},
};

use anyhow::{Context, Result, bail};
use serde_json::Value;

#[derive(Clone, Debug)]
pub struct HwiBinary {
    label: &'static str,
    path: String,
}

#[derive(Clone, Debug)]
pub struct HwiOutput {
    pub status_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub json: Value,
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
        let output = Command::new(&self.path)
            .args(args)
            .output()
            .with_context(|| format!("failed to spawn {} hwi at {}", self.label, self.path))?;
        parse_output(self.label, output)
    }

    pub fn run_with_stdin<I, S>(&self, args: I, stdin: &str) -> Result<HwiOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut child = Command::new(&self.path)
            .args(args)
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

        parse_output(self.label, child.wait_with_output()?)
    }
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
    let json = serde_json::from_str(stdout.trim()).with_context(|| {
        format!(
            "{label} hwi stdout was not JSON\nstatus: {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        )
    })?;

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
            "{label} hwi exited unsuccessfully\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status_code,
            output.stdout,
            output.stderr
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn candidate_enumerate_matches_reference() -> Result<()> {
        if env::var("HWI_BIN").is_err() {
            return Ok(());
        }

        let (args, expected_device_type) = enumerate_args_from_env()?;
        assert_enumerate_parity(args, expected_device_type.as_deref())?;
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

        for args in getmasterxpub_arg_cases(&device_type) {
            assert_getmasterxpub_parity(args.clone())
                .with_context(|| format!("getmasterxpub parity failed for args: {args:?}"))?;
        }

        Ok(())
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

    fn getmasterxpub_arg_cases(device_type: &str) -> Vec<Vec<String>> {
        vec![
            args([
                "--emulators",
                "--chain",
                "test",
                "--device-type",
                device_type,
                "getmasterxpub",
            ]),
            args([
                "--emulators",
                "--chain",
                "test",
                "--expert",
                "--device-type",
                device_type,
                "getmasterxpub",
            ]),
            args([
                "--emulators",
                "--chain",
                "test",
                "--device-type",
                device_type,
                "getmasterxpub",
                "--account",
                "1",
            ]),
            args([
                "--emulators",
                "--chain",
                "test",
                "--device-type",
                device_type,
                "getmasterxpub",
                "--addr-type",
                "legacy",
            ]),
            args([
                "--emulators",
                "--chain",
                "test",
                "--device-type",
                device_type,
                "getmasterxpub",
                "--addr-type",
                "sh_wit",
            ]),
            args([
                "--emulators",
                "--chain",
                "test",
                "--device-type",
                device_type,
                "getmasterxpub",
                "--addr-type",
                "wit",
            ]),
            args([
                "--emulators",
                "--chain",
                "test",
                "--device-type",
                device_type,
                "getmasterxpub",
                "--addr-type",
                "tap",
            ]),
        ]
    }

    fn getxpub_arg_cases(device_type: &str) -> Vec<Vec<String>> {
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

    fn enumerate_python_hwi_arg_cases(
        device_type: &str,
        device_path: &str,
        fingerprint: &str,
    ) -> Vec<Vec<String>> {
        vec![
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
        ]
    }

    fn args<const N: usize>(items: [&str; N]) -> Vec<String> {
        items.into_iter().map(str::to_owned).collect()
    }

    fn normalize_device_type(device_type: &str) -> Result<String> {
        let device_type = device_type.to_ascii_lowercase();
        match device_type.as_str() {
            "coldcard" | "jade" | "ledger" => Ok(device_type),
            _ => bail!("unsupported HWI_PARITY_DEVICE_TYPE {device_type:?}"),
        }
    }
}
