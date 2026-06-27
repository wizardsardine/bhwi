use std::{
    env,
    ffi::OsStr,
    process::{Command, Output},
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
            assert_enumerate_contains_device("reference", &reference.json, device_type)?;
            assert_enumerate_contains_device("candidate", &candidate.json, device_type)?;
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

    fn assert_enumerate_array(label: &str, json: &Value) -> Result<()> {
        if !json.is_array() {
            bail!(
                "{label} hwi enumerate output was not an array:\n{}",
                serde_json::to_string_pretty(json)?
            );
        }
        Ok(())
    }

    fn assert_enumerate_contains_device(
        label: &str,
        json: &Value,
        device_type: &str,
    ) -> Result<()> {
        if enumerate_contains_device(json, device_type)? {
            return Ok(());
        }

        bail!(
            "{label} hwi enumerate output did not include expected device type {device_type:?}:\n{}",
            serde_json::to_string_pretty(json)?
        );
    }

    fn enumerate_contains_device(json: &Value, device_type: &str) -> Result<bool> {
        let devices = json
            .as_array()
            .with_context(|| "HWI enumerate output was not an array")?;
        Ok(devices
            .iter()
            .any(|device| device.get("type").and_then(Value::as_str) == Some(device_type)))
    }

    fn enumerate_args_from_env() -> Result<(Vec<String>, Option<String>)> {
        match env::var("HWI_PARITY_DEVICE_TYPE") {
            Ok(device_type) => {
                let device_type = normalize_device_type(&device_type)?;
                Ok((
                    vec![
                        "--emulators".to_owned(),
                        "--device-type".to_owned(),
                        device_type.clone(),
                        "enumerate".to_owned(),
                    ],
                    Some(device_type),
                ))
            }
            Err(env::VarError::NotPresent) => Ok((vec!["enumerate".to_owned()], None)),
            Err(err) => Err(err).context("failed to read HWI_PARITY_DEVICE_TYPE"),
        }
    }

    fn normalize_device_type(device_type: &str) -> Result<String> {
        let device_type = device_type.to_ascii_lowercase();
        match device_type.as_str() {
            "coldcard" | "jade" | "ledger" => Ok(device_type),
            _ => bail!("unsupported HWI_PARITY_DEVICE_TYPE {device_type:?}"),
        }
    }
}
