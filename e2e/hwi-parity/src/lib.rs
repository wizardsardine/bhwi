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

    pub fn run_with_envs<I, S>(&self, args: I, envs: &[(&str, &str)]) -> Result<HwiOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = Command::new(&self.path)
            .args(args)
            .envs(envs.iter().copied())
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
    use std::{
        fs,
        io::{Read, Write},
        os::unix::fs::PermissionsExt,
        os::unix::net::UnixDatagram,
        path::{Path, PathBuf},
        str::FromStr,
        time::Duration,
    };

    use bitcoin::{
        Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Witness,
        absolute::LockTime,
        address::Address,
        base64::prelude::{BASE64_STANDARD, Engine as _},
        bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub},
        blockdata::{opcodes::all::OP_CHECKMULTISIG, script::Builder},
        psbt::{Input, Output as PsbtOutput, Psbt},
        secp256k1::Secp256k1,
        transaction::Version as TxVersion,
    };

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

        let singlesig = build_singlesig_signtx_case(&device_type)?;
        assert_signtx_parity(signtx_args(&device_type, &singlesig.psbt), &singlesig)
            .with_context(|| format!("signtx singlesig parity failed for {device_type}"))?;

        if device_type == "ledger" {
            let multisig = build_ledger_multisig_signtx_case(&device_type)?;
            assert_signtx_parity(signtx_args(&device_type, &multisig.psbt), &multisig)
                .context("signtx Ledger multisig parity failed")?;
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

        for (message, path) in signmessage_arg_cases(&device_type)? {
            assert_signmessage_parity(signmessage_args(&device_type, message, path))
                .with_context(|| {
                    format!(
                        "signmessage parity failed for {device_type}, message {message:?}, path {path}"
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
            match case.expect {
                ExpectedResult::Success => assert_displayaddress_parity(case.args.clone())
                    .with_context(|| {
                        format!("displayaddress parity failed for args: {:?}", case.args)
                    })?,
                ExpectedResult::Error => {
                    assert_error_json_parity(case.args.clone()).with_context(|| {
                        format!(
                            "displayaddress error parity failed for args: {:?}",
                            case.args
                        )
                    })?
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
                ExpectedResult::Success => assert_json_parity(case.args.clone())
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

    #[test]
    fn candidate_unsupported_device_actions_match_reference() -> Result<()> {
        if env::var("HWI_BIN").is_err() {
            return Ok(());
        }

        let Some(device_type) = expected_device_type_from_env()? else {
            return Ok(());
        };

        for case in unsupported_device_action_cases(&device_type) {
            if device_type == "coldcard" && case.command == "backup" {
                let candidate =
                    assert_candidate_error_json(case.args.clone()).with_context(|| {
                        format!(
                            "candidate Coldcard backup deviation failed for args: {:?}",
                            case.args
                        )
                    })?;
                assert_eq!(candidate["code"], -9);
                assert_eq!(
                    candidate["error"],
                    "The Coldcard does not support creating a backup via software"
                );
            } else {
                assert_error_json_parity(case.args.clone()).with_context(|| {
                    format!(
                        "unsupported device action parity failed for args: {:?}",
                        case.args
                    )
                })?;
            }
        }

        Ok(())
    }

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

    fn assert_error_json_parity(args: Vec<String>) -> Result<()> {
        let reference = HwiBinary::reference()?.run(args.clone())?;
        let candidate = HwiBinary::candidate()?.run(args)?;

        // Python HWI 3.2.0 sometimes exits 0 for JSON error responses; keep
        // command parity focused on the HWI JSON contract until the dedicated
        // error-model work standardizes process status.
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

    fn assert_candidate_error_json(args: Vec<String>) -> Result<Value> {
        let candidate = HwiBinary::candidate()?.run(args)?;
        assert_error_shape("candidate", &candidate.json)?;
        Ok(candidate.json)
    }

    fn assert_signmessage_parity(args: Vec<String>) -> Result<()> {
        let device_type = arg_value(&args, "--device-type").map(str::to_owned);
        prepare_signmessage_run(&args)?;
        let reference = HwiBinary::reference()?.run(args.clone())?;
        assert_success("reference", &reference)?;
        assert_signmessage_shape("reference", &reference.json)?;

        prepare_signmessage_run(&args)?;
        let candidate = HwiBinary::candidate()?.run(args)?;
        assert_success("candidate", &candidate)?;
        assert_signmessage_shape("candidate", &candidate.json)?;

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

    fn assert_displayaddress_parity(args: Vec<String>) -> Result<()> {
        prepare_displayaddress_run(&args)?;
        let reference = HwiBinary::reference()?.run(args.clone())?;
        assert_success("reference", &reference)?;
        assert_displayaddress_shape("reference", &reference.json)?;

        prepare_displayaddress_run(&args)?;
        let candidate = HwiBinary::candidate()?.run(args)?;
        assert_success("candidate", &candidate)?;
        assert_displayaddress_shape("candidate", &candidate.json)?;

        if reference.json != candidate.json {
            bail!(
                "HWI displayaddress JSON mismatch\nreference:\n{}\ncandidate:\n{}",
                serde_json::to_string_pretty(&reference.json)?,
                serde_json::to_string_pretty(&candidate.json)?
            );
        }

        Ok(())
    }

    fn assert_signtx_parity(args: Vec<String>, case: &SigntxCase) -> Result<()> {
        prepare_signtx_run(&args, case)?;
        let reference = HwiBinary::reference()?.run(args.clone())?;
        assert_success("reference", &reference)?;
        assert_signtx_shape("reference", &reference.json)?;
        let reference_psbt = assert_signed_psbt("reference", &reference.json, case)?;

        prepare_signtx_run(&args, case)?;
        let candidate = HwiBinary::candidate()?.run(args)?;
        assert_success("candidate", &candidate)?;
        assert_signtx_shape("candidate", &candidate.json)?;
        let candidate_psbt = assert_signed_psbt("candidate", &candidate.json, case)?;

        assert_eq!(reference.json["signed"], candidate.json["signed"]);
        assert_eq!(
            reference_psbt.unsigned_tx, candidate_psbt.unsigned_tx,
            "reference and candidate signed different transactions"
        );

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
        assert_exact_keys(label, "signtx", json, &["psbt", "signed"])?;
        assert_string_json_field(label, json, "psbt")?;
        if json.get("signed").and_then(Value::as_bool).is_none() {
            bail!(
                "{label} hwi signtx field \"signed\" was not a bool:\n{}",
                serde_json::to_string_pretty(json)?
            );
        }
        Ok(())
    }

    fn assert_signed_psbt(label: &str, json: &Value, case: &SigntxCase) -> Result<Psbt> {
        if json.get("signed").and_then(Value::as_bool) != Some(true) {
            bail!(
                "{label} hwi signtx did not report signed=true:\n{}",
                serde_json::to_string_pretty(json)?
            );
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
        if !signed_psbt.inputs[0]
            .partial_sigs
            .contains_key(&case.expected_pubkey)
        {
            bail!("{label} hwi signtx did not add the expected device signature");
        }
        Ok(signed_psbt)
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
        expected_pubkey: PublicKey,
        ledger_registers_wallet: bool,
    }

    fn build_singlesig_signtx_case(device_type: &str) -> Result<SigntxCase> {
        let fingerprint = reference_fingerprint(device_type)?;
        let account_xpub = reference_xpub(device_type, "m/84'/1'/0'")?;
        let secp = Secp256k1::verification_only();
        let input_path = DerivationPath::from_str("m/84'/1'/0'/0/0")?;
        let change_path = DerivationPath::from_str("m/84'/1'/0'/1/0")?;
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
        let input_script = Address::p2wpkh(&input_xpub.to_pub(), Network::Testnet).script_pubkey();
        let change_script =
            Address::p2wpkh(&change_xpub.to_pub(), Network::Testnet).script_pubkey();
        let mut psbt = spending_psbt(input_script.clone(), change_script);
        psbt.inputs[0] = Input {
            non_witness_utxo: Some(previous_tx(input_script.clone())),
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: input_script,
            }),
            bip32_derivation: [(input_pubkey.inner, (fingerprint, input_path))].into(),
            ..Default::default()
        };
        psbt.outputs[0] = PsbtOutput {
            bip32_derivation: [(change_pubkey.inner, (fingerprint, change_path))].into(),
            ..Default::default()
        };

        Ok(SigntxCase {
            psbt: psbt.to_string(),
            original: psbt,
            expected_pubkey: input_pubkey,
            ledger_registers_wallet: false,
        })
    }

    fn build_ledger_multisig_signtx_case(device_type: &str) -> Result<SigntxCase> {
        let fingerprint = reference_fingerprint(device_type)?;
        let device_xpub = reference_xpub(device_type, "m/48'/1'/0'/2'")?;
        let device_path = DerivationPath::from_str("m/48'/1'/0'/2'")?;
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
            &change_suffix,
        )?;
        let input_script = multisig_script(2, &receive);
        let change_script = multisig_script(2, &change);
        let mut psbt = spending_psbt(input_script.to_p2wsh(), change_script.to_p2wsh());

        psbt.inputs[0] = Input {
            non_witness_utxo: Some(previous_tx(input_script.to_p2wsh())),
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: input_script.to_p2wsh(),
            }),
            witness_script: Some(input_script),
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
            witness_script: Some(change_script),
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
            expected_pubkey,
            ledger_registers_wallet: true,
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
        suffix: &DerivationPath,
    ) -> Result<Vec<DerivedKey>> {
        let device = device_xpub.derive_pub(secp, suffix)?;
        let cosigner = cosigner_xpub.derive_pub(secp, suffix)?;
        let account_path = DerivationPath::from_str("m/48'/1'/0'/2'")?;
        let mut keys = vec![
            DerivedKey {
                inner: device.public_key,
                fingerprint: device_fingerprint,
                derivation_path: join_derivation_path(&account_path, suffix),
            },
            DerivedKey {
                inner: cosigner.public_key,
                fingerprint: cosigner_fingerprint,
                derivation_path: join_derivation_path(&account_path, suffix),
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

    struct ExpertXpub {
        pubkey: String,
    }

    fn reference_expert_xpub(device_type: &str, path: &str) -> Result<ExpertXpub> {
        let output = HwiBinary::reference()?.run(args([
            "--emulators",
            "--chain",
            "test",
            "--expert",
            "--device-type",
            device_type,
            "getxpub",
            path,
        ]))?;
        assert_success("reference", &output)?;
        Ok(ExpertXpub {
            pubkey: assert_string_json_field("reference", &output.json, "pubkey")?.to_owned(),
        })
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

    fn signmessage_arg_cases(device_type: &str) -> Result<Vec<(&'static str, &'static str)>> {
        let path = match device_type {
            "bitbox02" => "m/49'/1'/0'/0/10",
            "ledger" => "m/44'/1'/0'/0",
            "jade" | "coldcard" => "m/44'/1'/0'",
            _ => bail!("unsupported signmessage device type {device_type:?}"),
        };
        Ok(vec![("hello", path), ("hello world", path)])
    }

    fn displayaddress_arg_cases(device_type: &str) -> Result<Vec<CommandCase>> {
        let fingerprint = reference_fingerprint(device_type)?;
        let wit_xpub = reference_xpub(device_type, "m/84'/1'/0'")?;
        let sh_wit_xpub = reference_xpub(device_type, "m/49'/1'/0'")?;
        let fingerprint = fingerprint.to_string();
        let wit_xpub_string = wit_xpub.to_string();
        let wit_pubkey = lower_hex(&wit_xpub.public_key.serialize());
        let sh_wit_xpub = sh_wit_xpub.to_string();

        let mut cases = vec![
            CommandCase {
                args: displayaddress_path_args(device_type, "sh_wit", "m/49h/1h/0h/0/0"),
                expect: ExpectedResult::Success,
            },
            CommandCase {
                args: displayaddress_path_args(device_type, "wit", "m/84h/1h/0h/0/0"),
                expect: ExpectedResult::Success,
            },
            CommandCase {
                args: displayaddress_desc_args(
                    device_type,
                    &format!("wpkh([{fingerprint}/84h/1h/0h]{wit_xpub_string}/0/0)"),
                ),
                expect: ExpectedResult::Success,
            },
            CommandCase {
                args: displayaddress_desc_args(
                    device_type,
                    &format!("wpkh([{fingerprint}/84h/1h/0h]{wit_pubkey}/0/0)"),
                ),
                expect: ExpectedResult::Success,
            },
            CommandCase {
                args: displayaddress_desc_args(
                    device_type,
                    &format!("sh(wpkh([{fingerprint}/49h/1h/0h]{sh_wit_xpub}/0/0))"),
                ),
                expect: ExpectedResult::Success,
            },
        ];

        if device_type != "bitbox02" {
            let legacy_xpub = reference_xpub(device_type, "m/44'/1'/0'")?.to_string();
            cases.insert(
                0,
                CommandCase {
                    args: displayaddress_path_args(device_type, "legacy", "m/44h/1h/0h/0/0"),
                    expect: ExpectedResult::Success,
                },
            );
            cases.push(CommandCase {
                args: displayaddress_desc_args(
                    device_type,
                    &format!("pkh([{fingerprint}/44h/1h/0h]{legacy_xpub}/0/0)"),
                ),
                expect: ExpectedResult::Success,
            });
        }

        cases.push(CommandCase {
            args: displayaddress_path_args(device_type, "tap", "m/86h/1h/0h/0/0"),
            expect: if device_type == "bitbox02" || device_type == "ledger" {
                ExpectedResult::Success
            } else {
                ExpectedResult::Error
            },
        });
        cases.push(CommandCase {
            args: displayaddress_desc_args(
                device_type,
                &format!("wpkh([00000000/84h/1h/0h]{wit_xpub_string}/0/0)"),
            ),
            expect: ExpectedResult::Error,
        });
        cases.push(CommandCase {
            args: displayaddress_desc_args(
                device_type,
                &format!("wpkh([{fingerprint}/84h/1h/0h]not_an_xpub/0/0)"),
            ),
            expect: ExpectedResult::Error,
        });
        if device_type == "coldcard" {
            // A standalone Python HWI displayaddress run cannot display a
            // Coldcard multisig descriptor until the matching multisig wallet
            // is registered in simulator state. Keep the unregistered-wallet
            // contract in parity here; registered multisig display belongs in a
            // setup-backed case.
            for descriptor in coldcard_multisig_display_descriptors(device_type, &fingerprint)? {
                cases.push(CommandCase {
                    args: displayaddress_desc_args(device_type, &descriptor),
                    expect: ExpectedResult::Error,
                });
            }
        }

        Ok(cases)
    }

    fn coldcard_multisig_display_descriptors(
        device_type: &str,
        fingerprint: &str,
    ) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        for account in 0..3 {
            let origin_path = format!("48h/1h/{account}h/0h/0");
            let full_path = format!("m/{origin_path}/0");
            let expert = reference_expert_xpub(device_type, &full_path)?;
            keys.push(format!("[{fingerprint}/{origin_path}/0]{}", expert.pubkey));
        }
        let keys = keys.join(",");
        Ok(vec![
            format!("sh(sortedmulti(2,{keys}))"),
            format!("wsh(sortedmulti(2,{keys}))"),
            format!("sh(wsh(sortedmulti(2,{keys})))"),
        ])
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

    fn prepare_signmessage_run(args: &[String]) -> Result<()> {
        let Some(device_type) = arg_value(args, "--device-type") else {
            return Ok(());
        };
        match device_type {
            "ledger" => set_ledger_signmessage_automation(),
            "coldcard" => {
                spawn_coldcard_approval();
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn prepare_displayaddress_run(args: &[String]) -> Result<()> {
        let Some(device_type) = arg_value(args, "--device-type") else {
            return Ok(());
        };
        match device_type {
            "ledger" => set_ledger_displayaddress_automation(),
            "coldcard" => {
                spawn_coldcard_approval();
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn prepare_signtx_run(args: &[String], case: &SigntxCase) -> Result<()> {
        let Some(device_type) = arg_value(args, "--device-type") else {
            return Ok(());
        };
        match device_type {
            "ledger" => set_ledger_automation(case.ledger_registers_wallet),
            "coldcard" => {
                spawn_coldcard_approval();
                Ok(())
            }
            _ => Ok(()),
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

    fn send_coldcard_approval() -> Result<()> {
        let client_socket = format!("/tmp/bhwi-hwi-parity-ckcc-{}.sock", std::process::id());
        let _ = std::fs::remove_file(&client_socket);
        let socket = UnixDatagram::bind(&client_socket)?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        socket.connect("/tmp/ckcc-simulator.sock")?;
        coldcard_hid_exchange(&socket, b"XKEYy")?;
        let _ = std::fs::remove_file(client_socket);
        Ok(())
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

    enum ExpectedResult {
        Success,
        Error,
    }

    struct CommandCase {
        args: Vec<String>,
        expect: ExpectedResult,
    }

    struct UnsupportedDeviceActionCase {
        command: &'static str,
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
            expect: if device_type == "ledger" {
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

        vec![
            UnsupportedDeviceActionCase {
                command: "setup",
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
                command: "setup",
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
                command: "wipe",
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
                command: "restore",
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
                command: "restore",
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
                command: "backup",
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
            },
            UnsupportedDeviceActionCase {
                command: "promptpin",
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
                command: "sendpin",
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
                command: "togglepassphrase",
                args: args([
                    "--emulators",
                    "--chain",
                    "test",
                    "--device-type",
                    device_type,
                    "togglepassphrase",
                ]),
            },
        ]
    }

    fn backup_arg_cases(device_type: &str) -> Vec<CommandCase> {
        if device_type != "bitbox02" {
            return Vec::new();
        }

        vec![
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

    fn write_fake_command(path: &Path, exit_code: i32) -> Result<()> {
        fs::write(path, format!("#!/bin/sh\nexit {exit_code}\n"))
            .with_context(|| format!("failed to write {}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to chmod {}", path.display()))?;
        Ok(())
    }

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
            "bitbox02" | "coldcard" | "jade" | "ledger" => Ok(device_type),
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
