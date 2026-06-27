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
    let reference = HwiBinary::reference()?.run(args.clone())?;
    let candidate = HwiBinary::candidate()?.run(args)?;

    if reference.json != candidate.json {
        bail!(
            "HWI JSON mismatch\nreference:\n{}\ncandidate:\n{}",
            serde_json::to_string_pretty(&reference.json)?,
            serde_json::to_string_pretty(&candidate.json)?
        );
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_binary_enumerate_is_json_or_reports_clear_error() -> Result<()> {
        if env::var("REFERENCE_HWI_BIN").is_err() {
            return Ok(());
        }

        let output = HwiBinary::reference()?.run(["enumerate"])?;
        assert!(output.json.is_array(), "unexpected enumerate shape");
        Ok(())
    }

    #[test]
    fn candidate_parity_smoke_is_env_gated() -> Result<()> {
        if env::var("HWI_BIN").is_err() {
            return Ok(());
        }

        assert_json_parity(["enumerate"])?;
        Ok(())
    }
}
