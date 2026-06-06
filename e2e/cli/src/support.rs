use std::{
    env,
    process::{Command, Output},
};

use anyhow::{Context, Result, bail};

#[derive(Clone, Debug)]
pub(crate) struct Cli {
    args: Vec<String>,
}

impl Cli {
    pub(crate) fn global() -> Self {
        Self {
            args: vec!["--network".to_string(), "testnet".to_string()],
        }
    }

    pub(crate) fn for_device(fingerprint: &str) -> Self {
        Self::global().with_args(["--fingerprint", fingerprint])
    }

    pub(crate) fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.args
            .extend(args.into_iter().map(|arg| arg.as_ref().to_string()));
        self
    }

    fn command_args<I, S>(&self, args: I) -> Vec<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut command_args = self.args.clone();
        command_args.extend(args.into_iter().map(|arg| arg.as_ref().to_string()));
        command_args
    }

    pub(crate) fn run_ok<I, S>(&self, args: I) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        run_ok(&self.command_args(args))
    }
}

pub(crate) struct CommandCase<'a> {
    pub(crate) name: &'a str,
    pub(crate) cli: Cli,
    pub(crate) args: &'a [&'a str],
    pub(crate) expected: ExpectedOutput<'a>,
}

pub(crate) enum ExpectedOutput<'a> {
    Exact(&'a str),
    DescriptorPubkeys { fingerprint: &'a str, account: u32 },
}

impl ExpectedOutput<'_> {
    fn assert_stdout(&self, name: &str, stdout: &str) -> Result<()> {
        match self {
            Self::Exact(output) => assert_eq!(stdout, format!("{output}\n"), "{name}"),
            Self::DescriptorPubkeys {
                fingerprint,
                account,
            } => assert_descriptor_pubkeys(name, stdout, fingerprint, *account)?,
        }
        Ok(())
    }
}

pub(crate) fn assert_command(case: CommandCase<'_>) -> Result<()> {
    let stdout = case
        .cli
        .run_ok(case.args)
        .with_context(|| format!("failed to run {}", case.name))?;
    case.expected
        .assert_stdout(case.name, &stdout)
        .with_context(|| format!("unexpected output for {}", case.name))?;
    Ok(())
}

fn bhwi(args: &[String]) -> Result<Output> {
    let bin = env::var("BHWI_BIN").context("BHWI_BIN must point to the built bhwi binary")?;
    Command::new(bin)
        .args(args)
        .output()
        .context("failed to spawn bhwi")
}

fn run_ok(args: &[String]) -> Result<String> {
    let output = bhwi(args)?;
    ensure_success(args, output)
}

fn ensure_success(args: &[String], output: Output) -> Result<String> {
    if !output.status.success() {
        bail!(
            "bhwi {:?} failed with status {}\nstdout:\n{}\nstderr:\n{}",
            args,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stderr = String::from_utf8(output.stderr)?;
    if !stderr.is_empty() {
        bail!(
            "bhwi {:?} succeeded with unexpected stderr\nstdout:\n{}\nstderr:\n{}",
            args,
            String::from_utf8_lossy(&output.stdout),
            stderr
        );
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn assert_descriptor_pubkeys(
    name: &str,
    stdout: &str,
    fingerprint: &str,
    account: u32,
) -> Result<()> {
    struct DescriptorLine<'a> {
        prefix: &'static str,
        purpose: u32,
        xpub: &'a str,
    }

    let xpub_44 = descriptor_xpub(fingerprint, 44, account)?;
    let xpub_49 = descriptor_xpub(fingerprint, 49, account)?;
    let xpub_84 = descriptor_xpub(fingerprint, 84, account)?;
    let xpub_86 = descriptor_xpub(fingerprint, 86, account)?;
    let expected = [
        DescriptorLine {
            prefix: "pkh(",
            purpose: 44,
            xpub: &xpub_44,
        },
        DescriptorLine {
            prefix: "wpkh(",
            purpose: 84,
            xpub: &xpub_84,
        },
        DescriptorLine {
            prefix: "sh(wpkh(",
            purpose: 49,
            xpub: &xpub_49,
        },
        DescriptorLine {
            prefix: "tr(",
            purpose: 86,
            xpub: &xpub_86,
        },
    ];

    assert!(
        stdout.ends_with('\n'),
        "{name}: stdout should end with newline"
    );
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), expected.len() * 2, "{name}: descriptor count");

    for (change, lines) in [0, 1].into_iter().zip(lines.chunks_exact(expected.len())) {
        for (line, expected) in lines.iter().zip(expected.iter()) {
            let origin = format!("[{fingerprint}/{}'/1'/{account}']", expected.purpose);
            let suffix = format!("/{change}/*");
            assert!(
                line.starts_with(expected.prefix),
                "{name}: descriptor `{line}` should start with `{}`",
                expected.prefix
            );
            assert!(
                line.contains(&origin),
                "{name}: descriptor `{line}` should contain origin `{origin}`"
            );
            assert!(
                line.contains(&suffix),
                "{name}: descriptor `{line}` should contain suffix `{suffix}`"
            );
            assert!(
                line.contains(expected.xpub),
                "{name}: descriptor `{line}` should contain purpose {} xpub `{}`",
                expected.purpose,
                expected.xpub
            );
        }
    }
    Ok(())
}

fn descriptor_xpub(fingerprint: &str, purpose: u32, account: u32) -> Result<String> {
    Ok(Cli::for_device(fingerprint)
        .run_ok(["xpub", "get", &format!("m/{purpose}'/1'/{account}'")])?
        .trim()
        .to_string())
}
