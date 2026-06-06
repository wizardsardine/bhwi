use std::{
    env,
    process::{Command, Output},
    str::FromStr,
};

use anyhow::{Context, Result, anyhow, bail};
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use miniscript::{
    Descriptor, DescriptorPublicKey,
    descriptor::{DescriptorType, DescriptorXKey, Wildcard, Wpkh},
};
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

    pub(crate) fn json(&self) -> Self {
        self.clone().with_args(["--format", "json"])
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

    pub(crate) fn assert_failure_contains<I, S>(&self, args: I, needle: &str) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let args = self.command_args(args);
        let output = bhwi(&args)?;
        assert!(
            !output.status.success(),
            "bhwi {args:?} unexpectedly succeeded with stdout:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let stderr = String::from_utf8(output.stderr)?;
        assert!(
            stderr.contains(needle),
            "stderr did not contain {needle:?}\nstderr:\n{stderr}"
        );
        Ok(())
    }
}

pub(crate) struct CommandCase<'a> {
    pub(crate) name: &'a str,
    pub(crate) cli: Cli,
    pub(crate) args: &'a [&'a str],
    pub(crate) expected: ExpectedOutput<'a>,
}

pub(crate) enum ExpectedOutput<'a> {
    Static(&'a str),
    DescriptorPubkeys { fingerprint: &'a str },
}

impl ExpectedOutput<'_> {
    fn render(&self) -> Result<String> {
        match self {
            Self::Static(output) => Ok((*output).to_string()),
            Self::DescriptorPubkeys { fingerprint } => descriptor_stdout_for_device(fingerprint),
        }
    }
}

pub(crate) fn run_command_cases(cases: &[CommandCase<'_>]) -> Result<()> {
    for case in cases {
        let expected = case
            .expected
            .render()
            .with_context(|| format!("failed to build expected output for {}", case.name))?;
        let stdout = case
            .cli
            .run_ok(case.args)
            .with_context(|| format!("failed to run {}", case.name))?;
        assert_eq!(stdout, format!("{expected}\n"), "{}", case.name);
    }
    Ok(())
}

pub(crate) fn basic_cli_cases<'a>(fingerprint: &'a str, xpub: &'a str) -> Vec<CommandCase<'a>> {
    vec![
        CommandCase {
            name: "device list",
            cli: Cli::global(),
            args: &["device", "list"],
            expected: ExpectedOutput::Static(fingerprint),
        },
        CommandCase {
            name: "xpub get m/44'/1'/0'",
            cli: Cli::for_device(fingerprint),
            args: &["xpub", "get", "m/44'/1'/0'"],
            expected: ExpectedOutput::Static(xpub),
        },
        CommandCase {
            name: "descriptor pubkeys account 0",
            cli: Cli::for_device(fingerprint),
            args: &["descriptor", "pubkeys", "--account", "0"],
            expected: ExpectedOutput::DescriptorPubkeys { fingerprint },
        },
    ]
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

fn descriptor_stdout(fingerprint: &str, xpubs: [&str; 4]) -> Result<String> {
    struct DescriptorCase {
        desc_type: DescriptorType,
        purpose: &'static str,
        xpub_index: usize,
    }

    let cases = [
        DescriptorCase {
            desc_type: DescriptorType::Pkh,
            purpose: "44",
            xpub_index: 0,
        },
        DescriptorCase {
            desc_type: DescriptorType::Wpkh,
            purpose: "84",
            xpub_index: 2,
        },
        DescriptorCase {
            desc_type: DescriptorType::ShWpkh,
            purpose: "49",
            xpub_index: 1,
        },
        DescriptorCase {
            desc_type: DescriptorType::Tr,
            purpose: "86",
            xpub_index: 3,
        },
    ];
    let mut rendered = Vec::new();
    for change in [0, 1] {
        for case in &cases {
            let origin = format!("m/{}'/1'/0'", case.purpose);
            rendered.push(descriptor(
                case.desc_type,
                fingerprint,
                &origin,
                xpubs[case.xpub_index],
                &format!("m/{change}"),
            )?);
        }
    }
    Ok(rendered.join("\n"))
}

fn descriptor_xpubs(fingerprint: &str) -> Result<[String; 4]> {
    let cli = Cli::for_device(fingerprint);
    Ok([
        cli.run_ok(["xpub", "get", "m/44'/1'/0'"])?
            .trim()
            .to_string(),
        cli.run_ok(["xpub", "get", "m/49'/1'/0'"])?
            .trim()
            .to_string(),
        cli.run_ok(["xpub", "get", "m/84'/1'/0'"])?
            .trim()
            .to_string(),
        cli.run_ok(["xpub", "get", "m/86'/1'/0'"])?
            .trim()
            .to_string(),
    ])
}

fn descriptor_stdout_for_device(fingerprint: &str) -> Result<String> {
    let xpubs = descriptor_xpubs(fingerprint)?;
    descriptor_stdout(fingerprint, [&xpubs[0], &xpubs[1], &xpubs[2], &xpubs[3]])
}

fn descriptor(
    desc_type: DescriptorType,
    fingerprint: &str,
    origin: &str,
    xpub: &str,
    suffix: &str,
) -> Result<String> {
    let key = DescriptorPublicKey::XPub(DescriptorXKey {
        origin: Some((
            Fingerprint::from_str(fingerprint)?,
            DerivationPath::from_str(origin)?,
        )),
        xkey: Xpub::from_str(xpub)?,
        derivation_path: DerivationPath::from_str(suffix)?,
        wildcard: Wildcard::Unhardened,
    });
    let desc = match desc_type {
        DescriptorType::Pkh => Descriptor::new_pkh(key)?,
        DescriptorType::Wpkh => Descriptor::new_wpkh(key)?,
        DescriptorType::ShWpkh => Descriptor::new_sh_with_wpkh(Wpkh::new(key)?),
        DescriptorType::Tr => Descriptor::new_tr(key, None)?,
        _ => return Err(anyhow!("unsupported descriptor type")),
    };
    Ok(format!("{desc:#}"))
}
