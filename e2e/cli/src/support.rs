use std::{
    env,
    io::{self, Read},
    process::{Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};

pub(crate) const COMMAND_TIMEOUT: Duration = Duration::from_secs(180);
const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Clone)]
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

    pub(crate) fn command<I, S>(&self, args: I) -> Result<Command>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        bhwi_command(&self.command_args(args))
    }

    pub(crate) fn run_output<I, S>(&self, args: I) -> Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        bhwi(&self.command_args(args))
    }

    pub(crate) fn run_output_cancellable<I, S>(
        &self,
        args: I,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let args = self.command_args(args);
        bhwi_with_control(&args, COMMAND_TIMEOUT, cancelled)
    }

    pub(crate) fn run_ok<I, S>(&self, args: I) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        run_ok(&self.command_args(args))
    }

    pub(crate) fn run_ok_cancellable<I, S>(
        &self,
        args: I,
        cancelled: Arc<AtomicBool>,
    ) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let args = self.command_args(args);
        let output = bhwi_with_control(&args, COMMAND_TIMEOUT, cancelled)?;
        ensure_success(&args, output)
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
    DescriptorPubkeys {
        fingerprint: &'a str,
        account: u32,
    },
    Keypool {
        fingerprint: &'a str,
        purpose: u32,
        account: u32,
        branch: u32,
        start: u32,
        end: u32,
        internal: bool,
    },
}

impl ExpectedOutput<'_> {
    fn assert_stdout(&self, name: &str, stdout: &str) -> Result<()> {
        match self {
            Self::Exact(output) => assert_eq!(stdout, format!("{output}\n"), "{name}"),
            Self::DescriptorPubkeys {
                fingerprint,
                account,
            } => assert_descriptor_pubkeys(name, stdout, fingerprint, *account)?,
            Self::Keypool {
                fingerprint,
                purpose,
                account,
                branch,
                start,
                end,
                internal,
            } => assert_keypool(
                name,
                stdout,
                KeypoolExpectation {
                    fingerprint,
                    purpose: *purpose,
                    account: *account,
                    branch: *branch,
                    start: *start,
                    end: *end,
                    internal: *internal,
                },
            )?,
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

fn bhwi_command(args: &[String]) -> Result<Command> {
    let bin = env::var("BHWI_BIN").context("BHWI_BIN must point to the built bhwi binary")?;
    let mut command = Command::new(bin);
    command.args(args);
    Ok(command)
}

fn bhwi(args: &[String]) -> Result<Output> {
    bhwi_with_control(args, COMMAND_TIMEOUT, Arc::new(AtomicBool::new(false)))
}

fn bhwi_with_control(
    args: &[String],
    timeout: Duration,
    cancelled: Arc<AtomicBool>,
) -> Result<Output> {
    command_output(bhwi_command(args)?, args, timeout, cancelled)
}

fn command_output(
    mut command: Command,
    args: &[String],
    timeout: Duration,
    cancelled: Arc<AtomicBool>,
) -> Result<Output> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Stop {
        Exited,
        TimedOut,
        Cancelled,
        WaitFailed,
    }

    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn bhwi")?;
    let mut stdout = child.stdout.take().expect("stdout was piped");
    let mut stderr = child.stderr.take().expect("stderr was piped");
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes)?;
        Ok::<_, io::Error>(bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes)?;
        Ok::<_, io::Error>(bytes)
    });

    let started = Instant::now();
    let mut status = None;
    let mut wait_error = None;
    let stop = loop {
        if cancelled.load(Ordering::Acquire) {
            break Stop::Cancelled;
        }
        match child.try_wait() {
            Ok(Some(exit_status)) => {
                status = Some(exit_status);
                break Stop::Exited;
            }
            Ok(None) => {}
            Err(error) => {
                wait_error = Some(error);
                break Stop::WaitFailed;
            }
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break Stop::TimedOut;
        }
        thread::sleep(COMMAND_POLL_INTERVAL.min(remaining));
    };

    let reap_error = if stop != Stop::Exited {
        cancelled.store(true, Ordering::Release);
        let _ = child.kill();
        child.wait().err()
    } else {
        None
    };

    let stdout = stdout_reader.join();
    let stderr = stderr_reader.join();
    let stdout = stdout
        .map_err(|_| anyhow!("bhwi stdout reader panicked"))?
        .context("read bhwi stdout")?;
    let stderr = stderr
        .map_err(|_| anyhow!("bhwi stderr reader panicked"))?
        .context("read bhwi stderr")?;

    if let Some(error) = reap_error {
        return Err(error).context("kill and reap bhwi");
    }
    if let Some(error) = wait_error {
        return Err(error).context("poll bhwi process");
    }
    match stop {
        Stop::TimedOut => {
            let reason = format!("timed out after {timeout:?}");
            return Err(stopped_command_error(args, &reason, &stdout, &stderr));
        }
        Stop::Cancelled => {
            return Err(stopped_command_error(
                args,
                "was cancelled",
                &stdout,
                &stderr,
            ));
        }
        Stop::Exited => {}
        Stop::WaitFailed => unreachable!("wait error handled above"),
    }

    Ok(Output {
        status: status.context("bhwi exited without a status")?,
        stdout,
        stderr,
    })
}

fn stopped_command_error(
    args: &[String],
    reason: &str,
    stdout: &[u8],
    stderr: &[u8],
) -> anyhow::Error {
    let (stdout, stderr) = if command_output_is_sensitive(args) {
        ("<redacted>".to_owned(), "<redacted>".to_owned())
    } else {
        (
            String::from_utf8_lossy(stdout).into_owned(),
            String::from_utf8_lossy(stderr).into_owned(),
        )
    };
    anyhow!(
        "bhwi {:?} {reason}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        redacted_args(args)
    )
}

fn command_output_is_sensitive(args: &[String]) -> bool {
    args.iter().any(|arg| {
        matches!(
            arg.as_str(),
            "sign-psbt"
                | "signtx"
                | "--psbt"
                | "--passphrase"
                | "--password"
                | "-p"
                | "--backup-passphrase"
                | "--backup_passphrase"
                | "send-pin"
                | "sendpin"
        ) || arg.starts_with("--psbt=")
            || arg.starts_with("--passphrase=")
            || arg.starts_with("--password=")
            || arg.starts_with("--backup-passphrase=")
            || arg.starts_with("--backup_passphrase=")
    })
}

fn run_ok(args: &[String]) -> Result<String> {
    let output = bhwi(args)?;
    ensure_success(args, output)
}

fn ensure_success(args: &[String], output: Output) -> Result<String> {
    let hide_output = args
        .iter()
        .any(|arg| matches!(arg.as_str(), "sign-psbt" | "signtx" | "--psbt"));
    let safe_stdout = || {
        if hide_output {
            "<redacted>".to_owned()
        } else {
            String::from_utf8_lossy(&output.stdout).into_owned()
        }
    };
    let safe_stderr = || {
        if hide_output {
            "<redacted>".to_owned()
        } else {
            String::from_utf8_lossy(&output.stderr).into_owned()
        }
    };
    let args = redacted_args(args);
    if !output.status.success() {
        bail!(
            "bhwi {:?} failed with status {}\nstdout:\n{}\nstderr:\n{}",
            args,
            output.status,
            safe_stdout(),
            safe_stderr()
        );
    }
    let stderr = String::from_utf8(output.stderr)?;
    if !stderr.is_empty() {
        bail!(
            "bhwi {:?} succeeded with unexpected stderr\nstdout:\n{}\nstderr:\n{}",
            args,
            safe_stdout(),
            if hide_output { "<redacted>" } else { &stderr }
        );
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn redacted_args(args: &[String]) -> Vec<String> {
    let mut redact_next = false;
    args.iter()
        .map(|arg| {
            if redact_next {
                redact_next = false;
                return "<redacted>".to_owned();
            }
            if matches!(
                arg.as_str(),
                "--passphrase"
                    | "--password"
                    | "-p"
                    | "--psbt"
                    | "--backup-passphrase"
                    | "--backup_passphrase"
                    | "send-pin"
                    | "sendpin"
                    | "signtx"
            ) {
                redact_next = true;
                return arg.clone();
            }
            if arg.starts_with("--passphrase=")
                || arg.starts_with("--password=")
                || arg.starts_with("--psbt=")
                || arg.starts_with("--backup-passphrase=")
                || arg.starts_with("--backup_passphrase=")
            {
                return format!("{}=<redacted>", arg.split_once('=').unwrap().0);
            }
            arg.clone()
        })
        .collect()
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

struct KeypoolExpectation<'a> {
    fingerprint: &'a str,
    purpose: u32,
    account: u32,
    branch: u32,
    start: u32,
    end: u32,
    internal: bool,
}

fn assert_keypool(name: &str, stdout: &str, expected: KeypoolExpectation<'_>) -> Result<()> {
    let xpub = descriptor_xpub(expected.fingerprint, expected.purpose, expected.account)?;
    let origin = format!(
        "[{}/{}'/1'/{}']",
        expected.fingerprint, expected.purpose, expected.account
    );
    let suffix = format!("/{branch}/*", branch = expected.branch);
    let metadata = format!(
        " range={}-{} internal={} keypool=true",
        expected.start, expected.end, expected.internal
    );

    assert!(
        stdout.ends_with('\n'),
        "{name}: stdout should end with newline"
    );
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{name}: keypool descriptor count");
    let line = lines[0];
    assert!(
        line.starts_with("wpkh("),
        "{name}: keypool descriptor `{line}` should start with `wpkh(`"
    );
    assert!(
        line.contains(&origin),
        "{name}: keypool descriptor `{line}` should contain origin `{origin}`"
    );
    assert!(
        line.contains(&xpub),
        "{name}: keypool descriptor `{line}` should contain xpub `{xpub}`"
    );
    assert!(
        line.contains(&suffix),
        "{name}: keypool descriptor `{line}` should contain suffix `{suffix}`"
    );
    assert!(
        line.ends_with(&metadata),
        "{name}: keypool descriptor `{line}` should end with metadata `{metadata}`"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{command_output, redacted_args};

    #[test]
    fn diagnostics_redact_secrets_and_psbt_paths() {
        let args = [
            "--passphrase",
            "secret",
            "sign-psbt",
            "--psbt",
            "wallet.psbt",
        ]
        .map(str::to_owned);
        assert_eq!(
            redacted_args(&args),
            [
                "--passphrase",
                "<redacted>",
                "sign-psbt",
                "--psbt",
                "<redacted>"
            ]
            .map(str::to_owned)
        );
        let args = ["device", "send-pin", "1234"].map(str::to_owned);
        assert_eq!(
            redacted_args(&args),
            ["device", "send-pin", "<redacted>"].map(str::to_owned)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn timed_out_command_is_killed_and_reaped() {
        use std::{
            env, fs,
            path::Path,
            process::{self, Command},
            sync::{Arc, atomic::AtomicBool},
            time::{Duration, SystemTime, UNIX_EPOCH},
        };

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_nanos();
        let pid_file =
            env::temp_dir().join(format!("bhwi-e2e-timeout-{}-{nonce}.pid", process::id()));
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("printf '%s' \"$$\" > \"$1\"; printf stdout-secret; printf stderr-secret >&2; exec sleep 30")
            .arg("bhwi-timeout-test")
            .arg(&pid_file);
        let error = command_output(
            command,
            &["--passphrase".to_owned(), "argument-secret".to_owned()],
            Duration::from_millis(100),
            Arc::new(AtomicBool::new(false)),
        )
        .expect_err("command should time out");
        let diagnostic = error.to_string();
        assert!(diagnostic.contains("timed out"));
        assert!(diagnostic.contains("<redacted>"));
        assert!(!diagnostic.contains("argument-secret"));
        assert!(!diagnostic.contains("stdout-secret"));
        assert!(!diagnostic.contains("stderr-secret"));

        let pid = fs::read_to_string(&pid_file).expect("timed-out child should record its pid");
        fs::remove_file(pid_file).expect("remove child pid file");
        assert!(
            !Path::new("/proc").join(pid.trim()).exists(),
            "timed-out child was not reaped"
        );
    }
}
