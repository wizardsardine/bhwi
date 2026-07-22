use std::{
    env,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::DeviceType;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum UdevRuleSelection {
    All,
    Devices(Vec<DeviceType>),
}

#[derive(Debug)]
pub enum UdevInstallError {
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    CommandSpawn {
        program: String,
        source: io::Error,
    },
    CommandFailed {
        program: String,
        args: Vec<String>,
        code: Option<i32>,
    },
    MissingUser,
}

impl UdevInstallError {
    pub fn needs_root(&self) -> bool {
        match self {
            Self::Io { source, .. } => source.kind() == io::ErrorKind::PermissionDenied,
            Self::CommandFailed { .. } => true,
            Self::CommandSpawn { .. } | Self::MissingUser => false,
        }
    }
}

impl fmt::Display for UdevInstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                action,
                path,
                source,
            } => write!(f, "failed to {action} {}: {source}", path.display()),
            Self::CommandSpawn { program, source } => {
                write!(f, "failed to run {program}: {source}")
            }
            Self::CommandFailed {
                program,
                args,
                code,
            } => {
                write!(
                    f,
                    "{} {} failed with status {}",
                    program,
                    args.join(" "),
                    code.map_or_else(|| "unknown".to_owned(), |code| code.to_string())
                )
            }
            Self::MissingUser => write!(f, "could not determine current user"),
        }
    }
}

impl Error for UdevInstallError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } | Self::CommandSpawn { source, .. } => Some(source),
            Self::CommandFailed { .. } | Self::MissingUser => None,
        }
    }
}

pub fn install_udev_rules(
    location: &Path,
    selection: UdevRuleSelection,
) -> Result<(), UdevInstallError> {
    let user = current_user()?;
    let mut runner = SystemCommandRunner;
    install_udev_rules_with_runner(location, &selection, &mut runner, &user)
}

pub fn udev_rule_names(selection: &UdevRuleSelection) -> Vec<&'static str> {
    rules_for_selection(selection)
        .into_iter()
        .map(|rule| rule.name)
        .collect()
}

fn install_udev_rules_with_runner(
    location: &Path,
    selection: &UdevRuleSelection,
    runner: &mut dyn CommandRunner,
    user: &str,
) -> Result<(), UdevInstallError> {
    copy_udev_rule_files(location, selection)?;
    runner.run("udevadm", &["trigger"])?;
    runner.run("udevadm", &["control", "--reload-rules"])?;
    match runner.run("groupadd", &["plugdev"]) {
        Ok(()) => {}
        Err(UdevInstallError::CommandFailed { code: Some(9), .. }) => {}
        Err(err) => return Err(err),
    }
    runner.run("usermod", &["-aG", "plugdev", user])?;
    Ok(())
}

fn copy_udev_rule_files(
    location: &Path,
    selection: &UdevRuleSelection,
) -> Result<(), UdevInstallError> {
    for rule in rules_for_selection(selection) {
        let path = location.join(rule.name);
        fs::write(&path, rule.contents).map_err(|source| UdevInstallError::Io {
            action: "write",
            path: path.clone(),
            source,
        })?;

        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).map_err(|source| {
            UdevInstallError::Io {
                action: "chmod",
                path: path.clone(),
                source,
            }
        })?;
    }
    Ok(())
}

fn current_user() -> Result<String, UdevInstallError> {
    ["SUDO_USER", "USER", "LOGNAME"]
        .into_iter()
        .find_map(|name| env::var(name).ok().filter(|value| !value.is_empty()))
        .ok_or(UdevInstallError::MissingUser)
}

trait CommandRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<(), UdevInstallError>;
}

struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<(), UdevInstallError> {
        let status = Command::new(program)
            .args(args)
            .status()
            .map_err(|source| UdevInstallError::CommandSpawn {
                program: program.to_owned(),
                source,
            })?;
        if status.success() {
            Ok(())
        } else {
            Err(UdevInstallError::CommandFailed {
                program: program.to_owned(),
                args: args.iter().map(|arg| (*arg).to_owned()).collect(),
                code: status.code(),
            })
        }
    }
}

#[derive(Debug)]
struct UdevRule {
    name: &'static str,
    contents: &'static str,
    device_type: Option<DeviceType>,
}

fn rules_for_selection(selection: &UdevRuleSelection) -> Vec<&'static UdevRule> {
    match selection {
        UdevRuleSelection::All => UDEV_RULES.iter().collect(),
        UdevRuleSelection::Devices(device_types) => UDEV_RULES
            .iter()
            .filter(|rule| {
                rule.device_type
                    .is_some_and(|device_type| device_types.contains(&device_type))
            })
            .collect(),
    }
}

const UDEV_RULES: &[UdevRule] = &[
    UdevRule {
        name: "20-hw1.rules",
        contents: include_str!("udev/20-hw1.rules"),
        device_type: Some(DeviceType::Ledger),
    },
    UdevRule {
        name: "51-coinkite.rules",
        contents: include_str!("udev/51-coinkite.rules"),
        device_type: Some(DeviceType::Coldcard),
    },
    UdevRule {
        name: "51-hid-digitalbitbox.rules",
        contents: include_str!("udev/51-hid-digitalbitbox.rules"),
        device_type: None,
    },
    UdevRule {
        name: "51-trezor.rules",
        contents: include_str!("udev/51-trezor.rules"),
        device_type: None,
    },
    UdevRule {
        name: "51-usb-keepkey.rules",
        contents: include_str!("udev/51-usb-keepkey.rules"),
        device_type: None,
    },
    UdevRule {
        name: "52-hid-digitalbitbox.rules",
        contents: include_str!("udev/52-hid-digitalbitbox.rules"),
        device_type: None,
    },
    UdevRule {
        name: "53-hid-bitbox02.rules",
        contents: include_str!("udev/53-hid-bitbox02.rules"),
        device_type: None,
    },
    UdevRule {
        name: "54-hid-bitbox02.rules",
        contents: include_str!("udev/54-hid-bitbox02.rules"),
        device_type: None,
    },
    UdevRule {
        name: "55-usb-jade.rules",
        contents: include_str!("udev/55-usb-jade.rules"),
        device_type: Some(DeviceType::Jade),
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn selects_native_device_rule_files() {
        assert_eq!(
            udev_rule_names(&UdevRuleSelection::Devices(vec![DeviceType::Ledger])),
            vec!["20-hw1.rules"]
        );
        assert_eq!(
            udev_rule_names(&UdevRuleSelection::Devices(vec![DeviceType::Coldcard])),
            vec!["51-coinkite.rules"]
        );
        assert_eq!(
            udev_rule_names(&UdevRuleSelection::Devices(vec![DeviceType::Jade])),
            vec!["55-usb-jade.rules"]
        );
    }

    #[test]
    fn selects_all_hwi_rule_files() {
        assert_eq!(
            udev_rule_names(&UdevRuleSelection::All),
            vec![
                "20-hw1.rules",
                "51-coinkite.rules",
                "51-hid-digitalbitbox.rules",
                "51-trezor.rules",
                "51-usb-keepkey.rules",
                "52-hid-digitalbitbox.rules",
                "53-hid-bitbox02.rules",
                "54-hid-bitbox02.rules",
                "55-usb-jade.rules",
            ]
        );
    }

    #[test]
    fn copies_files_and_runs_install_commands() {
        let temp = test_dir("copies_files_and_runs_install_commands");
        fs::create_dir_all(&temp).expect("temp dir");
        let mut runner = FakeCommandRunner::default();

        install_udev_rules_with_runner(
            &temp,
            &UdevRuleSelection::Devices(vec![DeviceType::Ledger, DeviceType::Jade]),
            &mut runner,
            "alice",
        )
        .expect("install rules");

        assert!(temp.join("20-hw1.rules").exists());
        assert!(temp.join("55-usb-jade.rules").exists());
        assert!(!temp.join("51-coinkite.rules").exists());
        assert_eq!(
            runner.commands,
            vec![
                command("udevadm", &["trigger"]),
                command("udevadm", &["control", "--reload-rules"]),
                command("groupadd", &["plugdev"]),
                command("usermod", &["-aG", "plugdev", "alice"]),
            ]
        );
        fs::remove_dir_all(temp).ok();
    }

    #[test]
    fn ignores_existing_plugdev_group() {
        let temp = test_dir("ignores_existing_plugdev_group");
        fs::create_dir_all(&temp).expect("temp dir");
        let mut runner = FakeCommandRunner {
            failures: VecDeque::from([None, None, Some(9)]),
            ..FakeCommandRunner::default()
        };

        install_udev_rules_with_runner(
            &temp,
            &UdevRuleSelection::Devices(vec![DeviceType::Coldcard]),
            &mut runner,
            "alice",
        )
        .expect("install rules");

        assert_eq!(
            runner.commands.last(),
            Some(&command("usermod", &["-aG", "plugdev", "alice"]))
        );
        fs::remove_dir_all(temp).ok();
    }

    #[test]
    fn reports_permission_denied_as_needs_root() {
        let error = UdevInstallError::Io {
            action: "write",
            path: PathBuf::from("/etc/udev/rules.d/20-hw1.rules"),
            source: io::Error::new(io::ErrorKind::PermissionDenied, "denied"),
        };
        assert!(error.needs_root());
    }

    #[derive(Default)]
    struct FakeCommandRunner {
        commands: Vec<Vec<String>>,
        failures: VecDeque<Option<i32>>,
    }

    impl CommandRunner for FakeCommandRunner {
        fn run(&mut self, program: &str, args: &[&str]) -> Result<(), UdevInstallError> {
            self.commands.push(command(program, args));
            if let Some(code) = self.failures.pop_front().flatten() {
                Err(UdevInstallError::CommandFailed {
                    program: program.to_owned(),
                    args: args.iter().map(|arg| (*arg).to_owned()).collect(),
                    code: Some(code),
                })
            } else {
                Ok(())
            }
        }
    }

    fn command(program: &str, args: &[&str]) -> Vec<String> {
        std::iter::once(program.to_owned())
            .chain(args.iter().map(|arg| (*arg).to_owned()))
            .collect()
    }

    fn test_dir(name: &str) -> PathBuf {
        env::temp_dir().join(format!("bhwi-udev-{name}-{}", std::process::id()))
    }
}
