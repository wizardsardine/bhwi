use std::process::Command;

/// A panic must honor the HWI exit-status contract: status 1, no JSON on
/// stdout, traceback-ish output on stderr (docs/HWI_PARITY.md).
#[test]
fn panic_exits_one_with_empty_stdout_and_stderr_traceback() {
    let output = Command::new(env!("CARGO_BIN_EXE_hwi"))
        .env("HWI_DEBUG_PANIC", "1")
        .arg("enumerate")
        .output()
        .expect("run hwi binary");

    assert_eq!(output.status.code(), Some(1), "panic must exit 1");
    assert!(
        output.stdout.is_empty(),
        "panic must not write stdout, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        !output.stderr.is_empty(),
        "panic must report the crash on stderr"
    );
}
