use anyhow::Result;

use crate::support::{basic_cli_cases, run_command_cases};

const COLDCARD_FINGERPRINT: &str = "0f056943";
const COLDCARD_XPUB_44: &str = "tpubDCiHGUNYdRRBPNYm7CqeeLwPWfeb2ZT2rPsk4aEW3eUoJM93jbBa7hPpB1T9YKtigmjpxHrB1522kSsTxGm9V6cqKqrp1EDaYaeJZqcirYB";

#[test]
fn coldcard_basic_cli_commands() -> Result<()> {
    run_command_cases(&basic_cli_cases(COLDCARD_FINGERPRINT, COLDCARD_XPUB_44))
}
