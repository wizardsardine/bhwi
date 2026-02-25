# Ledger End-to-End Testing

## Running the Tests

1. Start Speculos per instructions [here](../../docs/LEDGER.md)
2. `cargo test`

### Notes

The tests need to run synchonously so the emulator doesn't get confused, hence
the `RUST_TEST_THREADS=1` being set in `.cargo/config.toml`.
