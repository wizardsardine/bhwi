# Emulator Validation Runbook

Use this when a change touches device protocol behavior, emulator-supported CLI
behavior, HWI parity, Nix emulator infrastructure, or CI logs.

## General Rules

- Run only the intended emulator family for the test being performed.
- Use `-- --test-threads=1` for emulator tests.
- Treat emulator startup and Rust test execution as separate validation steps.
- Redact sensitive logs. Do not include seeds, private keys, xprvs, PINs,
  passphrases, wallet secrets, real HMACs, raw APDU dumps, or full real-device
  payloads in handoffs or CI comments.
- If validation fails, determine whether the failure is caused by the current
  change, pre-existing behavior, or local environment.

## Coldcard

Start:

```sh
nix run .#coldcard
```

Readiness:

```sh
test -S /tmp/ckcc-simulator.sock
```

Package e2e:

```sh
nix develop .#coldcard -c cargo test -p bhwi-e2e-coldcard -- --test-threads=1
```

CLI e2e:

```sh
cargo build -p bhwi-cli
BHWI_BIN="$PWD/target/debug/bhwi" \
  nix develop .#coldcard -c cargo test -p bhwi-e2e-cli coldcard -- --test-threads=1
```

HWI parity:

```sh
cargo build -p bhwi-cli --bin hwi
nix run .#hwi-parity-coldcard
```

## Ledger

Start:

```sh
nix run .#ledger
```

Readiness:

```sh
nc -z localhost 9999 && nc -z localhost 5000
```

Package e2e:

```sh
nix develop .#ledger -c cargo test -p bhwi-e2e-ledger -- --test-threads=1
```

CLI e2e:

```sh
cargo build -p bhwi-cli
BHWI_BIN="$PWD/target/debug/bhwi" \
  nix develop .#ledger -c cargo test -p bhwi-e2e-cli ledger -- --test-threads=1
```

HWI parity:

```sh
cargo build -p bhwi-cli --bin hwi
nix run .#hwi-parity-ledger
```

## Jade

Start:

```sh
nix run .#jade-pinserver
nix run .#jade
nix run .#jade-init
```

Readiness:

```sh
nc -z localhost 8096 && nc -z localhost 30121
```

Package e2e:

```sh
nix develop .#jade -c cargo test -p bhwi-e2e-jade -- --test-threads=1
```

CLI e2e:

```sh
cargo build -p bhwi-cli
BHWI_BIN="$PWD/target/debug/bhwi" \
  nix develop .#jade -c cargo test -p bhwi-e2e-cli jade -- --test-threads=1
```

HWI parity:

```sh
cargo build -p bhwi-cli --bin hwi
nix run .#hwi-parity-jade
```

## Nix Script Checks

Run after adding or changing emulator scripts:

```sh
nix build .#checks.x86_64-linux.emulator-scripts
```

New scripts must be staged before this flake check can see them.
