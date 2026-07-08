# Device Onboarding References

Use this page to collect the upstream projects and protocol documentation needed
to add or maintain support for a hardware wallet in BHWI.

## BHWI Model

- [README](../README.md): explains the sans-I/O interpreter model used by device
  integrations.
- [VISION](VISION.md): gives the project context and the reason BHWI keeps
  protocol logic separate from transport I/O.
- [Common command interface](../bhwi/src/common.rs): lists the device-agnostic
  commands, responses, recipients, and device-specific context.
- [Async transport crate](../bhwi-async/src/transport): contains concrete HID,
  TCP, and emulator transports for the sans-I/O interpreters.
- [CLI crate](../bhwi-cli/src): shows how discovery, command parsing, and async
  device execution are wired together.

## Shared Bitcoin Standards

- [BIP 32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki):
  hierarchical deterministic keys and derivation paths.
- [BIP 44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki):
  account structure used by standard descriptors.
- [BIP 174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki):
  PSBT v0.
- [BIP 370](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki):
  PSBT v2, required by the Ledger Bitcoin app.
- [BIP 380](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki)
  and [BIP 388](https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki):
  output descriptors and wallet policies.
- [Miniscript](https://bitcoin.sipa.be/miniscript/): policy language used for
  descriptor-backed wallet support.
- [Bitcoin Core HWI](https://github.com/bitcoin-core/HWI): reference behavior
  for common hardware wallet commands.
- [Async-HWI](https://github.com/Wizardsardine/async-hwi): earlier Wizardsardine
  Rust implementation that informed and inspired BHWI.

## BitBox02

- Local code (gated behind the `bitbox` cargo feature):
  - [Interpreter](../bhwi/src/bitbox/interpreter.rs)
  - [Bitcoin request/response builders](../bhwi/src/bitbox/api.rs)
  - [Protobuf messages](../bhwi/src/bitbox/proto.rs)
  - [Noise pairing state](../bhwi/src/bitbox/noise.rs)
  - [U2F-HID framing](../bhwi/src/bitbox/u2f.rs)
  - [PSBT signing](../bhwi/src/bitbox/sign.rs)
  - [Wallet policy handling](../bhwi/src/bitbox/policy.rs)
  - [E2E docs](BITBOX.md)
- Upstream references:
  - [BitBox02 firmware and simulator](https://github.com/BitBoxSwiss/bitbox02-firmware)
  - [bitbox-api-rs](https://github.com/BitBoxSwiss/bitbox-api-rs)
- Onboarding notes:
  - BitBox02 traffic rides U2F-HID framing and is encrypted with a Noise channel
    established during pairing. The simulator auto-confirms pairing.
  - Descriptor-based address display re-supplies the wallet policy each time via
    `DeviceContext::BitBox`; the device holds no persistent policy token like a
    Ledger HMAC.
  - Wallet policies share the miniscript `WalletPolicy` extraction in
    [`bhwi/src/policy.rs`](../bhwi/src/policy.rs) with the Ledger backend.
  - Use these commands for emulator-backed tests:

```sh
nix run .#bitbox
nix develop .#bitbox -c cargo test -p bhwi-e2e-bitbox -- --test-threads=1
```

## Ledger

- Local code:
  - [Interpreter](../bhwi/src/ledger/mod.rs)
  - [APDU helpers](../bhwi/src/ledger/apdu.rs)
  - [Command encoders](../bhwi/src/ledger/command.rs)
  - [Wallet policy encoding](../bhwi/src/ledger/wallet.rs)
  - [PSBT serialization](../bhwi/src/ledger/psbt.rs)
  - [E2E docs](LEDGER.md)
- Upstream references:
  - [Ledger Bitcoin app](https://github.com/LedgerHQ/app-bitcoin-new)
  - [Bitcoin app client tests](https://github.com/LedgerHQ/app-bitcoin-new/tree/develop/bitcoin_client_rs/tests)
  - [Speculos emulator](https://github.com/LedgerHQ/speculos)
  - [Ledger app-builder image](https://github.com/LedgerHQ/ledger-app-builder)
  - [Ledger Live open-app reference](https://github.com/LedgerHQ/ledger-live)
- Onboarding notes:
  - Ledger uses APDUs and device-requested client callbacks for wallet policy
    merkle data and PSBT signing data.
  - Keep wallet policy formatting aligned with BIP 388 and the Ledger Bitcoin
    app's expected key-info strings.
  - Use these commands for emulator-backed tests:

```sh
nix run .#ledger
nix develop .#ledger -c cargo test -p bhwi-e2e-ledger -- --test-threads=1
```

## Coldcard

- Local code:
  - [Interpreter](../bhwi/src/coldcard/mod.rs)
  - [API request/response encoding](../bhwi/src/coldcard/api.rs)
  - [Encryption engine](../bhwi/src/coldcard/encrypt.rs)
  - [E2E docs](COLDCARD.md)
- Upstream references:
  - [Coldcard firmware](https://github.com/Coldcard/firmware)
  - [ckcc-protocol](https://github.com/Coldcard/ckcc-protocol)
  - [Coldcard simulator README](https://github.com/Coldcard/firmware/blob/master/README.md)
- Onboarding notes:
  - Coldcard commands are encrypted after the initial public-key exchange.
  - The simulator exposes `/tmp/ckcc-simulator.sock`; the local device ID also
    records this emulator path.
  - Use these commands for emulator-backed tests:

```sh
nix run .#coldcard
nix develop .#coldcard -c cargo test -p bhwi-e2e-coldcard -- --test-threads=1
```

## Jade

- Local code:
  - [Interpreter](../bhwi/src/jade/mod.rs)
  - [CBOR RPC types](../bhwi/src/jade/api.rs)
  - [TCP transport](../bhwi-async/src/transport/jade/tcp.rs)
  - [E2E docs](JADE.md)
- Upstream references:
  - [Blockstream Jade](https://github.com/Blockstream/Jade)
  - [Jade API documentation](https://github.com/Blockstream/Jade/blob/master/docs/index.rst)
  - [Jade Python client](https://github.com/Blockstream/Jade/tree/master/jadepy)
  - [Blind pin server](https://github.com/Blockstream/blind_pin_server)
- Onboarding notes:
  - Jade uses CBOR-RPC requests over serial/TCP.
  - Authentication may require forwarding a device-provided HTTP request to the
    pinserver before completing the device handshake.
  - Use these commands for emulator-backed tests:

```sh
nix run .#jade-pinserver
nix run .#jade
nix run .#jade-init
nix develop .#jade -c cargo test -p bhwi-e2e-jade -- --test-threads=1
```

## Adding a Device

- Start from `bhwi/src/common.rs` and map each supported common command to the
  device protocol.
- Keep protocol encoding, response parsing, authentication, and intermediate
  device callbacks inside the device interpreter.
- Keep USB, serial, TCP, browser, and emulator I/O in transport crates or
  clients, not in the interpreter.
- Add emulator or simulator notes under `docs/` when an upstream test target is
  available.
- Add focused unit tests for protocol encoding/parsing and e2e coverage for
  commands that need an emulator.
