# BHWI, the Bitcoin Hardware Wallet Interface

**BHWI** is a [sans-IO](https://sans-io.readthedocs.io/) Bitcoin hardware wallet
interface. For each device it implements an *interpreter* that encodes commands,
decodes device responses and routes data to its recipients, while leaving all
I/O (transport, async runtime, HTTP) to the caller. That lets one Rust core
serve every target platform, from desktop and mobile to the browser (WASM) and
other languages through FFI. And because every device
sits behind one common interface, applications share a single dependency tree
instead of pulling a separate client library (and its transitive dependencies)
per hardware wallet. It ships a CLI plus a Python-HWI-compatible `hwi` binary.

Keeping I/O out of the core matters because driving a hardware wallet is rarely
one request/response: registering a Miniscript descriptor before signing,
answering a Ledger's Merkle-proof data requests, or routing through a Jade PIN
server all take several round trips. Rather than commit every caller to one
execution model, BHWI leaves that choice to them: each device is a small state
machine that performs no I/O itself, so it fits synchronous, asynchronous, FFI
and WASM callers alike. This matters most across an FFI boundary, where the host
language often brings its own native I/O stack: a sans-IO core lets that language
plug in its own transport directly instead of embedding a Rust runtime. The
repository ships [`bhwi-async`](bhwi-async) for those who want a ready-made
rust async layer. See [docs/VISION.md](docs/VISION.md) for the full rationale
behind this design.

Concretely, each device is an `Interpreter`: the caller calls `start`, feeds
device replies back through `exchange` until no further `Transmit` is returned,
then `end` yields the response. Throughout, the caller performs the actual I/O
for each `Transmit` payload the interpreter hands back.

```rust
pub trait Interpreter {
    type Command;
    type Transmit;
    type Response;
    type Error;
    fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, Self::Error>;
    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error>;
    fn end(self) -> Result<Self::Response, Self::Error>;
}
```

`bhwi-async` is one such driver: it pumps the common interpreter (coldcard,
ledger, jade, bitbox) over HID, TCP or the browser and routes each `Transmit` to
the device transport or to the Jade PIN server via its `Recipient`.

## Workspace

| crate        | description                                                        |
| ------------ | ------------------------------------------------------------------ |
| `bhwi`       | Core sans-IO interpreters and the `common` command/response model. |
| `bhwi-async` | `async`/`await` `HWI` trait over the interpreters, with transports.|
| `bhwi-cli`   | `bhwi` command-line tool and the `hwi` parity binary.              |
| `bhwi-wasm`  | WebAssembly bindings for browser callers.                          |

## Supported devices

- [BitBox02](https://github.com/digitalbitbox/bitbox02-firmware)
- [Coldcard](https://github.com/Coldcard/firmware)
- [Jade](https://github.com/Blockstream/Jade)
- [Ledger](https://github.com/LedgerHQ/app-bitcoin-new)

Every device implements the full [`HWI` trait](bhwi-async/src/lib.rs): `unlock`,
`get_info`, `get_master_fingerprint`, `get_extended_pubkey`, `sign_message`,
`display_address`, `register_wallet` and `sign_tx`. The only capability gap is
`backup_device`, which is supported on BitBox02 and Coldcard but not on Jade or
Ledger.

## CLI

`bhwi` is a Unix-friendly command-line tool over `bhwi-async`:

```sh
cargo build -p bhwi-cli
```

| command           | purpose                                              |
| ----------------- | ---------------------------------------------------- |
| `device`          | list devices, firmware/app info, device management   |
| `xpub`            | get an extended public key at a derivation path      |
| `descriptor`      | descriptor / pubkey-descriptor operations            |
| `address`         | display, check and get addresses                     |
| `register-wallet` | register a wallet policy on the device               |
| `sign-psbt`       | sign a PSBT                                           |
| `sign-message`    | sign a message                                       |

Output is chainable by default (no headers); use `--pretty` for tables and
`--json` for structured output suitable for `jq`.

## HWI parity

`bhwi-cli` also builds a Python-HWI-compatible `hwi` binary. A parity suite
checks its output against Bitcoin Core HWI for the devices where parity is
claimed. See [docs/HWI_PARITY.md](docs/HWI_PARITY.md).

## Documentation

- [docs/VISION.md](docs/VISION.md): design rationale
- [docs/DEVICE_ONBOARDING.md](docs/DEVICE_ONBOARDING.md): adding a device
- [docs/HWI_PARITY.md](docs/HWI_PARITY.md): Python-HWI parity
- [docs/NIX.md](docs/NIX.md): Nix emulator runners
- Device emulation: [BITBOX](docs/BITBOX.md) · [COLDCARD](docs/COLDCARD.md) · [JADE](docs/JADE.md) · [LEDGER](docs/LEDGER.md)

## License

BHWI is released under the terms of the license in [LICENSE](LICENSE). The
BitBox02 integration additionally carries [BITBOX_LICENSE](BITBOX_LICENSE).
