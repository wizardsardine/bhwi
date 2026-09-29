# bhwi-ipc

`bhwi-ipc` serves bhwi to programs that do not link Rust. A client connects to a
local socket, speaks Cap'n Proto RPC, and drives every supported hardware wallet
through one interface.

The contract is [`bhwi-ipc/schema/bhwi.capnp`](../bhwi-ipc/schema/bhwi.capnp). A
client needs that file and a Cap'n Proto runtime, nothing else. Its ordinals are
permanent: fields and methods are added, never renumbered.

## Running the server

Building needs the `capnp` compiler on `PATH`; the Nix devshells provide it.

```sh
cargo run -p bhwi-ipc -- --socket "$XDG_RUNTIME_DIR/bhwi.sock"
```

- The socket is created with mode `0600`. Only the user running the server can
  connect, and anyone who can connect can drive the wallet.
- A socket another `bhwi-ipc` still serves is refused. A stale socket is replaced.
  A path that is not a socket is never touched.
- The server removes its socket when it exits.
- Every device is built in by default. Each has a cargo feature: `bitbox`,
  `coldcard`, `jade`, `keepkey`, `ledger`, `specter`, `trezor`.

The server runs on Unix. Windows is not supported yet.

## Interfaces

| Interface | Implemented by | Purpose |
|---|---|---|
| `Bhwi` | server | Bootstrap capability: list and open devices. |
| `Device` | server | One held device and its commands. |
| `Signing` | server | One PSBT signing run. |
| `Prompter` | client | Answers the questions a device needs a user for. |

## Results and errors

Every method returns `Result(T)`: either `ok` or `error { code, message }`. A
failure the client can act on is always an `error` arm. An RPC exception means a
lost connection, an unreadable request or a bug in the server.

Codes up to `other` mirror `bhwi::common::ErrorKind` one to one, and its
documentation describes each. The server adds two of its own and gives a few
shared codes a server-side meaning:

| Code | Meaning |
|---|---|
| `noDevice` | Nothing matched the selector. |
| `badArgument` | The request breaks the interface: an unreadable path, a repeated `Signing.result`, a host passphrase for a BitBox02. |
| `busy` | Another session holds the device. |
| `locked` | A Trezor or KeepKey needs its PIN. |
| `notReady` | The session is closed, or the device needs a prompt and the client passed no `Prompter`. |
| `userCancelled` | The user refused on the device, or the client refused a prompt. |
| `other` | Anything else. The message says what. |

## Selecting and holding a device

A `Selector` picks devices by network, fingerprint, device type and transport
path. An empty fingerprint or path matches any device. Set `includeEmulators` to
reach emulators.

- `listDevices` enumerates and unlocks every match. Devices that could not be
  opened are listed in `skipped` with a code, and do not fail the call. A locked
  Trezor or KeepKey is listed with `locked`.
- `openDevice` takes exclusive hold of the first match and returns a `Device`. It
  unlocks a locked Trezor or KeepKey through `Prompter.requestPin`. A second
  caller gets `busy`, and `listDevices` reports the held device as skipped with
  `busy`.
- The hold ends when the client drops the `Device` capability or disconnects.

`networkMismatch` reports a device whose own networks do not include the
selector's. An empty `reported` list means the device claims no network, which
is never a mismatch.

The passphrase is chosen per selector: `none`, a `value`, or `askPrompter`, which
calls `Prompter.requestPassphrase` before enumerating. A BitBox02 takes its
passphrase on the device only and refuses a `value` with `badArgument`.

## Prompter

The client passes a `Prompter` to `listDevices` or `openDevice`. The server calls
it while a command runs.

| Method | Devices | Answer |
|---|---|---|
| `pairingCode(code)` | BitBox02 | None. The user compares the code on the device; the server does not wait. |
| `requestPin(kind)` | Trezor, KeepKey | Keypad positions read off the device screen, not the PIN digits. `kind` is `current`, `chooseNew` or `confirmNew`. |
| `requestPassphrase()` | Trezor, KeepKey | The passphrase text. |
| `requestRecoveryCharacter(word, character)` | KeepKey | One ciphered letter as shown on the screen, `delete`, `nextWord` or `done`. Positions are 0-based. |

To refuse, the client raises an exception whose reason is `"<code>: <message>"`,
for example `"userCancelled: the user closed the dialog"`. The command then fails
with that code. A reason without a known code becomes `other`.

## Signing

`signPsbt` validates the PSBT and returns a `Signing` capability at once. The
device stays held until the run ends.

- `result` waits for the device and returns the PSBT and `signed`, which is
  `false` when the device returned it unchanged. It returns once; a second call is
  `badArgument`.
- `abort` cancels the run and closes the `Device`: an interrupted exchange leaves
  the device in an unknown state. Later calls on it are `notReady`, and `result`
  is `userCancelled`.

`policy.auto` derives the wallet policies the PSBT needs. On a Ledger it registers
each multisig policy it signs under, and the user confirms each registration.
`policy.registered` signs under a policy registered earlier: name, policy and HMAC
on a Ledger, the policy alone on a Specter-DIY.

## Wallet policies

`registerWallet(name, policy)` takes a full descriptor with key origins, such as
`wsh(sortedmulti(2,[fp/48'/1'/0'/2']tpub…/<0;1>/*,…))`.

| Device | Result |
|---|---|
| Ledger | `complete` with a 32-byte HMAC. Keep it: signing and address display under the policy need it. |
| Coldcard | `pendingUserConfirmation`. The device asks the user after the call returns. |
| BitBox02, Jade, Specter-DIY | `complete` with an empty HMAC. |
| Trezor, KeepKey | `unsupported`. They check the descriptor when showing addresses and signing. |

`displayAddress` takes a path and address format, a registered policy by name
and index, or a full descriptor. `display` shows the address on the device and
waits for the user.

## Device management

`setupDevice`, `restoreDevice`, `wipeDevice` and `togglePassphrase` run on
BitBox02, KeepKey and Trezor, which take their seed entropy and clock from the
host. The server supplies both. Every other device answers `unsupported`
without being contacted.

`backupDevice` runs on BitBox02, which writes the backup itself and answers
`complete`, and on Coldcard, which returns the backup as a `file`. Every other
device answers `unsupported` without being contacted.

## Reference client

[`e2e/ipc`](../e2e/ipc) is a complete Rust client. It runs every command above
against the emulators and is the executable form of this document.
