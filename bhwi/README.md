# bhwi

The sans-I/O core of BHWI, the Bitcoin Hardware Wallet Interface. It interprets
hardware-wallet protocols without choosing a transport or execution runtime.

## Role and features

An `Interpreter` encodes a command with `Interpreter::start`, consumes device
replies through repeated `exchange` calls, and returns the response with `end`.
The caller supplies all I/O for the resulting transmissions. The `common`
module provides device-agnostic commands, responses, and device context.

Default features enable `bitbox`, `coldcard`, `jade`, `keepkey`, `ledger`,
`specter`, and `trezor`. Consumers can disable default features and select the
device features they need.

## Documentation

- [BHWI documentation](https://wizardsardine.github.io/bhwi/docs/)
- [Device onboarding](https://wizardsardine.github.io/bhwi/docs/docs/DEVICE_ONBOARDING.html)
- [Released and current development APIs](https://wizardsardine.github.io/bhwi/docs/API.html)
- [Source](https://github.com/wizardsardine/bhwi/tree/main/bhwi)
