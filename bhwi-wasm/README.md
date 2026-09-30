# bhwi-wasm

Browser bindings and transports for BHWI, exposing hardware-wallet operations
through WebAssembly and JavaScript with WebHID, WebUSB, and WebSerial.

## Role and features

Build for the `wasm32-unknown-unknown` target. Browser clients require the
relevant device APIs, a secure context, and user-granted device permissions;
API availability depends on the browser. The current core and async dependencies
enable `bitbox`, `coldcard`, `jade`, `keepkey`, `ledger`, `specter`, and `trezor`;
this crate does not expose the same selectable device-feature table as the
native crates. Web-sys's unstable device APIs require the
`web_sys_unstable_apis` cfg for both compilation and rustdoc.

## Documentation

- [BHWI documentation](https://wizardsardine.github.io/bhwi/docs/)
- [Browser demo](https://wizardsardine.github.io/bhwi/)
- [Device onboarding](https://wizardsardine.github.io/bhwi/docs/docs/DEVICE_ONBOARDING.html)
- [Released and current development APIs](https://wizardsardine.github.io/bhwi/docs/API.html)
- [Source](https://github.com/wizardsardine/bhwi/tree/main/bhwi-wasm)
