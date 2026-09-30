# bhwi-async

Asynchronous execution of BHWI's sans-I/O hardware-wallet interpreters. It
provides device clients and protocol framing while leaving native device
channels and discovery to `bhwi-async-transport`.

## Role and features

The `HWI` trait exposes common hardware-wallet operations. Device clients drive
interpreters through a `Transport`, route HTTP requests through `HttpClient`,
and use `HostInteraction` for host-side prompts such as PIN or passphrase entry.
The transport framing and client behavior are reusable with native or browser
I/O implementations.

Default features enable `bitbox`, `coldcard`, `jade`, `keepkey`, `ledger`,
`specter`, and `trezor`. Consumers can disable default features and select the
device features they need.

## Documentation

- [BHWI documentation](https://wizardsardine.github.io/bhwi/docs/)
- [Device onboarding](https://wizardsardine.github.io/bhwi/docs/docs/DEVICE_ONBOARDING.html)
- [Released and current development APIs](https://wizardsardine.github.io/bhwi/docs/API.html)
- [Source](https://github.com/wizardsardine/bhwi/tree/main/bhwi-async)
