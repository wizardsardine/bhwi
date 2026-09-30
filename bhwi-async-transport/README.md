# bhwi-async-transport

Concrete native channels and device discovery for BHWI's asynchronous clients.
This crate connects the protocol layer to desktop hardware and emulators.

## Role and features

`NativeSource` discovers supported devices and supplies channels to the
re-exported `DeviceManager`. Native implementations cover HID, USB, serial,
and emulator transports, including TCP, UDP, and local sockets where applicable.
The Linux-only `udev` module supports device-access rules.

Default features enable `bitbox`, `coldcard`, `jade`, `keepkey`, `ledger`,
`specter`, and `trezor`. Consumers can disable default features and select the
device features they need.

## Documentation

- [BHWI documentation](https://wizardsardine.github.io/bhwi/docs/)
- [Device onboarding](https://wizardsardine.github.io/bhwi/docs/docs/DEVICE_ONBOARDING.html)
- [Nix emulator runners](https://wizardsardine.github.io/bhwi/docs/docs/NIX.html)
- [Released and current development APIs](https://wizardsardine.github.io/bhwi/docs/API.html)
- [Source](https://github.com/wizardsardine/bhwi/tree/main/bhwi-async-transport)
