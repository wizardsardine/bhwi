# BHWI Website

Demo web application for [BHWI](../README.md) using WebAssembly.

Supports connecting to Coldcard, Jade, and Ledger devices via WebHID/WebSerial.

Requires a Chromium-based browser (Chrome, Edge, etc.).

## Running

From the root of the repository:

```
nix run .#website
```

## Device icons

Hardware wallet illustrations come from
[bitcoin-hardware-illustrations](https://github.com/GBKS/bitcoin-hardware-illustrations)
(MIT), recolored to the site's dark palette (body `#374151`, lines
`#9ca3af`). The full upstream set is already vendored in
`src/assets/devices/`, so onboarding a new device only requires adding
its icon to `DEVICE_ICONS` in `src/App.tsx`. Optionally accent the
device's screen element by hand with `stroke="#60a5fa"
stroke-opacity="0.8"`.
