# bhwi-cli

BHWI's command-line tools and shared CLI helpers. The crate builds the `bhwi`
binary and a Python-HWI-compatible `hwi` binary on top of the native asynchronous
hardware-wallet stack.

## Role and features

The library shares device selection, host interactions, and output-formatting
helpers between the binaries. The existing CLI and HWI guides below describe
the commands and compatibility behavior.

Default features enable `bitbox`, `coldcard`, `jade`, `keepkey`, `ledger`,
`specter`, and `trezor`. Consumers can disable default features and select the
device features they need. Installing `udev` rules is Linux only.

## Documentation

- [BHWI documentation](https://wizardsardine.github.io/bhwi/docs/)
- [CLI usage](https://wizardsardine.github.io/bhwi/docs/README.html#cli)
- [HWI compatibility](https://wizardsardine.github.io/bhwi/docs/docs/HWI.html)
- [Released and current development APIs](https://wizardsardine.github.io/bhwi/docs/API.html)
- [Source](https://github.com/wizardsardine/bhwi/tree/main/bhwi-cli)
