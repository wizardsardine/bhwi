# Specter-DIY

BHWI supports Specter-DIY through its native USB serial protocol and browser
WebSerial. The protocol runs at 115200 baud and each sensitive request is
confirmed on the device.

## Device setup

USB communication is disabled by default. On the device, open **Device
settings**, enable **USB communication**, and reboot when prompted. Connect the
device after it restarts.

On Linux, the user running `bhwi` needs read/write access to the serial device,
usually `/dev/ttyACM*`. Add that user to the distribution's serial group (often
`dialout`) or install an equivalent local udev rule, then log out and back in.

The native CLI discovers the device by its MicroPython USB vendor ID. Select it
explicitly when more than one compatible serial device is present:

```sh
bhwi --device-type specter device list
bhwi --device-type specter xpub get "m/84'/0'/0'"
```

Use the native global selectors with other commands as needed:

```sh
bhwi --device-type specter --fingerprint <fingerprint> sign-message \
  --path "m/84'/0'/0'/0/0" --message "message to sign"
```

The browser connection uses WebSerial at the same baud rate. Select the
Specter-DIY serial port in the browser permission dialog.

## Supported operations

- Master fingerprint and extended public keys.
- Wallet-policy import.
- Descriptor-backed address display after importing the wallet and confirming
  on-device. Supply the same policy with
  `address get --from-descriptor ... --wallet-descriptor ...`.
- Legacy Bitcoin message signing.
- ECDSA signing for legacy and SegWit PSBT inputs.
- Taproot key-path PSBT signing. The device returns a finalized witness.

Specter-DIY does not expose firmware metadata through this protocol, so native
`--format json device list` omits `firmware` and `version` for this device.

## Limits

- The pinned firmware does not support Taproot script trees or Taproot address
  display.
- BHWI does not retrieve addresses without displaying them on Specter-DIY.
- Host-controlled setup, restore, backup, wipe, PIN, passphrase, and network
  actions are unavailable.

## Simulator

The flake pins Specter-DIY, including submodules, at
`b9c85b9651d3e4cea2fbc954a8c5558844367c81`. Start the simulator and initialize
its synthetic test wallet in separate terminals:

```sh
# Terminal 1
nix run .#specter

# Terminal 2, after the GUI controller is ready
nix run .#specter-init
nix develop .#specter -c cargo test -p bhwi-e2e-specter -- --test-threads=1

# In Terminal 1, press Ctrl-C and run nix run .#specter again
# Then, in Terminal 2, reinitialize the wallet
nix run .#specter-init

# Build and run the native CLI tests against the fresh simulator
nix develop .#specter -c cargo build -p bhwi-cli
BHWI_BIN="$PWD/target/debug/bhwi" nix develop .#specter \
  -c cargo test -p bhwi-e2e-cli specter -- --test-threads=1
```

The GUI controller listens on `127.0.0.1:8787` and the simulated USB protocol
on `127.0.0.1:8789`. Set `SPECTER_GUI_PORT` before starting the simulator and
initializer to use another GUI port. The CLI simulator selector is
`--device-type specter --device-path tcp:127.0.0.1:8789`.
