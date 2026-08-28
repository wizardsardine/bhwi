# Jade Emulation

## Nix

The recommended local e2e path is the Nix runner documented in
[`docs/NIX.md`](NIX.md). It starts the Jade pinserver, runs the pinned Jade QEMU
image, and uses `jade-init` to configure the emulator for tests.

```sh
# Terminal 1
nix run .#jade-pinserver

# Terminal 2
nix run .#jade

# Terminal 3, after QEMU is listening
nix run .#jade-init
nix develop .#jade -c cargo test -p bhwi-e2e-jade -- --test-threads=1
```

## Docker/Podman

https://github.com/Blockstream/Jade/blob/1ca0a0a475f227153070bc00e56734e0ca1fe6c2/README.md?plain=1#L257

```sh
cd jade/
# automatically approves workflows without user interaction
podman build -t jade-qemu -f Dockerfile.qemu .
# if you want to manually test the emulated device:
# podman build -t jade-qemu -f Dockerfile.qemu . --build-arg QEMU_CONFIG_ARGS="--dev --psram --webdisplay-larger"
podman run --rm -p 30121:30121 -p 30122:30122 -it jade-qemu
```

Go to `http://127.0.0.1:30122/` to play with the web interface. Use arrow keys
and Enter for controls.

## Pinserver

```sh
cd jade/pinserver
python -m venv venv
. venv/bin/activate
pip install --require-hashes -r requirements.txt

podman build -t jade_pinserver
mkdir pinsdir
podman run --rm -v $PWD/test_keys/server_private_key.key:/server_private_key.key -v $PWD/pinsdir:/pins -p 8096:8096 jade_pinserver
```

## Device Preparation for e2e/jade

### Set Mneumonic on device

TODO: implement this somewhere in Rust
```python
from jadepy.jade import JadeAPI

jade = JadeAPI.create_serial(device='tcp:localhost:30121')
jade.connect();
jade.set_mnemonic('fish inner face ginger orchard permit useful method fence kidney chuckle party favorite sunset draw limb science crane oval letter slot invite sadness banana');
jade.disconnect()
```

### Set Pinserver on device

```sh
./jade_cli.py set-pinserver --pubkey pinserver/test_keys/server_public_key.pub http://localhost:8096
```

## Descriptor Registration Names

Jade persists registered descriptors as NVS storage keys on the device, so the
`descriptor_name` passed to `register_descriptor` is constrained: at most 16
characters, using only letters, digits and underscores. Spaces are not allowed.
See the [Jade API client](https://github.com/Blockstream/Jade/tree/master/jadepy)
(`jadepy`) and the [RPC docs](https://github.com/Blockstream/Jade/blob/master/docs/index.rst)
for the reference behaviour. The check itself is
[`storage_key_name_valid`](https://github.com/Blockstream/Jade/blob/f94fc04f66d6ed96f9df43af024b89be1b240bb2/main/storage.c#L398)
in the firmware.

An invalid name (e.g. `my wallet`) is rejected by the firmware before anything
is shown on the device, with the misleading RPC error
`-32602 "Missing or invalid descriptor name parameter"`; use `my_wallet`
instead. Ledger wallet policy names allow spaces, so a name that works for a
Ledger registration may still fail on Jade.
