# Jade Emulation

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
podman run -v $PWD/test_keys/server_private_key.key:/server_private_key.key -v $PWD/pinsdir:/pins -p 8096:8096 jade_pinserver
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
