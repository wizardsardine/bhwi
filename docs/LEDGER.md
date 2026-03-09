# Ledger

## Simulating Ledger Devices

## Installing

### Install the Speculos emulator
```sh
pip install speculos
```

### Build the Ledger Bitcoin App

Using docker (from their
[docs](https://github.com/LedgerHQ/app-bitcoin-new/tree/develop?tab=readme-ov-file#with-a-terminal))
```sh
sudo docker pull ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
sudo docker run --rm -ti --user "$(id -u):$(id -g)" --privileged -v "/dev/bus/usb:/dev/bus/usb" -v "$(realpath .):/app" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
BOLOS_SDK=$NANOX_SDK make
```

You can also use rootless podman:

```sh
podman pull ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
podman run --rm -ti --user "$(id -u):$(id -g)" --privileged -v "/dev/bus/usb:/dev/bus/usb" -v "$(realpath .):/app:U" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest # subtle difference of :U
BOLOS_SDK=$NANOX_SDK make
```

The .elf and .apdu files will be available in `build/nanox/bin/`

### Running the emulator

```sh

podman run --rm -ti -v "$(realpath .):/app" --user $(id -u):$(id -g) -p 9999:9999 -p 5000:5000 ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
speculos build/nanox/bin/app.elf --model nanox --display headless
```

Note: this is the default mneumonic in Speculos:

```
glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin
```


Then you can open [localhost:5000](localhost:5000) to use the wallet's web interface.
