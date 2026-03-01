# Coldcard Emulation

## Installation

Follow instructions [here](https://github.com/Coldcard/firmware/blob/master/README.md) to build
and simulate a coldcard device.

### Caveat

For me, on Linux, I needed to comment out this like in `firmware/unix/Makefile`:

```sh
export PKG_CONFIG_PATH=/usr/local/opt/libffi/lib/pkgconfig
```
My system doesn't have an issue finding `libffi` in using `pkg-config` and this
breaks it since it's also not where my `libffi` is installed.

## Running in Docker/Podman

Inspired by https://github.com/tadeubas/coldcard-docker

### Prerequisite

You must [download a patch](https://github.com/Coldcard/firmware/compare/master...trevarj:firmware:headless-tcp-key-input.diff) that allows the coldcard e2e tests to interact with the simulator and save it as `headless_socket.patch` in the directory where you have the `Dockerfile`:

```Dockerfile
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git make \
    python3-full python3-venv python3-pip python-is-python3 \
    swig \
    libpcsclite-dev pcscd \
    pkg-config libffi-dev libudev-dev \
    xterm \
    autoconf automake libtool m4 \
 && rm -rf /var/lib/apt/lists/*  # Clean up apt cache for smaller image size

WORKDIR /build

RUN if [ ! -d "firmware" ]; then \
       git clone --recursive https://github.com/Coldcard/firmware.git; \
    fi

WORKDIR /build/firmware/external/micropython
RUN git apply ../../ubuntu24_mpy.patch

WORKDIR /build/firmware
RUN python3 -m venv ENV && \
    ENV/bin/pip install --no-cache-dir -U pip setuptools && \
    ENV/bin/pip install --no-cache-dir -r requirements.txt && \
    ENV/bin/pip install --no-cache-dir pysdl2-dll && \
    cd unix && \
    make -C ../external/micropython/mpy-cross && \
    make setup && \
    make ngu-setup && \
    make && \
    find /build/firmware -name ".git" -type d -prune -exec rm -rf '{}' +

# Apply patch for headless socket comms
COPY headless_socket.patch /build/firmware/headless_socket.patch
RUN git apply headless_socket.patch

# Set the default working directory to the simulator
WORKDIR /build/firmware/unix

CMD ["bash", "-c", "\
cd /build/firmware/unix && \
../ENV/bin/python3 simulator.py --headless & \
cd .. && \
source ENV/bin/activate && \
echo 'Simulator running (headless). Virtualenv activated.' && \
exec bash"]
```

Build:
```sh
podman build -t coldcard-simulator .
```

Run:
```sh
mkdir microSD 2&>/dev/null

podman run --rm -it \
       -v /tmp:/tmp:Z \
       -v /tmp/.X11-unix:/tmp/.X11-unix \
       -v $PWD/microSD:/build/firmware/unix/work/MicroSD \
       -e DISPLAY=unix$DISPLAY \
       -p 9999:9999 \
       coldcard-simulator
```
