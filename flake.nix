{
  description = "Minimal rust wasm32-unknown-unknown example";

  inputs = {
    app-bitcoin-new = {
      url = "github:LedgerHQ/app-bitcoin-new";
      flake = false;
    };
    coldcard-firmware = {
      url = "github:Coldcard/firmware";
      flake = false;
    };
    flake-utils.url = "github:numtide/flake-utils";
    jade-firmware = {
      url = "github:Blockstream/Jade/1ca0a0a475f227153070bc00e56734e0ca1fe6c2";
      flake = false;
    };
    jade-pinserver = {
      url = "github:Blockstream/blind_pin_server/0205d38e75cb47f187db2efda5846cc898a85039";
      flake = false;
    };
    python-hwi = {
      url = "github:bitcoin-core/HWI/3.2.0";
      flake = false;
    };
    nixpkgs-esp-dev.url = "github:mirrexagon/nixpkgs-esp-dev";
    nixpkgs-coldcard.url = "github:NixOS/nixpkgs/nixos-24.05";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixpkgs.url = "nixpkgs/nixos-unstable";
  };

  outputs = {
    self,
    app-bitcoin-new,
    coldcard-firmware,
    jade-firmware,
    jade-pinserver,
    python-hwi,
    nixpkgs,
    nixpkgs-coldcard,
    nixpkgs-esp-dev,
    flake-utils,
    rust-overlay,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        overlays = [rust-overlay.overlays.default];
        pkgs = import nixpkgs {
          inherit system overlays;
          config.permittedInsecurePackages = [
            "python3.12-ecdsa-0.19.1"
          ];
        };
        coldcardPkgs = import nixpkgs-coldcard {inherit system;};
        emulatorSystem = system == "x86_64-linux";
        espPkgs = import nixpkgs-esp-dev.inputs.nixpkgs {
          inherit system;
          overlays = [nixpkgs-esp-dev.overlays.default];
          config.permittedInsecurePackages = [
            "python3.13-ecdsa-0.19.1"
          ];
        };
        jadeEspIdf = espPkgs.esp-idf-xtensa.override {
          rev = "v5.4.3";
          sha256 = "sha256-sV/eL3jRG9GdaQNByBypmH5ZKmZoOnWCEY1ABySIeac=";
        };
        jadePython = pkgs.python3.withPackages (pythonPackages: [
          pythonPackages.zopfli
        ]);
        hwiCbor2 = pkgs.python312Packages.cbor2.overridePythonAttrs (_old: rec {
          version = "5.9.0";
          src = pkgs.fetchPypi {
            pname = "cbor2";
            inherit version;
            hash = "sha256-hcekYnmsjyJuEFknUiHms9DjcNK7a9BQD5eAeBYVvOo=";
          };
        });
        hwiPython = pkgs.python312.withPackages (pythonPackages: [
          # HWI 3.2.0 times out against Jade with cbor2 5.8.0 because its
          # larger stream reads expose HWI's exact-fill Jade TCP read loop.
          # Upstream HWI is relaxing its cbor2 cap to permit 5.9.0:
          # https://github.com/bitcoin-core/HWI/pull/832
          hwiCbor2
          pythonPackages.ecdsa
          pythonPackages.hidapi
          pythonPackages.libusb1
          pythonPackages.mnemonic
          pythonPackages.noiseprotocol
          pythonPackages.protobuf
          pythonPackages.pyaes
          pythonPackages.pyserial
          pythonPackages.requests
          pythonPackages.semver
          pythonPackages.typing-extensions
        ]);
        rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        rustPlatformWasm = pkgs.makeRustPlatform {
          cargo = rust;
          rustc = rust;
        };
        bhwi-wasm-pkg = rustPlatformWasm.buildRustPackage {
          name = "bhwi-wasm-pkg";
          src = ./.;
          cargoLock = {
            lockFile = ./Cargo.lock;
            outputHashes = {
              "miniscript-13.0.0" = "sha256-sCxv3/haaN6AJn1ot4gqnAoJJypKAv5nUh/rSDTS3YI=";
            };
          };
          nativeBuildInputs = [
            pkgs.wasm-bindgen-cli
            pkgs.binaryen
            pkgs.llvmPackages.clang-unwrapped
            pkgs.llvmPackages.libclang
          ];
          buildPhase = ''
            runHook preBuild
            export CC_wasm32_unknown_unknown=${pkgs.llvmPackages.clang-unwrapped}/bin/clang
            export CFLAGS_wasm32_unknown_unknown="-I ${pkgs.llvmPackages.libclang.lib}/lib/clang/21.1.8/include/"
            cargo build --release --target wasm32-unknown-unknown -p bhwi-wasm
            runHook postBuild
          '';
          installPhase = ''
            runHook preInstall
            mkdir -p $out
            wasm-bindgen --out-dir $out --target web --out-name bhwi_wasm \
              target/wasm32-unknown-unknown/release/bhwi_wasm.wasm
            wasm-opt -O $out/bhwi_wasm_bg.wasm -o $out/bhwi_wasm_bg.wasm
            cat > $out/package.json << 'EOF'
            {
              "name": "bhwi-wasm",
              "type": "module",
              "version": "0.0.1",
              "main": "bhwi_wasm.js",
              "types": "bhwi_wasm.d.ts"
            }
            EOF
            runHook postInstall
          '';
          doCheck = false;
        };
        mkWebsite = pkgs.callPackage ({buildNpmPackage, nodejs_20, base ? "/"}: buildNpmPackage {
          name = "bhwi-website";
          src = ./website;
          nodejs = nodejs_20;
          npmDepsHash = "sha256-N2Uxh6567ry8CSZyBWWIg8yDJEqQXFtToKi4hVBr8Hk=";
          postPatch = ''
            cp -rL --no-preserve=mode,ownership ${bhwi-wasm-pkg} pkg
          '';
          npmBuildFlags = ["--" "--base" base];
          installPhase = ''
            runHook preInstall
            cp -r dist $out
            runHook postInstall
          '';
        });
        inputs = [
          rust
          pkgs.rust-analyzer
          pkgs.openssl
          pkgs.zlib
          pkgs.gcc
          pkgs.pkg-config
          pkgs.wasm-pack
          pkgs.wasm-bindgen-cli
          pkgs.binaryen
          pkgs.clang
          pkgs.corepack_20
          pkgs.nodejs_20
        ];
        emulatorInputs = [
          pkgs.bash
          pkgs.cacert
          pkgs.coreutils
          pkgs.curl
          pkgs.git
          pkgs.gnumake
          pkgs.gnused
          pkgs.netcat-openbsd
          pkgs.openssl
          pkgs.pkg-config
          pkgs.procps
          pkgs.python3
          pkgs.which
        ];
        coldcardEmulatorInputs = [
          coldcardPkgs.bash
          coldcardPkgs.cacert
          coldcardPkgs.coreutils
          coldcardPkgs.curl
          coldcardPkgs.gawk
          coldcardPkgs.git
          coldcardPkgs.gnumake
          coldcardPkgs.gnugrep
          coldcardPkgs.gnused
          coldcardPkgs.netcat-openbsd
          coldcardPkgs.openssl
          coldcardPkgs.pkg-config
          coldcardPkgs.procps
          coldcardPkgs.python312
          coldcardPkgs.which
        ];
        coldcardInputs =
          coldcardEmulatorInputs
          ++ [
            coldcardPkgs.autoconf
            coldcardPkgs.automake
            coldcardPkgs.binutils
            coldcardPkgs.gcc13
            coldcardPkgs.gcc-arm-embedded
            coldcardPkgs.glibc.bin
            coldcardPkgs.libffi
            coldcardPkgs.libtool
            coldcardPkgs.m4
            coldcardPkgs.pcsclite
            coldcardPkgs.python312Packages.virtualenv
            coldcardPkgs.SDL2
            coldcardPkgs.swig
            coldcardPkgs.systemd
            coldcardPkgs.xterm
          ];
        speculos = pkgs.callPackage ./nix/speculos.nix {};
        ledgerInputs =
          emulatorInputs
          ++ [
            pkgs.docker-client
            pkgs.podman
            speculos
          ];
        jadeQemuInputs =
          emulatorInputs
          ++ [
            jadeEspIdf
          ]
          ++ builtins.attrValues jadeEspIdf.passthru.tools
          ++ [
            espPkgs.qemu-esp32
            pkgs.cmake
            pkgs.ninja
            pkgs.python3Packages.virtualenv
          ];
        jadeInitInputs =
          emulatorInputs
          ++ [
            pkgs.python3Packages.virtualenv
          ];
        jadePinserverInputs =
          emulatorInputs
          ++ [
            pkgs.gcc
            pkgs.python311
            pkgs.python311Packages.virtualenv
          ];
        jadeInputs = jadeQemuInputs ++ jadePinserverInputs;
        mkApp = program: {
          type = "app";
          program = pkgs.lib.getExe program;
        };
        commonE2eEnv = ''
          export LIBCLANG_PATH=${pkgs.libclang.lib}/lib/
          export LD_LIBRARY_PATH=${pkgs.openssl}/lib:''${LD_LIBRARY_PATH:-}
          export RUST_TEST_THREADS=1
        '';
        coldcardE2eEnv = ''
          export LIBCLANG_PATH=${pkgs.libclang.lib}/lib/
          export COLDCARD_RUNTIME_LIBRARY_PATH="${coldcardPkgs.lib.makeLibraryPath [
            coldcardPkgs.SDL2
            coldcardPkgs.gcc13.cc.lib
            coldcardPkgs.glibc
            coldcardPkgs.libffi
            coldcardPkgs.openssl.out
            coldcardPkgs.pcsclite
            coldcardPkgs.systemd
          ]}"
          export LD_LIBRARY_PATH=${pkgs.openssl}/lib:''${LD_LIBRARY_PATH:-}
          export ACLOCAL_PATH="${coldcardPkgs.libtool}/share/aclocal:''${ACLOCAL_PATH:-}"
          export PKG_CONFIG_PATH="${coldcardPkgs.libffi.dev}/lib/pkgconfig:''${PKG_CONFIG_PATH:-}"
          export PYSDL2_DLL_PATH="${coldcardPkgs.SDL2}/lib"
          export CFLAGS="-I${coldcardPkgs.pcsclite.dev}/include/PCSC ''${CFLAGS:-}"
          export LDFLAGS="-L${coldcardPkgs.pcsclite}/lib ''${LDFLAGS:-}"
          export RUST_TEST_THREADS=1
        '';
        mkHwiParityRunner = name: device: runtimeInputs: env:
          pkgs.writeShellApplication {
            inherit name runtimeInputs;
            text =
              env
              + ''

                set -euo pipefail
                export REFERENCE_HWI_BIN="${pkgs.lib.getExe hwiReferenceBhwi}"
                export HWI_BIN="''${HWI_BIN:-$PWD/target/debug/hwi}"
                export HWI_PARITY_DEVICE_TYPE="${device}"

                cargo build -p bhwi-cli --bins
                exec cargo test -p bhwi-e2e-hwi-parity "$@"
              '';
          };
        mkRunnerWith = runnerPkgs: name: runtimeInputs: env: script:
          runnerPkgs.writeShellApplication {
            inherit name runtimeInputs;
            text =
              env
              + ''

                exec ${runnerPkgs.bash}/bin/bash ${script} "$@"
              '';
          };
        mkRunner = mkRunnerWith pkgs;
        coldcardRunner = mkRunnerWith coldcardPkgs "bhwi-start-coldcard" coldcardInputs ''
          unset LD_LIBRARY_PATH
          unset C_INCLUDE_PATH
          unset CPLUS_INCLUDE_PATH
          unset LIBRARY_PATH
          unset OBJC_INCLUDE_PATH
          unset OBJCPLUS_INCLUDE_PATH
          export COLDCARD_RUNTIME_LIBRARY_PATH="${coldcardPkgs.lib.makeLibraryPath [
            coldcardPkgs.SDL2
            coldcardPkgs.gcc13.cc.lib
            coldcardPkgs.glibc
            coldcardPkgs.libffi
            coldcardPkgs.openssl.out
            coldcardPkgs.pcsclite
            coldcardPkgs.systemd
          ]}"
          export COLDCARD_FIRMWARE_SRC="${coldcard-firmware}"
          export COLDCARD_FIRMWARE_REV="${coldcard-firmware.rev or "locked"}"
          export COLDCARD_FIRMWARE_URL="https://github.com/Coldcard/firmware.git"
          export ACLOCAL_PATH="${coldcardPkgs.libtool}/share/aclocal:''${ACLOCAL_PATH:-}"
          export PKG_CONFIG_PATH="${coldcardPkgs.libffi.dev}/lib/pkgconfig:''${PKG_CONFIG_PATH:-}"
          export PYSDL2_DLL_PATH="${coldcardPkgs.SDL2}/lib"
          export CFLAGS="-I${coldcardPkgs.pcsclite.dev}/include/PCSC ''${CFLAGS:-}"
          export LDFLAGS="-L${coldcardPkgs.pcsclite}/lib ''${LDFLAGS:-}"
        '' ./nix/scripts/start-coldcard.sh;
        ledgerRunner = mkRunner "bhwi-start-ledger" ledgerInputs ''
          export APP_BITCOIN_NEW_SRC="${app-bitcoin-new}"
          export APP_BITCOIN_NEW_REV="${app-bitcoin-new.rev or "locked"}"
          export APP_BITCOIN_NEW_URL="https://github.com/LedgerHQ/app-bitcoin-new.git"
          export SPECULOS_BIN="${speculos}/bin/speculos"
          export LEDGER_BUILD_APP_SCRIPT="${./nix/scripts/build-ledger-app.sh}"
        '' ./nix/scripts/start-ledger.sh;
        ledgerAppBuilder = mkRunner "bhwi-build-ledger-app" ledgerInputs ''
          export APP_BITCOIN_NEW_SRC="${app-bitcoin-new}"
          export APP_BITCOIN_NEW_REV="${app-bitcoin-new.rev or "locked"}"
          export APP_BITCOIN_NEW_URL="https://github.com/LedgerHQ/app-bitcoin-new.git"
        '' ./nix/scripts/build-ledger-app.sh;
        jadeRunner = mkRunner "bhwi-start-jade" jadeQemuInputs ''
          export JADE_FIRMWARE_SRC="${jade-firmware}"
          export JADE_FIRMWARE_REV="${jade-firmware.rev or "locked"}"
          export JADE_FIRMWARE_URL="https://github.com/Blockstream/Jade.git"
          export PATH="${jadePython}/bin:$PATH"
          export IDF_PATH="${jadeEspIdf}"
          export IDF_TOOLS_PATH="$IDF_PATH/tools"
          export IDF_PYTHON_CHECK_CONSTRAINTS=no
          IDF_PYTHON_ENV_PATH="$(readlink "$IDF_PATH/python-env")"
          export IDF_PYTHON_ENV_PATH
          export PATH="$IDF_TOOLS_PATH:$IDF_PATH/components/espcoredump:$IDF_PATH/components/partition_table:$IDF_PATH/components/app_update:$PATH"
          if [ -e "$IDF_PATH/.tool-env" ]; then
            # shellcheck disable=SC1091
            . "$IDF_PATH/.tool-env"
          fi
          if [ -e "$IDF_PATH/etc/gitconfig" ]; then
            export GIT_CONFIG_SYSTEM="$IDF_PATH/etc/gitconfig"
          fi
        '' ./nix/scripts/start-jade.sh;
        jadeInitRunner = mkRunner "bhwi-init-jade" jadeInitInputs ''
          export JADE_FIRMWARE_SRC="${jade-firmware}"
          export JADE_FIRMWARE_REV="${jade-firmware.rev or "locked"}"
          export JADE_FIRMWARE_URL="https://github.com/Blockstream/Jade.git"
        '' ./nix/scripts/init-jade.sh;
        jadePinserverRunner = mkRunner "bhwi-start-jade-pinserver" jadePinserverInputs ''
          export JADE_FIRMWARE_SRC="${jade-firmware}"
          export JADE_FIRMWARE_REV="${jade-firmware.rev or "locked"}"
          export JADE_FIRMWARE_URL="https://github.com/Blockstream/Jade.git"
          export JADE_PINSERVER_SRC="${jade-pinserver}"
          export JADE_PINSERVER_REV="${jade-pinserver.rev or "locked"}"
          export JADE_PINSERVER_URL="https://github.com/Blockstream/blind_pin_server.git"
          export JADE_PINSERVER_PYTHON="${pkgs.python311}/bin/python3"
        '' ./nix/scripts/start-jade-pinserver.sh;
        hwiReference = pkgs.writeShellApplication {
          name = "hwi-reference";
          runtimeInputs = [hwiPython];
          text = ''
            export PYTHONPATH="${python-hwi}:''${PYTHONPATH:-}"
            exec ${hwiPython}/bin/python ${python-hwi}/hwi.py "$@"
          '';
        };
        hwiReferenceBhwi = pkgs.writeShellApplication {
          name = "hwi-reference-bhwi";
          runtimeInputs = [hwiPython];
          text = ''
            export PYTHONPATH="${python-hwi}:''${PYTHONPATH:-}"
            exec ${hwiPython}/bin/python - "$@" <<'PY'
from hwilib import commands

commands.all_devs = ["ledger", "coldcard", "jade"]

from hwilib._cli import main

main()
PY
          '';
        };
        hwiUpstreamSuite = pkgs.writeShellApplication {
          name = "hwi-upstream-suite";
          runtimeInputs =
            inputs
            ++ ledgerInputs
            ++ [
              hwiPython
              pkgs.bitcoin
            ];
          text = ''
            export HWI_UPSTREAM_SRC="${python-hwi}"
            export HWI_BITCOIND="''${HWI_BITCOIND:-${pkgs.bitcoin}/bin/bitcoind}"
            export HWI_LEDGER_SPECULOS_BIN="''${HWI_LEDGER_SPECULOS_BIN:-${speculos}/bin/speculos}"
            export LEDGER_BUILD_APP_SCRIPT="''${LEDGER_BUILD_APP_SCRIPT:-${./nix/scripts/build-ledger-app.sh}}"
            export APP_BITCOIN_NEW_SRC="${app-bitcoin-new}"
            export APP_BITCOIN_NEW_REV="${app-bitcoin-new.rev or "locked"}"
            export APP_BITCOIN_NEW_URL="https://github.com/LedgerHQ/app-bitcoin-new.git"
            export PYTHONPATH="${python-hwi}:''${PYTHONPATH:-}"

            exec ${pkgs.bash}/bin/bash ${./nix/scripts/run-hwi-upstream-suite.sh} "$@"
          '';
        };
        hwiParityColdcard = mkHwiParityRunner "bhwi-hwi-parity-coldcard" "coldcard" (coldcardInputs ++ inputs) coldcardE2eEnv;
        hwiParityLedger = mkHwiParityRunner "bhwi-hwi-parity-ledger" "ledger" (ledgerInputs ++ inputs) commonE2eEnv;
        hwiParityJade = mkHwiParityRunner "bhwi-hwi-parity-jade" "jade" (jadeInputs ++ inputs) commonE2eEnv;
        linuxPackages =
          pkgs.lib.optionalAttrs emulatorSystem {
            inherit speculos;
            coldcard-simulator = coldcardRunner;
            ledger-app = ledgerAppBuilder;
            jade-qemu = jadeRunner;
          };
        linuxApps =
          pkgs.lib.optionalAttrs emulatorSystem {
            coldcard = mkApp coldcardRunner;
            ledger = mkApp ledgerRunner;
            ledger-build-app = mkApp ledgerAppBuilder;
            hwi-upstream-suite = mkApp hwiUpstreamSuite;
            hwi-parity-coldcard = mkApp hwiParityColdcard;
            hwi-parity-ledger = mkApp hwiParityLedger;
            hwi-parity-jade = mkApp hwiParityJade;
            jade = mkApp jadeRunner;
            jade-init = mkApp jadeInitRunner;
            jade-pinserver = mkApp jadePinserverRunner;
          };
        linuxShells =
          pkgs.lib.optionalAttrs emulatorSystem {
            coldcard = pkgs.mkShell {
              packages = coldcardInputs ++ inputs;
              shellHook = coldcardE2eEnv;
            };
            ledger = pkgs.mkShell {
              packages = inputs ++ ledgerInputs;
              shellHook = commonE2eEnv;
            };
            jade = pkgs.mkShell {
              packages = inputs ++ jadeInputs;
              shellHook = commonE2eEnv;
            };
          };
        linuxChecks =
          pkgs.lib.optionalAttrs emulatorSystem {
            emulator-scripts = pkgs.runCommand "bhwi-emulator-scripts" {} ''
              test -f ${./nix/scripts/start-coldcard.sh}
              test -f ${./nix/scripts/start-ledger.sh}
              test -f ${./nix/scripts/start-jade.sh}
              test -f ${./nix/scripts/start-jade-pinserver.sh}
              test -f ${./nix/scripts/init-jade.sh}
              test -f ${./nix/scripts/emit-gh-error-log.sh}
              touch $out
            '';
          };
      in {
        packages = {
          hwi-reference = hwiReference;
          hwi-reference-bhwi = hwiReferenceBhwi;
          hwi-upstream-suite = hwiUpstreamSuite;
          default = pkgs.rustPlatform.buildRustPackage {
            name = "bhwi";
            src = ./.;

            cargoLock = {
              lockFile = ./Cargo.lock;
            };

            nativeBuildInputs = inputs;
          };
          website = mkWebsite {};
          website-ghpages = mkWebsite { base = "/bhwi/"; };
        } // linuxPackages;

        devShells = {
          default = pkgs.mkShell {
            packages = inputs;
            shellHook = ''
              export LIBCLANG_PATH=${pkgs.libclang.lib}/lib/
              export LD_LIBRARY_PATH=${pkgs.openssl}/lib:$LD_LIBRARY_PATH
              export CC_wasm32_unknown_unknown=${pkgs.llvmPackages.clang-unwrapped}/bin/clang
              export CFLAGS_wasm32_unknown_unknown="-I ${pkgs.llvmPackages.libclang.lib}/lib/clang/21.1.8/include/"
            '';
          };
        } // linuxShells;

        apps = {
          website = {
            type = "app";
            program = toString (pkgs.writeShellScript "run-website" ''
              export PATH="${pkgs.lib.makeBinPath [pkgs.nodejs_20 pkgs.corepack_20]}:$PATH"
              rm -rf website/pkg
              cp -rL --no-preserve=mode,ownership ${bhwi-wasm-pkg} website/pkg
              cd website && npm install && npm run dev
            '');
          };
        } // linuxApps;

        checks = linuxChecks;
      }
    );
}
