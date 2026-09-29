@0xf04f3deea0bc23a6;

# Plain Cap'n Proto: no libmultiprocess annotations, so a client needs this file
# and a capnp runtime and nothing else.
#
# Method and field ordinals are permanent once published. Add, never renumber.
#
# A failure a client can act on arrives as the `error` arm of a method's
# `Result`. Exceptions are left for a lost connection, an unreadable request and
# bugs in the server.
#
# `Prompter` is implemented by the client, which refuses a prompt by raising an
# exception whose reason reads "<code>: <message>", e.g. "userCancelled: ...".

interface Bhwi {
  # The bootstrap capability served on the socket.

  listDevices @0 (selector :Selector, prompter :Prompter) -> (result :Result(DeviceList));
  # Enumerates and unlocks every matching device. Devices that could not be
  # opened are reported in `skipped` rather than failing the call.

  openDevice @1 (selector :Selector, prompter :Prompter) -> (result :Result(OpenedDevice));
  # Takes exclusive hold of the first matching device until the returned
  # capability is dropped. A second caller gets `busy`. Devices passed
  # over on the way to this one are reported in `skipped`.
  #
  # `prompter` is optional: a null capability means the server may not ask the
  # client anything, so a device that needs a PIN or a passphrase fails instead.
}

interface Device {
  getInfo @0 () -> (result :Result(Info));
  getMasterFingerprint @1 () -> (result :Result(Text));
  getExtendedPubkey @2 (path :Text, display :Bool) -> (result :Result(Text));
  getDescriptors @3 (account :UInt32) -> (result :Result(Descriptors));
  getKeypool @4 (options :KeypoolOptions) -> (result :Result(Text));
  signMessage @5 (message :Data, path :Text) -> (result :Result(Text));
  # The signature is the base64 header-and-compact-signature form Bitcoin Core
  # accepts for `verifymessage`.

  displayAddress @6 (target :AddressTarget) -> (result :Result(Text));
  registerWallet @7 (name :Text, policy :Text) -> (result :Result(Registration));
  signPsbt @8 (psbt :Text, policy :SigningPolicy) -> (result :Result(Signing));
  setupDevice @9 (options :SetupOptions) -> (result :Result(Success));
  restoreDevice @10 (options :RestoreOptions) -> (result :Result(Success));
  wipeDevice @11 () -> (result :Result(Success));
  backupDevice @12 () -> (result :Result(Backup));
  togglePassphrase @13 () -> (result :Result(Success));
}

interface Signing {
  # One signing run. The device stays held until `result` returns or `abort`
  # is called.

  result @0 () -> (result :Result(SignedPsbt));

  abort @1 ();
  # Cancels the run. The device is left in whatever state the interrupted
  # exchange put it in, so the `Device` capability is closed too.
}

interface Prompter {
  # Implemented by the client. The server calls it while a command is in flight.

  pairingCode @0 (code :Text);
  # BitBox02 shows this code on its screen for the user to compare. The server
  # does not wait for a reply; the user confirms on the device.

  requestPin @1 (kind :PinKind) -> (positions :Text);
  # `positions` are the keypad positions the user reads off the device screen,
  # not the PIN digits.

  requestPassphrase @2 () -> (passphrase :Text);

  requestRecoveryCharacter @3 (wordPosition :UInt32, characterPosition :UInt32)
      -> (input :RecoveryInput);
  # Restoring a seed one character at a time. Positions are 0-based and name the
  # word and the letter within it that the device is asking for.
}

struct Result(Ok) {
  union {
    ok @0 :Ok;
    error @1 :Error;
  }
}

struct Error {
  code @0 :ErrorCode;
  message @1 :Text;
}

struct Success {
  # Generic parameters must be pointer types, so a Bool result is wrapped.
  success @0 :Bool;
}

struct DeviceList {
  devices @0 :List(DeviceInfo);
  skipped @1 :List(SkippedDevice);
}

struct OpenedDevice {
  device @0 :Device;
  networkMismatch @1 :NetworkMismatch;
  skipped @2 :List(SkippedDevice);
}

struct Descriptors {
  receive @0 :List(Text);
  internal @1 :List(Text);
}

struct SignedPsbt {
  psbt @0 :Text;
  signed @1 :Bool;
  # False when the device returned the PSBT unchanged.
}

struct RecoveryInput {
  union {
    character @0 :Text;
    # One lowercase ASCII letter.

    delete @1 :Void;
    # Undo the previous character.

    nextWord @2 :Void;
    # The word is complete.

    done @3 :Void;
    # The whole seed is entered.
  }
}

struct Selector {
  network @0 :Network;
  fingerprint @1 :Text;
  # Master fingerprint as 8 hex characters. Empty matches any device.

  deviceType @2 :DeviceTypeFilter;
  devicePath @3 :Text;
  # Transport path as reported by `listDevices`. Empty matches any device.

  includeEmulators @4 :Bool;
  passphrase :union {
    none @5 :Void;
    value @6 :Text;
    askPrompter @7 :Void;
    # Call `Prompter.requestPassphrase` before enumerating.
  }
}

struct DeviceInfo {
  name @0 :Text;
  deviceType @1 :DeviceType;
  path @2 :Text;
  model @3 :Text;
  isEmulated @4 :Bool;
  fingerprint @5 :Text;
  # Empty on a device with no wallet material yet.

  info @6 :Info;
  canSignTaproot @7 :Bool;
  networkMismatch @8 :NetworkMismatch;
}

struct NetworkMismatch {
  # An empty `reported` means the device claimed no networks, so nothing
  # mismatched.
  expected @0 :Network;
  reported @1 :List(Network);
}

struct SkippedDevice {
  deviceType @0 :DeviceType;
  model @1 :Text;
  path @2 :Text;
  error @3 :Text;
  code @4 :ErrorCode;
}

struct Info {
  version @0 :Text;
  networks @1 :List(Network);
  firmware @2 :Text;
  label @3 :Text;
  initialized @4 :OptionalBool;
  onDevicePassphraseEntry @5 :OptionalBool;
  needsPinSent @6 :OptionalBool;
  needsPassphraseSent @7 :OptionalBool;
}

struct KeypoolOptions {
  path @0 :Text;
  start @1 :UInt32;
  end @2 :UInt32;
  internal @3 :Bool;
  addressFormat @4 :AddressFormat;
}

struct AddressTarget {
  union {
    path :group {
      path @0 :Text;
      display @1 :Bool;
      addressFormat @2 :AddressFormat;
    }
    descriptorName :group {
      # A policy already registered on the device, named.
      name @3 :Text;
      index @4 :UInt32;
      change @5 :Bool;
      display @6 :Bool;
      policy @7 :Text;
      # Wallet policy descriptor. Required for BitBox02 and Specter-DIY, and
      # for Ledger together with `hmac`.

      hmac @8 :Data;
      # 32 bytes from `registerWallet`. Ledger only.
    }
    descriptor @9 :Text;
    # A full output descriptor, read as singlesig first and then as multisig on
    # devices that take one at display time.
  }
}

struct SigningPolicy {
  union {
    auto @0 :Void;
    # Derive the wallet policies the PSBT needs. On a Ledger this registers
    # every multisig policy it does not already hold, which prompts the user.

    registered :group {
      name @1 :Text;
      policy @2 :Text;
      hmac @3 :Data;
      # 32 bytes from `registerWallet`, empty for a default policy. Ledger
      # only; Specter-DIY takes the policy alone.
    }
  }
}

struct SetupOptions {
  # The server supplies the host entropy and the host clock the device needs.
  label @0 :Text;
}

struct RestoreOptions {
  # The server supplies the host clock and the U2F counter, which must never go
  # backwards.
  label @0 :Text;
  wordCount @1 :Int32;
}

struct Registration {
  union {
    complete :group {
      hmac @0 :Data;
      # 32 bytes on a Ledger, empty on devices that return none.
    }
    pendingUserConfirmation @1 :Void;
  }
}

struct Backup {
  union {
    complete @0 :Void;
    # The device wrote the backup itself, to an SD card or its own screen.

    file @1 :Data;
  }
}

struct OptionalBool {
  # A device that does not report a capability leaves it unset.
  union {
    unknown @0 :Void;
    value @1 :Bool;
  }
}

struct DeviceTypeFilter {
  union {
    any @0 :Void;
    only @1 :DeviceType;
  }
}

enum DeviceType {
  bitbox02 @0;
  coldcard @1;
  jade @2;
  ledger @3;
  trezor @4;
  keepkey @5;
  specter @6;
}

enum Network {
  bitcoin @0;
  testnet @1;
  testnet4 @2;
  signet @3;
  regtest @4;
}

enum AddressFormat {
  unspecified @0;
  p2pkh @1;
  p2sh @2;
  p2wpkh @3;
  p2wsh @4;
  p2tr @5;
}

enum PinKind {
  current @0;
  # Unlocking a device that already has a PIN.

  chooseNew @1;
  # Setting a PIN, first entry.

  confirmNew @2;
  # Setting a PIN, second entry. The client should ask the user to re-enter.
}

enum ErrorCode {
  # Carried in `Error.code` and `SkippedDevice.code`, and as the prefix of a
  # `Prompter` exception's reason. Codes up to `other` mirror
  # `bhwi::common::ErrorKind`; the rest come from the server itself.
  userCancelled @0;
  authenticationRefused @1;
  hostUnavailable @2;
  locked @3;
  notReady @4;
  busy @5;
  alreadyUnlocked @6;
  notInitialized @7;
  alreadyInitialized @8;
  wrongPin @9;
  wrongNetwork @10;
  duplicate @11;
  unsupported @12;
  unsupportedDisplayAddress @13;
  missingContext @14;
  invalidInput @15;
  rejected @16;
  deviceFailure @17;
  protocol @18;
  unexpectedResponse @19;
  serialization @20;
  encryption @21;
  transport @22;
  disconnected @23;
  other @24;
  noDevice @25;
  badArgument @26;
}
