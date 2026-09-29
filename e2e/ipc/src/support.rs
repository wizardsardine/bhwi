use std::cell::{Cell, RefCell};
use std::env;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::rc::Rc;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use bhwi_ipc::bhwi_capnp::{
    AddressFormat, DeviceType, ErrorCode, Network, bhwi as bhwi_service, device, prompter,
    registration, result, selector,
};
use miniscript::{Descriptor, DescriptorPublicKey, psbt::PsbtExt};

use crate::approve::{Approver, accept_coldcard_prompt, approving};
use bitcoin::{
    Address, Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    absolute::LockTime,
    bip32::{DerivationPath, Fingerprint, Xpriv, Xpub},
    psbt::{Input, Psbt},
    secp256k1::Secp256k1,
    sign_message::{MessageSignature, signed_msg_hash},
    transaction::Version as TxVersion,
};
use capnp::traits::Owned;
use capnp_rpc::{RpcSystem, rpc_twoparty_capnp::Side, twoparty};
use tokio::net::UnixStream;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

const START_TIMEOUT: Duration = Duration::from_secs(10);

static SOCKETS: AtomicUsize = AtomicUsize::new(0);

struct Server {
    child: Child,
    socket: PathBuf,
}

impl Server {
    fn start() -> Result<Self> {
        let binary = binary()?;
        let socket = env::temp_dir().join(format!(
            "bhwi-ipc-e2e-{}-{}.sock",
            std::process::id(),
            SOCKETS.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&socket);
        let child = Command::new(&binary)
            .arg("--socket")
            .arg(&socket)
            .spawn()
            .with_context(|| format!("starting {}", binary.display()))?;
        let mut server = Self { child, socket };
        server.wait_until_listening()?;
        Ok(server)
    }

    fn wait_until_listening(&mut self) -> Result<()> {
        let deadline = Instant::now() + START_TIMEOUT;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait()? {
                bail!("bhwi-ipc exited with {status} before it listened");
            }
            if std::os::unix::net::UnixStream::connect(&self.socket).is_ok() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        bail!(
            "bhwi-ipc did not listen on {} within {START_TIMEOUT:?}",
            self.socket.display()
        )
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

fn binary() -> Result<PathBuf> {
    if let Some(path) = env::var_os("BHWI_IPC_BIN") {
        return Ok(PathBuf::from(path));
    }
    let target = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"));
    let path = target.join("debug").join("bhwi-ipc");
    if !path.exists() {
        bail!(
            "{} is missing: run `cargo build -p bhwi-ipc` or set BHWI_IPC_BIN",
            path.display()
        );
    }
    Ok(path)
}

pub(crate) fn with_server<F, Fut>(test: F) -> Result<()>
where
    F: FnOnce(bhwi_service::Client) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    with_server_socket(|socket| async move {
        let connection = Connection::open(&socket).await?;
        test(connection.client.clone()).await
    })
}

pub(crate) fn with_server_socket<F, Fut>(test: F) -> Result<()>
where
    F: FnOnce(PathBuf) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let server = Server::start()?;
    let socket = server.socket.clone();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, test(socket))
}

/// Dropping it closes the socket, which is how a client that dies looks to the
/// server.
pub(crate) struct Connection {
    pub(crate) client: bhwi_service::Client,
    rpc: tokio::task::JoinHandle<()>,
}

impl Connection {
    pub(crate) async fn open(socket: &Path) -> Result<Self> {
        let stream = UnixStream::connect(socket)
            .await
            .with_context(|| format!("connecting to {}", socket.display()))?;
        let (reader, writer) = stream.into_split();
        let network = twoparty::VatNetwork::new(
            futures::io::BufReader::new(reader.compat()),
            futures::io::BufWriter::new(writer.compat_write()),
            Side::Client,
            Default::default(),
        );
        let mut rpc = RpcSystem::new(Box::new(network), None);
        let client: bhwi_service::Client = rpc.bootstrap(Side::Server);
        let rpc = tokio::task::spawn_local(async move {
            let _ = rpc.await;
        });
        Ok(Self { client, rpc })
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.rpc.abort();
    }
}

pub(crate) fn set_selector(
    builder: selector::Builder<'_>,
    device_type: DeviceType,
    fingerprint: &str,
) {
    set_selector_on(builder, Network::Testnet, device_type, fingerprint);
}

pub(crate) fn set_selector_on(
    mut builder: selector::Builder<'_>,
    network: Network,
    device_type: DeviceType,
    fingerprint: &str,
) {
    builder.set_network(network);
    builder.set_fingerprint(fingerprint);
    builder.set_include_emulators(true);
    builder.reborrow().init_device_type().set_only(device_type);
    builder.init_passphrase().set_none(());
}

pub(crate) fn ok<T: Owned>(result: result::Reader<'_, T>) -> Result<T::Reader<'_>> {
    match result.which()? {
        result::Which::Ok(value) => Ok(value?),
        result::Which::Error(error) => {
            let error = error?;
            bail!(
                "{:?}: {}",
                error.get_code()?,
                error.get_message()?.to_str()?
            )
        }
    }
}

pub(crate) fn error_code<T: Owned>(result: result::Reader<'_, T>) -> Result<ErrorCode> {
    match result.which()? {
        result::Which::Ok(_) => bail!("expected an error, the call succeeded"),
        result::Which::Error(error) => Ok(error?.get_code()?),
    }
}

pub(crate) async fn open(
    client: &bhwi_service::Client,
    device_type: DeviceType,
    fingerprint: &str,
) -> Result<bhwi_ipc::bhwi_capnp::device::Client> {
    open_on(client, Network::Testnet, device_type, fingerprint).await
}

pub(crate) async fn open_on(
    client: &bhwi_service::Client,
    network: Network,
    device_type: DeviceType,
    fingerprint: &str,
) -> Result<bhwi_ipc::bhwi_capnp::device::Client> {
    let mut request = client.open_device_request();
    set_selector_on(
        request.get().init_selector(),
        network,
        device_type,
        fingerprint,
    );
    let response = request.send().promise.await?;
    Ok(ok(response.get()?.get_result()?)?.get_device()?)
}

/// `listDevices` reaches the device, so this also proves the transport works
/// before any session is opened.
pub(crate) fn assert_listed_emulator(
    device_type: DeviceType,
    fingerprint: &'static str,
    model: &'static str,
) -> Result<()> {
    with_server(move |client| async move {
        let mut request = client.list_devices_request();
        set_selector(request.get().init_selector(), device_type, fingerprint);
        let response = request.send().promise.await?;
        let devices = ok(response.get()?.get_result()?)?.get_devices()?;
        assert_eq!(devices.len(), 1, "expected exactly one {model}");
        let device = devices.get(0);
        assert_eq!(device.get_fingerprint()?.to_str()?, fingerprint);
        assert!(device.get_is_emulated());
        let reported = device.get_model()?.to_str()?;
        assert!(reported.contains(model), "{reported} is not a {model}");
        assert!(!device.get_info()?.get_version()?.to_str()?.is_empty());
        Ok(())
    })
}

pub(crate) fn account_xpub(
    device_type: DeviceType,
    fingerprint: &'static str,
    path: &'static str,
    expected: &'static str,
) -> Result<()> {
    with_server(move |client| async move {
        let device = open(&client, device_type, fingerprint).await?;
        let mut request = device.get_extended_pubkey_request();
        request.get().set_path(path);
        request.get().set_display(false);
        let response = request.send().promise.await?;
        assert_eq!(ok(response.get()?.get_result()?)?.to_str()?, expected);
        Ok(())
    })
}

pub(crate) fn assert_descriptor_set(
    device_type: DeviceType,
    fingerprint: &'static str,
) -> Result<()> {
    assert_descriptor_set_on(Network::Testnet, device_type, fingerprint)
}

pub(crate) fn assert_descriptor_set_on(
    network: Network,
    device_type: DeviceType,
    fingerprint: &'static str,
) -> Result<()> {
    with_server(move |client| async move {
        let device = open_on(&client, network, device_type, fingerprint).await?;
        let mut request = device.get_descriptors_request();
        request.get().set_account(0);
        let response = request.send().promise.await?;
        let descriptors = ok(response.get()?.get_result()?)?;
        let receive = descriptors.get_receive()?;
        let internal = descriptors.get_internal()?;
        assert!(!receive.is_empty(), "no receive descriptors");
        assert_eq!(receive.len(), internal.len());
        for index in 0..receive.len() {
            let descriptor = receive.get(index)?.to_str()?;
            assert!(
                descriptor.contains(fingerprint),
                "{descriptor} has no key origin"
            );
            assert!(
                descriptor.contains("/0/*"),
                "{descriptor} is not a receive branch"
            );
        }
        for index in 0..internal.len() {
            let descriptor = internal.get(index)?.to_str()?;
            assert!(
                descriptor.contains("/1/*"),
                "{descriptor} is not a change branch"
            );
        }
        Ok(())
    })
}

pub(crate) fn assert_info_matches_discovery(
    network: Network,
    device_type: DeviceType,
    fingerprint: &'static str,
) -> Result<()> {
    with_server(move |client| async move {
        let mut request = client.list_devices_request();
        set_selector_on(
            request.get().init_selector(),
            network,
            device_type,
            fingerprint,
        );
        let response = request.send().promise.await?;
        let listed = ok(response.get()?.get_result()?)?.get_devices()?.get(0);
        let listed = listed.get_info()?;
        let listed_version = listed.get_version()?.to_string()?;
        let listed_networks = network_codes(listed.get_networks()?);

        let device = open_on(&client, network, device_type, fingerprint).await?;
        let response = device.get_info_request().send().promise.await?;
        let info = ok(response.get()?.get_result()?)?;
        assert_eq!(info.get_version()?.to_string()?, listed_version);
        assert_eq!(network_codes(info.get_networks()?), listed_networks);
        Ok(())
    })
}

fn network_codes(networks: capnp::enum_list::Reader<'_, Network>) -> Vec<Option<u16>> {
    networks
        .iter()
        .map(|network| network.ok().map(|network| network as u16))
        .collect()
}

pub(crate) fn assert_keypool_on(
    network: Network,
    device_type: DeviceType,
    fingerprint: &'static str,
    account_path: &'static str,
) -> Result<()> {
    with_server(move |client| async move {
        let device = open_on(&client, network, device_type, fingerprint).await?;
        let mut request = device.get_keypool_request();
        {
            let mut options = request.get().init_options();
            options.set_path(account_path);
            options.set_start(0);
            options.set_end(4);
            options.set_internal(false);
            options.set_address_format(AddressFormat::P2wpkh);
        }
        let response = request.send().promise.await?;
        let descriptor = ok(response.get()?.get_result()?)?.to_str()?;
        assert!(
            descriptor.starts_with("wpkh("),
            "{descriptor} is not native segwit"
        );
        assert!(
            descriptor.contains(fingerprint),
            "{descriptor} has no key origin"
        );
        assert!(
            descriptor.contains("/0/*"),
            "{descriptor} is not a receive branch"
        );
        Ok(())
    })
}

/// The address is checked against one derived here from the device's own
/// account xpub, so a wrong path or script type cannot agree by accident.
pub(crate) fn assert_address_matches_xpub_on(
    network: Network,
    device_type: DeviceType,
    fingerprint: &'static str,
    account_path: &'static str,
) -> Result<()> {
    address_matches_xpub(network, device_type, fingerprint, account_path, false, None)
}

pub(crate) fn assert_shows_address_on(
    network: Network,
    device_type: DeviceType,
    fingerprint: &'static str,
    account_path: &'static str,
    approver: Option<Approver>,
) -> Result<()> {
    address_matches_xpub(
        network,
        device_type,
        fingerprint,
        account_path,
        true,
        approver,
    )
}

fn address_matches_xpub(
    network: Network,
    device_type: DeviceType,
    fingerprint: &'static str,
    account_path: &'static str,
    display: bool,
    approver: Option<Approver>,
) -> Result<()> {
    with_server(move |client| async move {
        let device = open_on(&client, network, device_type, fingerprint).await?;
        let xpub = account_xpub_of(&device, account_path).await?;
        let receive = DerivationPath::from_str("m/0/0")?;
        let key = xpub.derive_pub(&Secp256k1::verification_only(), &receive)?;
        let expected = Address::p2wpkh(&key.to_pub(), address_network(network));

        let mut request = device.display_address_request();
        {
            let mut target = request.get().init_target().init_path();
            target.set_path(format!("{account_path}/0/0"));
            target.set_display(display);
            target.set_address_format(AddressFormat::P2wpkh);
        }
        let response = approving(approver, || request.send().promise).await??;
        assert_eq!(
            ok(response.get()?.get_result()?)?.to_str()?,
            expected.to_string()
        );
        Ok(())
    })
}

const MESSAGE: &str = "bhwi-ipc message signing";

/// The signature must recover to the key the device's own account xpub
/// derives at `{account_path}/0/0`.
pub(crate) fn assert_signs_message_on(
    network: Network,
    device_type: DeviceType,
    fingerprint: &'static str,
    account_path: &'static str,
    approver: Option<Approver>,
) -> Result<()> {
    with_server(move |client| async move {
        let device = open_on(&client, network, device_type, fingerprint).await?;
        let xpub = account_xpub_of(&device, account_path).await?;
        let secp = Secp256k1::verification_only();
        let key = xpub.derive_pub(&secp, &DerivationPath::from_str("m/0/0")?)?;

        let mut request = device.sign_message_request();
        request.get().set_message(MESSAGE.as_bytes());
        request.get().set_path(format!("{account_path}/0/0"));
        let response = approving(approver, || request.send().promise).await??;
        let signature =
            MessageSignature::from_base64(ok(response.get()?.get_result()?)?.to_str()?)?;
        let recovered = signature.recover_pubkey(&secp, signed_msg_hash(MESSAGE))?;
        assert_eq!(recovered.inner, key.public_key);
        Ok(())
    })
}

pub(crate) fn assert_signs_psbt_on(
    network: Network,
    device_type: DeviceType,
    fingerprint: &'static str,
    account_path: &'static str,
    approver: Option<Approver>,
) -> Result<()> {
    with_server(move |client| async move {
        let device = open_on(&client, network, device_type, fingerprint).await?;
        let xpub = account_xpub_of(&device, account_path).await?;
        let (psbt, input_pubkey) = single_input_psbt(
            &xpub,
            Fingerprint::from_str(fingerprint)?,
            account_path,
            address_network(network),
        )?;
        let signed = approving(approver, || sign_psbt(&device, &psbt, None)).await??;
        assert!(signed.inputs[0].partial_sigs.contains_key(&input_pubkey));
        Ok(())
    })
}

async fn sign_psbt(
    device: &device::Client,
    psbt: &Psbt,
    registered: Option<(&str, &[u8])>,
) -> Result<Psbt> {
    let mut request = device.sign_psbt_request();
    request.get().set_psbt(psbt.to_string());
    match registered {
        None => request.get().init_policy().set_auto(()),
        Some((policy, hmac)) => {
            let mut registered = request.get().init_policy().init_registered();
            registered.set_name(WALLET_NAME);
            registered.set_policy(policy);
            registered.set_hmac(hmac);
        }
    }
    let response = request.send().promise.await?;
    let signing = ok(response.get()?.get_result()?)?;
    let response = signing.result_request().send().promise.await?;
    let signed = ok(response.get()?.get_result()?)?;
    assert!(signed.get_signed());
    Ok(Psbt::from_str(signed.get_psbt()?.to_str()?)?)
}

pub(crate) async fn account_xpub_of(device: &device::Client, account_path: &str) -> Result<Xpub> {
    let mut request = device.get_extended_pubkey_request();
    request.get().set_path(account_path);
    request.get().set_display(false);
    let response = request.send().promise.await?;
    Ok(Xpub::from_str(
        ok(response.get()?.get_result()?)?.to_str()?,
    )?)
}

/// A one-input, one-output PSBT spending `{account_path}/0/0` to the
/// account's own change branch, so no device needs extra policy data.
pub(crate) fn single_input_psbt(
    xpub: &Xpub,
    fingerprint: Fingerprint,
    account_path: &str,
    network: bitcoin::Network,
) -> Result<(Psbt, PublicKey)> {
    let secp = Secp256k1::verification_only();
    let input_path = DerivationPath::from_str(&format!("{account_path}/0/0"))?;
    let change_path = DerivationPath::from_str(&format!("{account_path}/1/0"))?;
    let input_xpub = xpub.derive_pub(&secp, &DerivationPath::from_str("m/0/0")?)?;
    let change_xpub = xpub.derive_pub(&secp, &DerivationPath::from_str("m/1/0")?)?;
    let input_pubkey = PublicKey::new(input_xpub.public_key);
    let change_pubkey = PublicKey::new(change_xpub.public_key);
    let input_script = Address::p2wpkh(&input_xpub.to_pub(), network).script_pubkey();
    let change_script = Address::p2wpkh(&change_xpub.to_pub(), network).script_pubkey();

    let mut psbt = spend_psbt(input_script, change_script)?;
    psbt.inputs[0].bip32_derivation = [(input_pubkey.inner, (fingerprint, input_path))].into();
    psbt.outputs[0].bip32_derivation = [(change_pubkey.inner, (fingerprint, change_path))].into();
    Ok((psbt, input_pubkey))
}

fn spend_psbt(input_script: ScriptBuf, output_script: ScriptBuf) -> Result<Psbt> {
    let prev_tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: input_script.clone(),
        }],
    };
    let unsigned_tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev_tx.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: output_script,
        }],
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;
    psbt.inputs[0] = Input {
        non_witness_utxo: Some(prev_tx),
        witness_utxo: Some(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: input_script,
        }),
        ..Default::default()
    };
    Ok(psbt)
}

const WALLET_NAME: &str = "bhwi-ipc-e2e";

#[derive(Debug, PartialEq)]
pub(crate) enum Registered {
    Hmac,
    NoHmac,
    Pending,
}

pub(crate) fn assert_registers_wallet_on(
    network: Network,
    device_type: DeviceType,
    fingerprint: &'static str,
    approver: Option<Approver>,
    expected: Registered,
) -> Result<()> {
    with_server(move |client| async move {
        let device = open_on(&client, network, device_type, fingerprint).await?;
        let descriptor = multisig_descriptor(&device, network, fingerprint).await?;
        let (registered, _) = register(&device, &descriptor, approver).await?;
        assert_eq!(registered, expected);
        if registered == Registered::Pending {
            accept_coldcard_prompt().await?;
        }
        Ok(())
    })
}

/// Registers the wallet, then uses it by name: the receive address at index 0
/// must match miniscript's, and the device must sign for its own key.
pub(crate) fn assert_registered_wallet_on(
    network: Network,
    device_type: DeviceType,
    fingerprint: &'static str,
    approver: Option<Approver>,
    show: bool,
    sign: bool,
) -> Result<()> {
    with_server(move |client| async move {
        let device = open_on(&client, network, device_type, fingerprint).await?;
        let descriptor = multisig_descriptor(&device, network, fingerprint).await?;
        let (registered, hmac) = register(&device, &descriptor, approver).await?;
        assert_ne!(registered, Registered::Pending);
        let branches =
            Descriptor::<DescriptorPublicKey>::from_str(&descriptor)?.into_single_descriptors()?;
        let receive = branches[0].at_derivation_index(0)?;

        if show {
            let mut request = device.display_address_request();
            {
                let mut target = request.get().init_target().init_descriptor_name();
                target.set_name(WALLET_NAME);
                target.set_index(0);
                target.set_change(false);
                target.set_display(true);
                target.set_policy(&descriptor);
                target.set_hmac(&hmac);
            }
            let response = approving(approver, || request.send().promise).await??;
            assert_eq!(
                ok(response.get()?.get_result()?)?.to_str()?,
                receive.address(address_network(network))?.to_string()
            );
        }

        if sign {
            let change = branches[1].at_derivation_index(0)?;
            let mut psbt = spend_psbt(receive.script_pubkey(), change.script_pubkey())?;
            psbt.update_input_with_descriptor(0, &receive)?;
            psbt.update_output_with_descriptor(0, &change)?;
            let own = Fingerprint::from_str(fingerprint)?;
            let own_key = psbt.inputs[0]
                .bip32_derivation
                .iter()
                .find(|(_, (key_fingerprint, _))| *key_fingerprint == own)
                .map(|(key, _)| PublicKey::new(*key))
                .context("the input has no key of the device")?;
            let registered_policy = Some((descriptor.as_str(), hmac.as_slice()));
            let signed =
                approving(approver, || sign_psbt(&device, &psbt, registered_policy)).await??;
            assert!(signed.inputs[0].partial_sigs.contains_key(&own_key));
        }
        Ok(())
    })
}

async fn register(
    device: &device::Client,
    descriptor: &str,
    approver: Option<Approver>,
) -> Result<(Registered, Vec<u8>)> {
    let mut request = device.register_wallet_request();
    request.get().set_name(WALLET_NAME);
    request.get().set_policy(descriptor);
    let response = approving(approver, || request.send().promise).await??;
    Ok(match ok(response.get()?.get_result()?)?.which()? {
        registration::Which::Complete(complete) => {
            let hmac = complete.get_hmac()?.to_vec();
            match hmac.len() {
                0 => (Registered::NoHmac, hmac),
                32 => (Registered::Hmac, hmac),
                len => bail!("a {len}-byte HMAC, where Ledger's is 32"),
            }
        }
        registration::Which::PendingUserConfirmation(()) => (Registered::Pending, Vec::new()),
    })
}

async fn multisig_descriptor(
    device: &device::Client,
    network: Network,
    fingerprint: &str,
) -> Result<String> {
    let coin = if network == Network::Bitcoin { 0 } else { 1 };
    let path = format!("m/48'/{coin}'/0'/2'");
    let own = account_xpub_of(device, &path).await?;
    let secp = Secp256k1::new();
    let seed = Xpriv::new_master(address_network(network), &[7; 32])?;
    let cosigner = Xpub::from_priv(
        &secp,
        &seed.derive_priv(&secp, &DerivationPath::from_str(&path)?)?,
    );
    let origin = |fingerprint: &str| format!("[{fingerprint}/48'/{coin}'/0'/2']");
    Ok(format!(
        "wsh(sortedmulti(2,{}{own}/<0;1>/*,{}{cosigner}/<0;1>/*))",
        origin(fingerprint),
        origin(&seed.fingerprint(&secp).to_string()),
    ))
}

fn address_network(network: Network) -> bitcoin::Network {
    match network {
        Network::Bitcoin => bitcoin::Network::Bitcoin,
        Network::Regtest => bitcoin::Network::Regtest,
        Network::Testnet | Network::Testnet4 | Network::Signet => bitcoin::Network::Testnet,
    }
}

/// Refuses every prompt the way the schema asks a client to: an exception whose
/// reason is "<code>: <message>".
pub(crate) struct RefusingPrompter(pub(crate) &'static str);

impl prompter::Server for RefusingPrompter {
    async fn request_passphrase(
        self: Rc<Self>,
        _: prompter::RequestPassphraseParams,
        _: prompter::RequestPassphraseResults,
    ) -> Result<(), capnp::Error> {
        Err(capnp::Error::failed(self.0.to_owned()))
    }
}

/// Counts prompts, so a test can prove the server asked rather than filling
/// the answer in itself.
#[derive(Default)]
pub(crate) struct RecordingPrompter {
    pub(crate) passphrases: Rc<Cell<usize>>,
    pub(crate) pairing_codes: Rc<RefCell<Vec<String>>>,
}

impl prompter::Server for RecordingPrompter {
    async fn request_passphrase(
        self: Rc<Self>,
        _: prompter::RequestPassphraseParams,
        mut results: prompter::RequestPassphraseResults,
    ) -> Result<(), capnp::Error> {
        self.passphrases.set(self.passphrases.get() + 1);
        results.get().set_passphrase("");
        Ok(())
    }

    async fn pairing_code(
        self: Rc<Self>,
        params: prompter::PairingCodeParams,
        _: prompter::PairingCodeResults,
    ) -> Result<(), capnp::Error> {
        let code = params.get()?.get_code()?.to_string()?;
        self.pairing_codes.borrow_mut().push(code);
        Ok(())
    }
}
