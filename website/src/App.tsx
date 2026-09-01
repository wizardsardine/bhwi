import { useEffect, useState } from 'react'
import initWasm, { initialize_logging, Client } from 'bhwi-wasm';
import coldcardIcon from './assets/devices/coldcard.svg';
import jadeIcon from './assets/devices/blockstream-jade.svg';
import ledgerIcon from './assets/devices/ledger-nano.svg';
import bitboxIcon from './assets/devices/bitbox02.svg';
import trezorOneIcon from './assets/devices/trezor-one.svg';
import trezorTIcon from './assets/devices/trezor-model-t.svg';

type DeviceType = 'Coldcard' | 'Jade' | 'Ledger' | 'BitBox02' | 'TrezorOne' | 'TrezorT';

const DEVICE_ICONS: Record<DeviceType, string> = {
    'Coldcard': coldcardIcon,
    'Jade': jadeIcon,
    'Ledger': ledgerIcon,
    'BitBox02': bitboxIcon,
    'TrezorOne': trezorOneIcon,
    'TrezorT': trezorTIcon,
};
type Network = 'bitcoin' | 'testnet';

interface ConnectedDevice {
    client: Client;
    type: DeviceType;
    masterFingerprint: string;
    network: Network | null;
}

interface XpubResult {
    derivationPath: string;
    xpub: string;
}

type AddressFormat = 'legacy' | 'nested-segwit' | 'native-segwit' | 'taproot';
type AddressMode = 'by-type' | 'by-path' | 'by-descriptor';

const ADDRESS_FORMAT_PURPOSE: Record<AddressFormat, number> = {
    'legacy': 44,
    'nested-segwit': 49,
    'native-segwit': 84,
    'taproot': 86,
};

interface RegisterWalletResult {
    name: string;
    policy: string;
    status: 'complete' | 'pending_user_confirmation';
    hmac: string | null;
}

interface WalletRegistration {
    status: 'complete' | 'pending_user_confirmation';
    hmac: string | null;
}

interface AddressResult {
    derivationPath: string;
    address: string;
}

interface SignMessageResult {
    message: string;
    derivationPath: string;
    signature: string;
}

const isFirefox = navigator.userAgent.toLowerCase().includes('firefox');

const JADE_WALLET_NAME_REGEX = /^[A-Za-z0-9_]{1,16}$/;

const App = () => {
    const [device, setDevice] = useState<ConnectedDevice | null>(null);
    const [connecting, setConnecting] = useState<DeviceType | null>(null);
    const [selectedDevice, setSelectedDevice] = useState<DeviceType>('Coldcard');
    const [jadeNetwork, setJadeNetwork] = useState<Network>('bitcoin');
    const [trezorNetwork, setTrezorNetwork] = useState<Network>('bitcoin');
    const [trezorPassphrase, setTrezorPassphrase] = useState('');
    const [derivationPath, setDerivationPath] = useState("m/48'/0'/0'/2'");
    const [xpubResults, setXpubResults] = useState<XpubResult[]>([]);
    const [fetchingXpub, setFetchingXpub] = useState(false);
    const [addressMode, setAddressMode] = useState<AddressMode>('by-type');
    const [addressPath, setAddressPath] = useState("m/84'/0'/0'/0/0");
    const [addressFormat, setAddressFormat] = useState<AddressFormat>('native-segwit');
    const [addressIndex, setAddressIndex] = useState(0);
    const [descriptorName, setDescriptorName] = useState('');
    const [descriptorIndex, setDescriptorIndex] = useState(0);
    const [descriptorChange, setDescriptorChange] = useState(false);
    const [descriptorHmac, setDescriptorHmac] = useState('');
    const [descriptorPolicy, setDescriptorPolicy] = useState('');
    const [addressResults, setAddressResults] = useState<AddressResult[]>([]);
    const [fetchingAddress, setFetchingAddress] = useState(false);
    const [walletName, setWalletName] = useState('');
    const [walletPolicy, setWalletPolicy] = useState('');
    const [registerWalletResults, setRegisterWalletResults] = useState<RegisterWalletResult[]>([]);
    const [registeringWallet, setRegisteringWallet] = useState(false);
    const [psbtInput, setPsbtInput] = useState('');
    const [psbtPolicyName, setPsbtPolicyName] = useState('');
    const [psbtDescriptor, setPsbtDescriptor] = useState('');
    const [psbtHmac, setPsbtHmac] = useState('');
    const [psbtResults, setPsbtResults] = useState<string[]>([]);
    const [signingPsbt, setSigningPsbt] = useState(false);
    const [signMsgText, setSignMsgText] = useState('');
    const [signMsgPath, setSignMsgPath] = useState("m/84'/0'/0'/0/0");
    const [signMsgResults, setSignMsgResults] = useState<SignMessageResult[]>([]);
    const [signingMessage, setSigningMessage] = useState(false);
    const [processing, setProcessing] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [pairingCode, setPairingCode] = useState<string | null>(null);
    const [pinRequest, setPinRequest] = useState<{ client: Client; type: DeviceType; network?: Network } | null>(null);
    const [pinPositions, setPinPositions] = useState('');

    const showError = (message: string) => {
        setError(message);
        setTimeout(() => setError(null), 5000);
    };

    useEffect(() => {
        const initializeWasm = async () => {
            try {
                await initWasm();
                initialize_logging("debug");
            } catch (error) {
                console.error("Error initializing WASM:", error);
            }
        };
        initializeWasm();
    }, []);

    const errorMessage = (err: unknown, fallback: string): string =>
        err instanceof Error ? err.message : typeof err === 'string' ? err : fallback;

    const completeConnection = async (client: Client, type: DeviceType, network?: Network) => {
        await client.unlock(network ?? 'bitcoin');
        setPairingCode(null);

        if (type === 'TrezorOne') {
            const locked = await client.get_info()
                .then((info) => info.needsPinSent === true)
                .catch(() => false);
            if (locked) {
                await client.prompt_pin();
                setPinPositions('');
                setPinRequest({ client, type, network });
                return;
            }
        }

        const masterFingerprint = await client.get_master_fingerprint();

        let detectedNetwork: Network | null = null;
        if (type === 'Jade') {
            detectedNetwork = network ?? 'bitcoin';
        } else {
            try {
                const info = await client.get_info();
                const networks: string[] = info.networks ?? [];
                if (networks.includes('testnet')) {
                    detectedNetwork = 'testnet';
                } else if (networks.includes('bitcoin')) {
                    detectedNetwork = 'bitcoin';
                }
            } catch (err) {
                console.warn("Could not detect network from device:", err);
            }
        }

        const ct = detectedNetwork === 'testnet' ? 1 : 0;
        setDerivationPath(`m/48'/${ct}'/0'/2'`);
        setAddressPath(`m/84'/${ct}'/0'/0/0`);
        setSignMsgPath(`m/84'/${ct}'/0'/0/0`);
        setDevice({ client, type, masterFingerprint, network: detectedNetwork });
    };

    const submitPin = async () => {
        if (!pinRequest) return;
        const { client, type, network } = pinRequest;
        setProcessing(true);
        try {
            const accepted = await client.send_pin(pinPositions);
            setPinPositions('');
            if (!accepted) {
                showError('Device rejected the PIN');
                // The keypad is gone after a rejection; a second ack would always fail.
                await client.prompt_pin();
                return;
            }
            setPinRequest(null);
            await completeConnection(client, type, network);
        } catch (err) {
            setPinRequest(null);
            setPinPositions('');
            showError(errorMessage(err, 'Failed to send PIN'));
            console.error('Error sending PIN:', err);
        } finally {
            setProcessing(false);
        }
    };

    const connectDevice = async (type: DeviceType, network?: Network) => {
        if (processing) return;
        setConnecting(type);
        setProcessing(true);
        let client: Client | null = null;
        try {
            await initWasm();
            client = new Client();

            const onCloseCallback = () => {
                console.log('Device closed');
                setDevice(null);
            };

            const onPairingCodeCallback = (code: string) => {
                setPairingCode(code);
            };

            switch (type) {
                case 'Coldcard':
                    await client.connect_coldcard(onCloseCallback);
                    break;
                case 'Jade':
                    await client.connect_jade(network ?? 'bitcoin', onCloseCallback);
                    break;
                case 'Ledger':
                    await client.connect_ledger(onCloseCallback);
                    break;
                case 'BitBox02':
                    await client.connect_bitbox(network ?? 'bitcoin', onCloseCallback, onPairingCodeCallback);
                    break;
                case 'TrezorOne':
                    await client.connect_trezor_one(
                        network ?? 'bitcoin',
                        trezorPassphrase.length > 0 ? trezorPassphrase : undefined,
                        onCloseCallback,
                    );
                    break;
                case 'TrezorT':
                    await client.connect_trezor_t(network ?? 'bitcoin', onCloseCallback);
                    break;
            }

            await completeConnection(client, type, network);
        } catch (err) {
            showError(errorMessage(err, `Failed to connect to ${type}`));
            console.error(`Error connecting to ${type}:`, err);
        } finally {
            setConnecting(null);
            setProcessing(false);
            setPairingCode(null);
        }
    };

    const coinType = device?.network === 'testnet' ? 1 : 0;

    const getPathNetworkWarning = (path: string): string | null => {
        if (!device?.network) return null;
        const match = path.match(/^m\/\d+'\/(\d+)'/);
        if (!match) return null;
        const pathCoinType = parseInt(match[1]);
        if (device.network === 'bitcoin' && pathCoinType === 1) {
            return "Path uses testnet coin type (1') but device is on mainnet";
        }
        if (device.network === 'testnet' && pathCoinType === 0) {
            return "Path uses mainnet coin type (0') but device is on testnet";
        }
        return null;
    };

    const fetchAddress = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!device || processing) return;

        setFetchingAddress(true);
        setProcessing(true);
        let path: string;
        let format: string | undefined;
        if (addressMode === 'by-type') {
            const purpose = ADDRESS_FORMAT_PURPOSE[addressFormat];
            path = `m/${purpose}'/${coinType}'/0'/0/${addressIndex}`;
            format = addressFormat;
        } else {
            path = addressPath;
            format = undefined;
        }
        try {
            const address = await device.client.display_address_by_path(path, true, format);
            setAddressResults(prev => [{ derivationPath: path, address }, ...prev]);
        } catch (err) {
            const raw = err instanceof Error ? err.message : typeof err === 'string' ? err : "Failed to display address";
            const warning = getPathNetworkWarning(path);
            const message = warning && raw.includes("UnexpectedResult")
                ? `${warning}. Please check that your derivation path matches the device network.`
                : raw;
            showError(message);
            console.error("Error displaying address:", err);
        } finally {
            setFetchingAddress(false);
            setProcessing(false);
        }
    };

    const fetchAddressByDescriptor = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!device || processing) return;

        setFetchingAddress(true);
        setProcessing(true);
        try {
            const hmac = descriptorHmac.trim() || undefined;
            const policy = descriptorPolicy.trim() || undefined;
            const address = await device.client.display_address_by_descriptor(
                descriptorName,
                descriptorIndex,
                descriptorChange,
                true,
                hmac,
                policy,
            );
            const label = `${descriptorName} [${descriptorChange ? '1' : '0'}/${descriptorIndex}]`;
            setAddressResults(prev => [{ derivationPath: label, address }, ...prev]);
        } catch (err) {
            const message = err instanceof Error ? err.message : typeof err === 'string' ? err : "Failed to display address";
            showError(message);
            console.error("Error displaying address by descriptor:", err);
        } finally {
            setFetchingAddress(false);
            setProcessing(false);
        }
    };

    const walletNameInvalid = device?.type === 'Jade'
        && walletName.length > 0
        && !JADE_WALLET_NAME_REGEX.test(walletName);

    const registerWallet = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!device || processing) return;

        if (device.type === 'Jade' && !JADE_WALLET_NAME_REGEX.test(walletName)) {
            return;
        }

        setRegisteringWallet(true);
        setProcessing(true);
        try {
            const registration = await device.client.register_wallet(walletName, walletPolicy) as WalletRegistration;
            setRegisterWalletResults(prev => [{
                name: walletName,
                policy: walletPolicy,
                status: registration.status,
                hmac: registration.hmac,
            }, ...prev]);
        } catch (err) {
            const message = err instanceof Error ? err.message : typeof err === 'string' ? err : "Failed to register wallet";
            showError(message);
            console.error("Error registering wallet:", err);
        } finally {
            setRegisteringWallet(false);
            setProcessing(false);
        }
    };

    const signPsbt = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!device || processing) return;

        setSigningPsbt(true);
        setProcessing(true);
        try {
            const signed = await device.client.sign_psbt(
                psbtInput.trim(),
                psbtPolicyName.trim() || undefined,
                psbtDescriptor.trim() || undefined,
                psbtHmac.trim() || undefined,
            );
            setPsbtResults(prev => [signed, ...prev]);
        } catch (err) {
            const message = err instanceof Error ? err.message : typeof err === 'string' ? err : "Failed to sign PSBT";
            showError(message);
            console.error("Error signing PSBT:", err);
        } finally {
            setSigningPsbt(false);
            setProcessing(false);
        }
    };

    const signMessage = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!device || processing) return;

        setSigningMessage(true);
        setProcessing(true);
        try {
            const signature = await device.client.sign_message(signMsgText, signMsgPath);
            setSignMsgResults(prev => [{ message: signMsgText, derivationPath: signMsgPath, signature }, ...prev]);
        } catch (err) {
            const message = err instanceof Error ? err.message : typeof err === 'string' ? err : "Failed to sign message";
            showError(message);
            console.error("Error signing message:", err);
        } finally {
            setSigningMessage(false);
            setProcessing(false);
        }
    };

    const fetchXpub = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!device || processing) return;

        setFetchingXpub(true);
        setProcessing(true);
        try {
            const xpub = await device.client.get_extended_pubkey(derivationPath, false);
            setXpubResults(prev => [{ derivationPath, xpub }, ...prev]);
        } catch (err) {
            const message = err instanceof Error ? err.message : typeof err === 'string' ? err : "Failed to fetch xpub";
            showError(message);
            console.error("Error fetching xpub:", err);
        } finally {
            setFetchingXpub(false);
            setProcessing(false);
        }
    };

    return (
        <div className="min-h-screen bg-gray-900 text-white flex flex-col">
            {error && (
                <div className="fixed top-4 right-4 z-60 bg-red-900/90 border border-red-700 text-red-200 px-4 py-3 rounded-lg shadow-lg max-w-sm">
                    <div className="flex justify-between items-start gap-3">
                        <p className="text-sm">{error}</p>
                        <button
                            onClick={() => setError(null)}
                            className="text-red-400 hover:text-red-200"
                        >
                            ×
                        </button>
                    </div>
                </div>
            )}

            {pinRequest && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
                    <div className="bg-gray-800 border border-gray-700 rounded-lg shadow-xl px-8 py-6 max-w-sm text-center">
                        <div className="flex justify-center mb-4">
                            <img src={DEVICE_ICONS[pinRequest.type]} alt="" className="h-12 w-12 object-contain" />
                        </div>
                        <h2 className="text-lg font-semibold mb-2">Enter PIN</h2>
                        <p className="text-sm text-gray-400 mb-4">
                            Your device shows a scrambled keypad. Click the positions matching your PIN,
                            using the layout on the device screen, not the digits themselves.
                        </p>
                        <div className="grid grid-cols-3 gap-2 mb-4">
                            {[7, 8, 9, 4, 5, 6, 1, 2, 3].map((position) => (
                                <button
                                    key={position}
                                    onClick={() => setPinPositions(pinPositions + position)}
                                    className="bg-gray-900 hover:bg-gray-700 rounded-lg py-4 text-xl font-mono transition-colors"
                                >
                                    &bull;
                                </button>
                            ))}
                        </div>
                        <p className="font-mono text-xl tracking-widest bg-gray-900 rounded-lg px-4 py-2 mb-4 min-h-[2.5rem]">
                            {'*'.repeat(pinPositions.length)}
                        </p>
                        <div className="flex gap-2">
                            <button
                                onClick={() => setPinPositions(pinPositions.slice(0, -1))}
                                disabled={processing || pinPositions.length === 0}
                                className="flex-1 bg-gray-700 hover:bg-gray-600 disabled:opacity-50 rounded-lg px-4 py-2 text-sm transition-colors"
                            >
                                Delete
                            </button>
                            <button
                                onClick={() => { setPinRequest(null); setPinPositions(''); }}
                                disabled={processing}
                                className="flex-1 bg-gray-700 hover:bg-gray-600 disabled:opacity-50 rounded-lg px-4 py-2 text-sm transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={submitPin}
                                disabled={processing || pinPositions.length === 0}
                                className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded-lg px-4 py-2 text-sm font-medium transition-colors"
                            >
                                Unlock
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {pairingCode && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
                    <div className="bg-gray-800 border border-gray-700 rounded-lg shadow-xl px-8 py-6 max-w-sm text-center">
                        <div className="flex justify-center mb-4">
                            <img src={DEVICE_ICONS['BitBox02']} alt="" className="h-12 w-12 object-contain" />
                        </div>
                        <h2 className="text-lg font-semibold mb-2">Confirm pairing code</h2>
                        <p className="text-sm text-gray-400 mb-4">
                            Check that this code matches the one shown on your BitBox02, then confirm on the device.
                        </p>
                        <p className="font-mono text-2xl tracking-widest bg-gray-900 rounded-lg px-4 py-3">
                            {pairingCode}
                        </p>
                    </div>
                </div>
            )}

            <header className="border-b border-gray-800 px-6 py-4">
                <h1 className="text-2xl font-bold">BHWI</h1>
            </header>

            {isFirefox && (
                <div className="bg-amber-900/50 border-b border-amber-700 px-6 py-3 text-amber-200 text-sm">
                    Firefox does not support WebHID/WebSerial. Please use Chrome, Edge, or another Chromium-based browser.
                </div>
            )}

            <main className="flex-1 w-full max-w-2xl mx-auto px-6 py-12">
                {device ? (
                    <div className="w-full space-y-6">
                        <div className="bg-gray-800 rounded-lg p-6 shadow-lg">
                            <h2 className="text-lg font-semibold text-gray-400 mb-4">Connected Device</h2>
                            <div className="space-y-3">
                                <div className="flex justify-between items-center">
                                    <span className="text-gray-400">Type</span>
                                    <span className="flex items-center gap-2 font-medium">
                                        <img src={DEVICE_ICONS[device.type]} alt="" className="h-6 w-6 object-contain" />
                                        {device.type}
                                    </span>
                                </div>
                                <div className="flex justify-between">
                                    <span className="text-gray-400">Master Fingerprint</span>
                                    <span className="font-mono">{device.masterFingerprint}</span>
                                </div>
                                <div className="flex justify-between">
                                    <span className="text-gray-400">Network</span>
                                    <span className="font-medium">{device.network === 'testnet' ? 'Testnet' : device.network === 'bitcoin' ? 'Mainnet' : 'Unknown'}</span>
                                </div>
                            </div>
                        </div>

                        <details className="bg-gray-800 rounded-lg shadow-lg group">
                            <summary className="p-6 cursor-pointer list-none flex justify-between items-center">
                                <h2 className="text-lg font-semibold text-gray-400">Fetch Extended Public Key</h2>
                                <span className="text-gray-400 group-open:rotate-180 transition-transform">▼</span>
                            </summary>
                            <div className="px-6 pb-6">
                                <form onSubmit={fetchXpub}>
                                    <label htmlFor="derivation-path" className="block text-sm text-gray-400 mb-2">
                                        Derivation Path
                                    </label>
                                    <div className="flex gap-3">
                                        <input
                                            id="derivation-path"
                                            type="text"
                                            value={derivationPath}
                                            onChange={(e) => setDerivationPath(e.target.value)}
                                            placeholder="m/48'/0'/0'/2'"
                                            className="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 font-mono text-sm focus:outline-none focus:border-blue-500"
                                        />
                                        <button
                                            type="submit"
                                            disabled={processing}
                                            className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed px-6 py-2 rounded-lg font-medium transition-colors whitespace-nowrap"
                                        >
                                            {fetchingXpub ? 'Fetching...' : 'Fetch'}
                                        </button>
                                    </div>
                                </form>

                                {xpubResults.length > 0 && (
                                    <div className="mt-6 pt-6 border-t border-gray-700 space-y-4">
                                        {xpubResults.map((result, index) => (
                                            <div key={index} className="bg-gray-700/50 rounded-lg p-4">
                                                <div className="text-sm text-gray-400 mb-1">{result.derivationPath}</div>
                                                <div className="font-mono text-sm break-all">{result.xpub}</div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </details>

                        <details className="bg-gray-800 rounded-lg shadow-lg group">
                            <summary className="p-6 cursor-pointer list-none flex justify-between items-center">
                                <h2 className="text-lg font-semibold text-gray-400">Display Address</h2>
                                <span className="text-gray-400 group-open:rotate-180 transition-transform">▼</span>
                            </summary>
                            <div className="px-6 pb-6">
                                <div className="flex gap-2 mb-4">
                                    <button
                                        type="button"
                                        onClick={() => setAddressMode('by-type')}
                                        className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-colors ${addressMode === 'by-type' ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-400 hover:bg-gray-600'}`}
                                    >
                                        By Type
                                    </button>
                                    <button
                                        type="button"
                                        onClick={() => setAddressMode('by-path')}
                                        className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-colors ${addressMode === 'by-path' ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-400 hover:bg-gray-600'}`}
                                    >
                                        By Path
                                    </button>
                                    <button
                                        type="button"
                                        onClick={() => setAddressMode('by-descriptor')}
                                        className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-colors ${addressMode === 'by-descriptor' ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-400 hover:bg-gray-600'}`}
                                    >
                                        By Descriptor
                                    </button>
                                </div>

                                {addressMode === 'by-descriptor' ? (
                                    <form onSubmit={fetchAddressByDescriptor}>
                                        <label htmlFor="descriptor-name" className="block text-sm text-gray-400 mb-2">
                                            Descriptor Name
                                        </label>
                                        <input
                                            id="descriptor-name"
                                            type="text"
                                            value={descriptorName}
                                            onChange={(e) => setDescriptorName(e.target.value)}
                                            placeholder="My Wallet"
                                            className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-sm focus:outline-none focus:border-blue-500 mb-4"
                                        />
                                        <div className="flex gap-4 mb-4">
                                            <div className="flex-1">
                                                <label htmlFor="descriptor-index" className="block text-sm text-gray-400 mb-2">
                                                    Index
                                                </label>
                                                <input
                                                    id="descriptor-index"
                                                    type="number"
                                                    min={0}
                                                    value={descriptorIndex}
                                                    onChange={(e) => setDescriptorIndex(parseInt(e.target.value) || 0)}
                                                    className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 font-mono text-sm focus:outline-none focus:border-blue-500"
                                                />
                                            </div>
                                            <div className="flex items-end pb-2">
                                                <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer">
                                                    <input
                                                        type="checkbox"
                                                        checked={descriptorChange}
                                                        onChange={(e) => setDescriptorChange(e.target.checked)}
                                                        className="w-4 h-4 accent-blue-600"
                                                    />
                                                    Change
                                                </label>
                                            </div>
                                        </div>
                                        <label htmlFor="descriptor-hmac" className="block text-sm text-gray-400 mb-2">
                                            Wallet HMAC (hex, Ledger only)
                                        </label>
                                        <input
                                            id="descriptor-hmac"
                                            type="text"
                                            value={descriptorHmac}
                                            onChange={(e) => setDescriptorHmac(e.target.value)}
                                            placeholder="Optional — 64 hex characters"
                                            className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 font-mono text-sm focus:outline-none focus:border-blue-500 mb-4"
                                        />
                                        <label htmlFor="descriptor-policy" className="block text-sm text-gray-400 mb-2">
                                            Wallet Descriptor (Ledger only)
                                        </label>
                                        <textarea
                                            id="descriptor-policy"
                                            value={descriptorPolicy}
                                            onChange={(e) => setDescriptorPolicy(e.target.value)}
                                            placeholder="Optional — e.g. wsh(sortedmulti(2,@0/**,@1/**))"
                                            rows={2}
                                            className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 font-mono text-sm focus:outline-none focus:border-blue-500 mb-4"
                                        />
                                        <button
                                            type="submit"
                                            disabled={processing}
                                            className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed px-6 py-2 rounded-lg font-medium transition-colors"
                                        >
                                            {fetchingAddress ? 'Displaying...' : 'Display'}
                                        </button>
                                    </form>
                                ) : (
                                    <form onSubmit={fetchAddress}>
                                        {addressMode === 'by-type' ? (
                                            <>
                                                <label htmlFor="address-format" className="block text-sm text-gray-400 mb-2">
                                                    Address Type
                                                </label>
                                                <select
                                                    id="address-format"
                                                    value={addressFormat}
                                                    onChange={(e) => setAddressFormat(e.target.value as AddressFormat)}
                                                    className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-sm focus:outline-none focus:border-blue-500 mb-4"
                                                >
                                                    <option value="legacy">Legacy (P2PKH) — m/44'/{coinType}'/0'/0/i</option>
                                                    <option value="nested-segwit">Nested SegWit (P2SH-P2WPKH) — m/49'/{coinType}'/0'/0/i</option>
                                                    <option value="native-segwit">Native SegWit (P2WPKH) — m/84'/{coinType}'/0'/0/i</option>
                                                    <option value="taproot">Taproot (P2TR) — m/86'/{coinType}'/0'/0/i</option>
                                                </select>
                                                <label htmlFor="address-index" className="block text-sm text-gray-400 mb-2">
                                                    Index
                                                </label>
                                                <input
                                                    id="address-index"
                                                    type="number"
                                                    min={0}
                                                    value={addressIndex}
                                                    onChange={(e) => setAddressIndex(parseInt(e.target.value) || 0)}
                                                    className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 font-mono text-sm focus:outline-none focus:border-blue-500 mb-4"
                                                />
                                            </>
                                        ) : (
                                            <>
                                                <label htmlFor="address-path" className="block text-sm text-gray-400 mb-2">
                                                    Derivation Path
                                                </label>
                                                <input
                                                    id="address-path"
                                                    type="text"
                                                    value={addressPath}
                                                    onChange={(e) => setAddressPath(e.target.value)}
                                                    placeholder="m/84'/0'/0'/0/0"
                                                    className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 font-mono text-sm focus:outline-none focus:border-blue-500 mb-1"
                                                />
                                                {getPathNetworkWarning(addressPath) && (
                                                    <p className="text-amber-400 text-xs mb-3">{getPathNetworkWarning(addressPath)}</p>
                                                )}
                                                {!getPathNetworkWarning(addressPath) && <div className="mb-3" />}
                                            </>
                                        )}
                                        <button
                                            type="submit"
                                            disabled={processing}
                                            className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed px-6 py-2 rounded-lg font-medium transition-colors"
                                        >
                                            {fetchingAddress ? 'Displaying...' : 'Display'}
                                        </button>
                                    </form>
                                )}

                                {addressResults.length > 0 && (
                                    <div className="mt-6 pt-6 border-t border-gray-700 space-y-4">
                                        {addressResults.map((result, index) => (
                                            <div key={index} className="bg-gray-700/50 rounded-lg p-4">
                                                <div className="text-sm text-gray-400 mb-1">{result.derivationPath}</div>
                                                <div className="font-mono text-sm break-all">{result.address}</div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </details>

                        <details className="bg-gray-800 rounded-lg shadow-lg group">
                            <summary className="p-6 cursor-pointer list-none flex justify-between items-center">
                                <h2 className="text-lg font-semibold text-gray-400">Register Wallet</h2>
                                <span className="text-gray-400 group-open:rotate-180 transition-transform">▼</span>
                            </summary>
                            <div className="px-6 pb-6">
                                <form onSubmit={registerWallet}>
                                    <label htmlFor="wallet-name" className="block text-sm text-gray-400 mb-2">
                                        Wallet Name
                                    </label>
                                    <input
                                        id="wallet-name"
                                        type="text"
                                        required
                                        value={walletName}
                                        onChange={(e) => setWalletName(e.target.value)}
                                        placeholder={device.type === 'Jade' ? 'My_Wallet' : 'My Wallet'}
                                        className={`w-full bg-gray-700 border rounded-lg px-4 py-2 text-sm focus:outline-none mb-4 ${walletNameInvalid ? 'border-red-500 focus:border-red-500' : 'border-gray-600 focus:border-blue-500'}`}
                                    />
                                    {walletNameInvalid ? (
                                        <p className="text-xs text-red-400 -mt-2 mb-4">
                                            Jade wallet names must be 1-16 characters, using only letters, digits and underscores (no spaces)
                                        </p>
                                    ) : device.type === 'Jade' && (
                                        <p className="text-xs text-gray-500 -mt-2 mb-4">
                                            Jade: 1-16 characters, letters, digits and underscores only
                                        </p>
                                    )}
                                    <label htmlFor="wallet-policy" className="block text-sm text-gray-400 mb-2">
                                        Wallet Descriptor
                                    </label>
                                    <textarea
                                        id="wallet-policy"
                                        value={walletPolicy}
                                        onChange={(e) => setWalletPolicy(e.target.value)}
                                        placeholder="wsh(sortedmulti(2,@0/**,@1/**))"
                                        rows={3}
                                        className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 font-mono text-sm focus:outline-none focus:border-blue-500 mb-4"
                                    />
                                    <button
                                        type="submit"
                                        disabled={processing || walletNameInvalid}
                                        className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed px-6 py-2 rounded-lg font-medium transition-colors"
                                    >
                                        {registeringWallet ? 'Registering...' : 'Register'}
                                    </button>
                                </form>

                                {registerWalletResults.length > 0 && (
                                    <div className="mt-6 pt-6 border-t border-gray-700 space-y-4">
                                        {registerWalletResults.map((result, index) => (
                                            <div key={index} className="bg-gray-700/50 rounded-lg p-4">
                                                <div className="text-sm text-gray-400 mb-1">{result.name}</div>
                                                <div className="font-mono text-sm break-all mb-1">{result.policy}</div>
                                                {result.status === 'pending_user_confirmation' && (
                                                    <div className="text-sm text-amber-300">Pending device confirmation</div>
                                                )}
                                                {result.hmac && (
                                                    <div className="text-sm">
                                                        <span className="text-gray-400">HMAC: </span>
                                                        <span className="font-mono text-sm break-all">{result.hmac}</span>
                                                    </div>
                                                )}
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </details>

                        <details className="bg-gray-800 rounded-lg shadow-lg group">
                            <summary className="p-6 cursor-pointer list-none flex justify-between items-center">
                                <h2 className="text-lg font-semibold text-gray-400">Sign PSBT</h2>
                                <span className="text-gray-400 group-open:rotate-180 transition-transform">▼</span>
                            </summary>
                            <div className="px-6 pb-6">
                                <form onSubmit={signPsbt}>
                                    <label htmlFor="psbt-input" className="block text-sm text-gray-400 mb-2">
                                        PSBT (base64)
                                    </label>
                                    <textarea
                                        id="psbt-input"
                                        value={psbtInput}
                                        onChange={(e) => setPsbtInput(e.target.value)}
                                        placeholder="cHNidP8B..."
                                        rows={4}
                                        className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 font-mono text-sm focus:outline-none focus:border-blue-500 mb-4"
                                    />
                                    {device.type === 'Ledger' && (
                                        <>
                                            <label htmlFor="psbt-policy-name" className="block text-sm text-gray-400 mb-2">
                                                Policy Name (registered wallets only)
                                            </label>
                                            <input
                                                id="psbt-policy-name"
                                                type="text"
                                                value={psbtPolicyName}
                                                onChange={(e) => setPsbtPolicyName(e.target.value)}
                                                placeholder="Optional — name used at registration"
                                                className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-sm focus:outline-none focus:border-blue-500 mb-4"
                                            />
                                            <label htmlFor="psbt-hmac" className="block text-sm text-gray-400 mb-2">
                                                Wallet HMAC (hex)
                                            </label>
                                            <input
                                                id="psbt-hmac"
                                                type="text"
                                                value={psbtHmac}
                                                onChange={(e) => setPsbtHmac(e.target.value)}
                                                placeholder="Optional — 64 hex characters"
                                                className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 font-mono text-sm focus:outline-none focus:border-blue-500 mb-4"
                                            />
                                        </>
                                    )}
                                    {(device.type === 'Ledger' || device.type === 'BitBox02') && (
                                        <>
                                            <label htmlFor="psbt-descriptor" className="block text-sm text-gray-400 mb-2">
                                                Wallet Descriptor {device.type === 'BitBox02' ? '(for multisig/policy signing)' : '(registered wallets only)'}
                                            </label>
                                            <textarea
                                                id="psbt-descriptor"
                                                value={psbtDescriptor}
                                                onChange={(e) => setPsbtDescriptor(e.target.value)}
                                                placeholder="Optional — e.g. wsh(sortedmulti(2,@0/**,@1/**))"
                                                rows={2}
                                                className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 font-mono text-sm focus:outline-none focus:border-blue-500 mb-4"
                                            />
                                        </>
                                    )}
                                    <button
                                        type="submit"
                                        disabled={processing}
                                        className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed px-6 py-2 rounded-lg font-medium transition-colors"
                                    >
                                        {signingPsbt ? 'Signing...' : 'Sign'}
                                    </button>
                                </form>

                                {psbtResults.length > 0 && (
                                    <div className="mt-6 pt-6 border-t border-gray-700 space-y-4">
                                        {psbtResults.map((result, index) => (
                                            <div key={index} className="bg-gray-700/50 rounded-lg p-4">
                                                <div className="text-sm text-gray-400 mb-1">Signed PSBT</div>
                                                <div className="font-mono text-sm break-all">{result}</div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </details>

                        <details className="bg-gray-800 rounded-lg shadow-lg group">
                            <summary className="p-6 cursor-pointer list-none flex justify-between items-center">
                                <h2 className="text-lg font-semibold text-gray-400">Sign Message</h2>
                                <span className="text-gray-400 group-open:rotate-180 transition-transform">▼</span>
                            </summary>
                            <div className="px-6 pb-6">
                                <form onSubmit={signMessage}>
                                    <label htmlFor="sign-message-text" className="block text-sm text-gray-400 mb-2">
                                        Message
                                    </label>
                                    <input
                                        id="sign-message-text"
                                        type="text"
                                        value={signMsgText}
                                        onChange={(e) => setSignMsgText(e.target.value)}
                                        placeholder="Hello world"
                                        className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-sm focus:outline-none focus:border-blue-500 mb-4"
                                    />
                                    <label htmlFor="sign-message-path" className="block text-sm text-gray-400 mb-2">
                                        Derivation Path
                                    </label>
                                    <input
                                        id="sign-message-path"
                                        type="text"
                                        value={signMsgPath}
                                        onChange={(e) => setSignMsgPath(e.target.value)}
                                        placeholder="m/84'/0'/0'/0/0"
                                        className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 font-mono text-sm focus:outline-none focus:border-blue-500 mb-1"
                                    />
                                    {getPathNetworkWarning(signMsgPath) && (
                                        <p className="text-amber-400 text-xs mb-3">{getPathNetworkWarning(signMsgPath)}</p>
                                    )}
                                    {!getPathNetworkWarning(signMsgPath) && <div className="mb-3" />}
                                    <button
                                        type="submit"
                                        disabled={processing}
                                        className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed px-6 py-2 rounded-lg font-medium transition-colors"
                                    >
                                        {signingMessage ? 'Signing...' : 'Sign'}
                                    </button>
                                </form>

                                {signMsgResults.length > 0 && (
                                    <div className="mt-6 pt-6 border-t border-gray-700 space-y-4">
                                        {signMsgResults.map((result, index) => (
                                            <div key={index} className="bg-gray-700/50 rounded-lg p-4">
                                                <div className="text-sm text-gray-400 mb-1">{result.message} — {result.derivationPath}</div>
                                                <div className="font-mono text-sm break-all">{result.signature}</div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </details>
                    </div>
                ) : (
                    <div>
                        <h2 className="text-xl text-gray-400 mb-6">Select your device</h2>
                        <div className="flex flex-col gap-3 mb-6">
                            <label className="flex items-center gap-3 bg-gray-800 px-6 py-3 rounded-lg cursor-pointer hover:bg-gray-700 transition-colors">
                                <input
                                    type="radio"
                                    name="device"
                                    checked={selectedDevice === 'Coldcard'}
                                    onChange={() => setSelectedDevice('Coldcard')}
                                    className="w-4 h-4 accent-blue-600"
                                />
                                <img src={DEVICE_ICONS['Coldcard']} alt="" className="h-10 w-10 object-contain" />
                                <span className="font-medium">Coldcard</span>
                            </label>

                            <label className="flex items-center gap-3 bg-gray-800 px-6 py-3 rounded-lg cursor-pointer hover:bg-gray-700 transition-colors">
                                <input
                                    type="radio"
                                    name="device"
                                    checked={selectedDevice === 'Jade'}
                                    onChange={() => setSelectedDevice('Jade')}
                                    className="w-4 h-4 accent-blue-600"
                                />
                                <img src={DEVICE_ICONS['Jade']} alt="" className="h-10 w-10 object-contain" />
                                <span className="font-medium">Jade</span>
                                <select
                                    value={jadeNetwork}
                                    onChange={(e) => {
                                        setJadeNetwork(e.target.value as Network);
                                        setSelectedDevice('Jade');
                                    }}
                                    onClick={(e) => e.stopPropagation()}
                                    className="ml-auto bg-gray-700 border border-gray-600 rounded-lg px-3 py-1 text-sm focus:outline-none focus:border-blue-500"
                                >
                                    <option value="bitcoin">Mainnet</option>
                                    <option value="testnet">Testnet</option>
                                </select>
                            </label>

                            <label className="flex items-center gap-3 bg-gray-800 px-6 py-3 rounded-lg cursor-pointer hover:bg-gray-700 transition-colors">
                                <input
                                    type="radio"
                                    name="device"
                                    checked={selectedDevice === 'Ledger'}
                                    onChange={() => setSelectedDevice('Ledger')}
                                    className="w-4 h-4 accent-blue-600"
                                />
                                <img src={DEVICE_ICONS['Ledger']} alt="" className="h-10 w-10 object-contain" />
                                <span className="font-medium">Ledger</span>
                            </label>

                            <label className="flex items-center gap-3 bg-gray-800 px-6 py-3 rounded-lg cursor-pointer hover:bg-gray-700 transition-colors">
                                <input
                                    type="radio"
                                    name="device"
                                    checked={selectedDevice === 'BitBox02'}
                                    onChange={() => setSelectedDevice('BitBox02')}
                                    className="w-4 h-4 accent-blue-600"
                                />
                                <img src={DEVICE_ICONS['BitBox02']} alt="" className="h-10 w-10 object-contain" />
                                <span className="font-medium">BitBox02</span>
                            </label>

                            <label className="flex items-center gap-3 bg-gray-800 px-6 py-3 rounded-lg cursor-pointer hover:bg-gray-700 transition-colors">
                                <input
                                    type="radio"
                                    name="device"
                                    checked={selectedDevice === 'TrezorOne'}
                                    onChange={() => setSelectedDevice('TrezorOne')}
                                    className="w-4 h-4 accent-blue-600"
                                />
                                <img src={DEVICE_ICONS['TrezorOne']} alt="" className="h-10 w-10 object-contain" />
                                <span className="font-medium">Trezor One</span>
                                <input
                                    type="password"
                                    value={trezorPassphrase}
                                    placeholder="Passphrase (optional)"
                                    autoComplete="off"
                                    onChange={(e) => {
                                        setTrezorPassphrase(e.target.value);
                                        setSelectedDevice('TrezorOne');
                                    }}
                                    onClick={(e) => e.stopPropagation()}
                                    className="ml-auto w-44 bg-gray-700 border border-gray-600 rounded-lg px-3 py-1 text-sm focus:outline-none focus:border-blue-500"
                                />
                                <select
                                    value={trezorNetwork}
                                    onChange={(e) => {
                                        setTrezorNetwork(e.target.value as Network);
                                        setSelectedDevice('TrezorOne');
                                    }}
                                    onClick={(e) => e.stopPropagation()}
                                    className="bg-gray-700 border border-gray-600 rounded-lg px-3 py-1 text-sm focus:outline-none focus:border-blue-500"
                                >
                                    <option value="bitcoin">Mainnet</option>
                                    <option value="testnet">Testnet</option>
                                </select>
                            </label>

                            <label className="flex items-center gap-3 bg-gray-800 px-6 py-3 rounded-lg cursor-pointer hover:bg-gray-700 transition-colors">
                                <input
                                    type="radio"
                                    name="device"
                                    checked={selectedDevice === 'TrezorT'}
                                    onChange={() => setSelectedDevice('TrezorT')}
                                    className="w-4 h-4 accent-blue-600"
                                />
                                <img src={DEVICE_ICONS['TrezorT']} alt="" className="h-10 w-10 object-contain" />
                                <span className="font-medium">Trezor Model T</span>
                                <select
                                    value={trezorNetwork}
                                    onChange={(e) => {
                                        setTrezorNetwork(e.target.value as Network);
                                        setSelectedDevice('TrezorT');
                                    }}
                                    onClick={(e) => e.stopPropagation()}
                                    className="ml-auto bg-gray-700 border border-gray-600 rounded-lg px-3 py-1 text-sm focus:outline-none focus:border-blue-500"
                                >
                                    <option value="bitcoin">Mainnet</option>
                                    <option value="testnet">Testnet</option>
                                </select>
                            </label>
                        </div>

                        <button
                            onClick={() => connectDevice(
                                selectedDevice,
                                selectedDevice === 'Jade'
                                    ? jadeNetwork
                                    : selectedDevice === 'TrezorOne' || selectedDevice === 'TrezorT'
                                        ? trezorNetwork
                                        : undefined,
                            )}
                            disabled={processing}
                            className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed px-6 py-3 rounded-lg font-medium transition-colors"
                        >
                            {connecting ? `Connecting to ${connecting}...` : 'Connect'}
                        </button>
                    </div>
                )}
            </main>

            <footer className="border-t border-gray-800 px-6 py-4 text-center text-sm text-gray-500">
                © 2026 Wizardsardine LDA
            </footer>
        </div>
    );
};

export default App;
