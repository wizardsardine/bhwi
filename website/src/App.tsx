import { useEffect, useState } from 'react'
import initWasm, { initialize_logging, Client } from 'bhwi-wasm';

type DeviceType = 'Coldcard' | 'Jade' | 'Ledger';
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
type AddressMode = 'by-type' | 'by-path';

const ADDRESS_FORMAT_PURPOSE: Record<AddressFormat, number> = {
    'legacy': 44,
    'nested-segwit': 49,
    'native-segwit': 84,
    'taproot': 86,
};

interface AddressResult {
    derivationPath: string;
    address: string;
}

const isFirefox = navigator.userAgent.toLowerCase().includes('firefox');

const App = () => {
    const [device, setDevice] = useState<ConnectedDevice | null>(null);
    const [connecting, setConnecting] = useState<DeviceType | null>(null);
    const [selectedDevice, setSelectedDevice] = useState<DeviceType>('Coldcard');
    const [jadeNetwork, setJadeNetwork] = useState<Network>('bitcoin');
    const [derivationPath, setDerivationPath] = useState("m/48'/0'/0'/2'");
    const [xpubResults, setXpubResults] = useState<XpubResult[]>([]);
    const [fetchingXpub, setFetchingXpub] = useState(false);
    const [addressMode, setAddressMode] = useState<AddressMode>('by-type');
    const [addressPath, setAddressPath] = useState("m/84'/0'/0'/0/0");
    const [addressFormat, setAddressFormat] = useState<AddressFormat>('native-segwit');
    const [addressIndex, setAddressIndex] = useState(0);
    const [addressResults, setAddressResults] = useState<AddressResult[]>([]);
    const [fetchingAddress, setFetchingAddress] = useState(false);
    const [processing, setProcessing] = useState(false);
    const [error, setError] = useState<string | null>(null);

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

    const connectDevice = async (type: DeviceType, network?: Network) => {
        if (processing) return;
        setConnecting(type);
        setProcessing(true);
        try {
            await initWasm();
            const client = new Client();

            const onCloseCallback = () => {
                console.log('Device closed');
                setDevice(null);
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
            }

            await client.unlock(network ?? 'bitcoin');
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
            setDevice({ client, type, masterFingerprint, network: detectedNetwork });
        } catch (err) {
            const message = err instanceof Error ? err.message : typeof err === 'string' ? err : `Failed to connect to ${type}`;
            showError(message);
            console.error(`Error connecting to ${type}:`, err);
        } finally {
            setConnecting(null);
            setProcessing(false);
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
                <div className="fixed top-4 right-4 bg-red-900/90 border border-red-700 text-red-200 px-4 py-3 rounded-lg shadow-lg max-w-sm">
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
                                <div className="flex justify-between">
                                    <span className="text-gray-400">Type</span>
                                    <span className="font-medium">{device.type}</span>
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
                                </div>

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
                                <span className="font-medium">Ledger</span>
                            </label>
                        </div>

                        <button
                            onClick={() => connectDevice(selectedDevice, selectedDevice === 'Jade' ? jadeNetwork : undefined)}
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
