import React, { useEffect, useState } from 'react'
import './App.css'

// Assuming the generated pkg folder is under src/pkg
import initWasm, { initialize_logging, Client } from 'bhwi-wasm';

const App: React.FC = () => {
    const [device, setDevice] = useState<Client | undefined>(undefined);
    // const [productId] = useState(0xcc10); // Product ID in hex

    useEffect(() => {
        // Initialize the WASM module
        const initializeWasm = async () => {
            try {
                await initWasm(); // Initialize the WebAssembly module
                initialize_logging("debug");
            } catch (error) {
                console.error("Error initializing WASM:", error);
            }
        };

        initializeWasm();
    }, []);

    const requestDevice = async () => {
        try {
            await initWasm();

            let client = new Client();

            const retryCallback = async () => {
                console.log('retrying');
                client = new Client();
                await client.connect_ledger(() => {
                    console.log('Failed to retry');
                });

                const masterFingerprint = await client.get_master_fingerprint();
                console.log("Master Fingerprint:", masterFingerprint);

                setDevice(client);
            };


            await client.connect_ledger(retryCallback);
            await client.unlock("testnet");

            // Log the master fingerprint
            const masterFingerprint = await client.get_master_fingerprint();
            console.log("Master Fingerprint:", masterFingerprint);

            const xpub = await client.get_extended_pubkey("m/48'/1'/0'/2'", false);
            console.log("xpub:", xpub);

            setDevice(client);
        } catch (error) {
            console.error("Error opening WebHID device:", error);
        }
    };

    const requestJade = async () => {
        try {
            await initWasm(); // Initialize the WebAssembly module

            const onCloseCallback = () => {
                console.log('Device closed');
            };


            const client = new Client(); // Create instance synchronously
            await client.connect_jade("testnet", onCloseCallback); // Connect asynchronously

            await client.unlock("testnet");

            // Log the master fingerprint
            const masterFingerprint = await client.get_master_fingerprint();
            console.log("Master Fingerprint:", masterFingerprint);

            const xpub = await client.get_extended_pubkey("m/48'/1'/0'/2'", false);
            console.log("xpub:", xpub);

            setDevice(client);
        } catch (error) {
            console.error("Error opening WebSerial device:", error);
        }
    };

    return (
        <div>
            <h1>WASM WebHID Device</h1>
            <button onClick={requestDevice}>Request HID Device</button>
            <button onClick={requestJade}>Request Jade Device</button>
            {device ? <p>Device connected !</p> : <p>No device connected</p>}
        </div>
    );
};

export default App
