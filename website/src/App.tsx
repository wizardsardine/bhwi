import React, { useEffect, useState } from 'react'
import './App.css'

// Assuming the generated pkg folder is under src/pkg
import initWasm, { initialize_logging, connect_ledger } from 'bhwi-wasm';

const App: React.FC = () => {
    const [device, setDevice] = useState<boolean | undefined>(undefined);
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
            await initWasm(); // Initialize the WebAssembly module

            const onCloseCallback = () => {
                console.log('Device closed');
            };

            await connect_ledger(
                onCloseCallback // on_close_cb
            );

            setDevice(true);
        } catch (error) {
            console.error("Error opening WebHID device:", error);
        }
    };

    return (
        <div>
            <h1>WASM WebHID Device</h1>
            <button onClick={requestDevice}>Request HID Device</button>
            {device ? <p>Device connected !</p> : <p>No device connected</p>}
        </div>
    );
};

export default App
