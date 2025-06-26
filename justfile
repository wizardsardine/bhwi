website: install-website
    cd website && npm run dev

install-website: build-website
    cd website && npm install

build-website:
    wasm-pack build bhwi-wasm --out-dir ../website/pkg --target web
