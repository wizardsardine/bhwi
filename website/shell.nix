let
   pkgs = import <nixpkgs> {};
in
pkgs.mkShell rec {
  buildInputs = with pkgs; [
    pkgs.binaryen # This includes wasm-opt
    pkgs.just
    pkgs.nodejs
    pkgs.wasm-pack
  ];
}
