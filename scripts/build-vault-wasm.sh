#!/bin/sh
# Rebuilds bolt-vault for the explorer's compute page (crates/node/src/explorer/vault/).
# Needs the wasm32-unknown-unknown target and wasm-bindgen-cli at the version in Cargo.lock.
set -e
cd "$(dirname "$0")/.."
cargo build -p bolt-vault --release --target wasm32-unknown-unknown --features wasm
wasm-bindgen --target web --no-typescript --out-dir crates/node/src/explorer/vault \
  target/wasm32-unknown-unknown/release/bolt_vault.wasm
ls -l crates/node/src/explorer/vault
