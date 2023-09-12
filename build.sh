#!/bin/bash
set -e

cd astra
cargo build --target wasm32-unknown-unknown --release
cd ..
cargo build --target wasm32-unknown-unknown --release
mkdir -p res
cp target/wasm32-unknown-unknown/release/*.wasm ./res/
