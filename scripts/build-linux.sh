#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --workspace
cargo build -p ghostchat-app --release
TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
cargo run -q -p ghostchat-xtask -- dist "$TARGET_DIR/release/ghostchat" dist/linux
chmod +x dist/linux/ghostchat
ls -l dist/linux
echo "Portable binary: dist/linux/ghostchat (verify: cd dist/linux && sha256sum -c ghostchat.sha256)"
