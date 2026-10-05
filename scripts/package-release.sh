#!/usr/bin/env bash
set -euo pipefail

# Determine script and project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_DIR}"

VERSION="$(grep -m1 '^version' Cargo.toml | awk -F '"' '{print $2}')"
ARCH="$(uname -m)"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
PACKAGE_NAME="redsocks-rs-v${VERSION}-${OS}-${ARCH}"
DIST_DIR="${PROJECT_DIR}/dist"
STAGE_DIR="${DIST_DIR}/${PACKAGE_NAME}"

echo "===> Building redsocks-rs v${VERSION} (${OS}-${ARCH}) in release mode..."
cargo build --release --locked

echo "===> Preparing release staging directory: ${STAGE_DIR}"
rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}"

cp target/release/redsocks "${STAGE_DIR}/redsocks"
ln -sf redsocks "${STAGE_DIR}/redsocks-rs"
cp redsocks.conf.example "${STAGE_DIR}/redsocks.conf.example"
cp redsocks.service "${STAGE_DIR}/redsocks.service"
cp README.md "${STAGE_DIR}/README.md"
cp LICENSE "${STAGE_DIR}/LICENSE"

echo "===> Creating release tarball: ${DIST_DIR}/${PACKAGE_NAME}.tar.gz"
tar -czvf "${DIST_DIR}/${PACKAGE_NAME}.tar.gz" -C "${DIST_DIR}" "${PACKAGE_NAME}"

echo "===> Generating SHA256 checksum..."
(cd "${DIST_DIR}" && sha256sum "${PACKAGE_NAME}.tar.gz" > "${PACKAGE_NAME}.tar.gz.sha256")

echo "===> Packaging complete:"
ls -lh "${DIST_DIR}/${PACKAGE_NAME}.tar.gz"*
cat "${DIST_DIR}/${PACKAGE_NAME}.tar.gz.sha256"
