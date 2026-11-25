#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
JAVELIN_OPENCODE_DIR="${PROJECT_ROOT}/third_party/Javelin/.opencode"
BUILD_DIR="${PROJECT_ROOT}/.build/javelin-runtime-deps"
TARGET_DIR="${PROJECT_ROOT}/javelin_runtime_deps"

if [[ ! -f "${JAVELIN_OPENCODE_DIR}/package.json" || ! -f "${JAVELIN_OPENCODE_DIR}/package-lock.json" ]]; then
  echo "[prepare_javelin_runtime_deps] Missing ${JAVELIN_OPENCODE_DIR}/package.json or package-lock.json" >&2
  exit 1
fi

rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
cp "${JAVELIN_OPENCODE_DIR}/package.json" "${BUILD_DIR}/package.json"
cp "${JAVELIN_OPENCODE_DIR}/package-lock.json" "${BUILD_DIR}/package-lock.json"

npm --prefix "${BUILD_DIR}" ci --omit=dev --no-audit --no-fund --ignore-scripts

rm -rf "${TARGET_DIR}"
mkdir -p "${TARGET_DIR}"
cp "${BUILD_DIR}/package.json" "${TARGET_DIR}/package.json"
cp "${BUILD_DIR}/package-lock.json" "${TARGET_DIR}/package-lock.json"
mv "${BUILD_DIR}/node_modules" "${TARGET_DIR}/node_modules"
rm -rf "${BUILD_DIR}"

echo "[prepare_javelin_runtime_deps] Prepared ${TARGET_DIR}/node_modules cleanly."
