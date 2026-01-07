#!/bin/bash
# KyubiSweep Build Script - Cross-platform compilation

set -e

APP_NAME="kyubisweep"
VERSION="1.0.0"
BUILD_DIR="./build"
MAIN_PATH="./cmd/sweep/main.go"

# Find go binary
GO_BIN=$(which go 2>/dev/null || echo "/usr/local/go/bin/go")

mkdir -p "$BUILD_DIR"

echo "🦊 KyubiSweep Build Script v${VERSION}"
echo "========================================"
echo ""

# macOS builds
echo "🍎 Building for macOS..."
echo "   → macOS ARM64 (Apple Silicon)..."
GOOS=darwin GOARCH=arm64 $GO_BIN build -ldflags="-s -w" -o "${BUILD_DIR}/${APP_NAME}-darwin-arm64" "${MAIN_PATH}"
echo "   → macOS AMD64 (Intel)..."
GOOS=darwin GOARCH=amd64 $GO_BIN build -ldflags="-s -w" -o "${BUILD_DIR}/${APP_NAME}-darwin-amd64" "${MAIN_PATH}"

# Linux builds
echo "🐧 Building for Linux..."
echo "   → Linux AMD64..."
GOOS=linux GOARCH=amd64 $GO_BIN build -ldflags="-s -w" -o "${BUILD_DIR}/${APP_NAME}-linux-amd64" "${MAIN_PATH}"
echo "   → Linux ARM64..."
GOOS=linux GOARCH=arm64 $GO_BIN build -ldflags="-s -w" -o "${BUILD_DIR}/${APP_NAME}-linux-arm64" "${MAIN_PATH}"

# Windows builds
echo "🪟 Building for Windows..."
echo "   → Windows AMD64..."
GOOS=windows GOARCH=amd64 $GO_BIN build -ldflags="-s -w" -o "${BUILD_DIR}/${APP_NAME}-windows-amd64.exe" "${MAIN_PATH}"

echo ""
echo "✅ Build complete! Binaries are in: ${BUILD_DIR}/"
echo ""
ls -lh "${BUILD_DIR}/"
echo ""
echo "📦 To distribute, just share the appropriate binary for each platform."
