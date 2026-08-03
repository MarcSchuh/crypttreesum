#!/usr/bin/env bash

# Build script for crypttreesum executable using PyInstaller

set -euo pipefail

echo "Building crypttreesum executable..."

if [ ! -f "pyproject.toml" ]; then
    echo "Error: Please run this script from the project root directory"
    exit 1
fi

echo "Cleaning previous builds..."
rm -rf build/ dist/crypttreesum __pycache__/ ./*.spec

echo "Building executable with PyInstaller..."
uv run pyinstaller --onefile \
    --name crypttreesum \
    --strip \
    src/crypttreesum/__main__.py

if [ -f "dist/crypttreesum" ]; then
    echo "Build successful!"
    echo "Executable created: dist/crypttreesum"
    echo "File size: $(du -h dist/crypttreesum | cut -f1)"
    chmod +x dist/crypttreesum
    echo ""
    echo "You can now run: ./dist/crypttreesum --help"
    rm -rf build/ ./*.spec
else
    echo "Build failed!"
    exit 1
fi
