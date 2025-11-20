#!/bin/bash

# Exit on error
set -e

# Navigate to the directory of the script
cd "$(dirname "$0")"

echo "🚀 Starting build process for Windows Executable..."

# Check if node_modules exists, if not install dependencies
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
fi

# Check for icon.ico
if [ -f "icon.ico" ]; then
    echo "🖼️  Found icon.ico, using it for build..."
else
    echo "⚠️  Warning: icon.ico not found! Build will use default Electron icon."
fi

# Build for Windows using electron-builder
echo "🔨 Building .exe..."
# Use npx to ensure we use the local or download if missing
npx electron-builder --win

echo "✅ Build complete! You can find the executable in the 'dist' directory."
