#!/bin/bash

# Client rerun script
# Kills existing Electron app and starts a new one

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo -e "${BLUE}🔄 Client Rerun Script${NC}"
echo "=================================="
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo -e "${RED}❌ Node.js is not installed or not in PATH${NC}"
    exit 1
fi

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo -e "${RED}❌ npm is not installed or not in PATH${NC}"
    exit 1
fi

# Check if node_modules exists, if not install dependencies
if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}⚠️  Dependencies not found. Installing...${NC}"
    npm install
    echo ""
fi

# Function to kill Electron processes
kill_electron() {
    echo -e "${YELLOW}🛑 Stopping Electron app...${NC}"
    
    # Kill Electron processes
    if command -v pkill &> /dev/null; then
        pkill -f "electron" 2>/dev/null || true
        sleep 1
        # Force kill if still running
        pkill -9 -f "electron" 2>/dev/null || true
    elif command -v killall &> /dev/null; then
        killall Electron 2>/dev/null || true
        sleep 1
        killall -9 Electron 2>/dev/null || true
    else
        # Fallback: try to find and kill by process name
        ps aux | grep -i electron | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null || true
    fi
    
    sleep 1
    echo -e "${GREEN}✅ Electron app stopped${NC}"
}

# Kill existing Electron app
kill_electron
echo ""

# Start Electron app
echo -e "${BLUE}🚀 Starting Electron app...${NC}"
echo -e "${YELLOW}   Press Ctrl+C to stop${NC}"
echo ""

# Run Electron in foreground
npm start