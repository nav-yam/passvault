#!/bin/bash

# Server rerun script
# Kills existing server process and starts a new one
clear
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

echo -e "${BLUE}🔄 Server Rerun Script${NC}"
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

# Rebuild native modules for current Node.js version
echo -e "${YELLOW}🔧 Rebuilding native modules...${NC}"
if [ -d "node_modules" ]; then
    npm rebuild better-sqlite3 2>&1 | grep -v "npm WARN" || true
    echo -e "${GREEN}✅ Native modules rebuilt${NC}"
else
    echo -e "${YELLOW}⚠️  node_modules not found. Installing dependencies...${NC}"
    npm install
fi
echo ""

# Function to find and kill server process
kill_server() {
    local port=3000
    
    # Find process using port 3000
    if command -v lsof &> /dev/null; then
        # macOS/Linux with lsof
        local pid=$(lsof -ti:$port 2>/dev/null)
        if [ ! -z "$pid" ]; then
            echo -e "${YELLOW}🛑 Stopping server on port $port (PID: $pid)...${NC}"
            kill $pid 2>/dev/null || true
            sleep 1
            # Force kill if still running
            if kill -0 $pid 2>/dev/null; then
                echo -e "${YELLOW}⚠️  Force killing server...${NC}"
                kill -9 $pid 2>/dev/null || true
            fi
            echo -e "${GREEN}✅ Server stopped${NC}"
        else
            echo -e "${BLUE}ℹ️  No server running on port $port${NC}"
        fi
    elif command -v netstat &> /dev/null; then
        # Linux with netstat
        local pid=$(netstat -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d'/' -f1 | head -1)
        if [ ! -z "$pid" ]; then
            echo -e "${YELLOW}🛑 Stopping server on port $port (PID: $pid)...${NC}"
            kill $pid 2>/dev/null || true
            sleep 1
            if kill -0 $pid 2>/dev/null; then
                echo -e "${YELLOW}⚠️  Force killing server...${NC}"
                kill -9 $pid 2>/dev/null || true
            fi
            echo -e "${GREEN}✅ Server stopped${NC}"
        else
            echo -e "${BLUE}ℹ️  No server running on port $port${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  Could not detect running server (lsof/netstat not available)${NC}"
        echo -e "${YELLOW}   Attempting to kill any node processes running index.js...${NC}"
        pkill -f "node.*index.js" 2>/dev/null || true
        sleep 1
    fi
}

# Kill existing server
kill_server
echo ""

# Rebuild database
echo -e "${YELLOW}🗄️  Rebuilding database...${NC}"
if [ -f "db/app.db" ]; then
    echo -e "${YELLOW}   Removing existing database...${NC}"
    rm -f db/app.db
fi

# Ensure db directory exists
mkdir -p db

# Run database setup
echo -e "${YELLOW}   Running database setup...${NC}"
node setupDatabase.js
echo -e "${GREEN}✅ Database rebuilt successfully${NC}"
echo ""

# Start server
echo -e "${BLUE}🚀 Starting server...${NC}"
echo -e "${BLUE}   Server will run on http://localhost:3000${NC}"
echo -e "${YELLOW}   Press Ctrl+C to stop${NC}"
echo ""

# Run server in foreground
node index.js

