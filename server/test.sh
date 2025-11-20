#!/bin/bash

# Test runner script for server tests
# Usage: ./test.sh [test-name]
# If no test-name is provided, runs all tests
clear
set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global counters for test results
PASSED=0
FAILED=0

print_summary() {
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}📊 Test Summary${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${GREEN}✅ Passed: $PASSED${NC}"
    echo -e "  ${RED}❌ Failed: $FAILED${NC}"
    echo ""
    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}🎉 All tests passed!${NC}"
    else
        echo -e "${RED}⚠️  Some tests failed${NC}"
    fi
}

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo -e "${BLUE}🧪 Server Test Runner${NC}"
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

# Rebuild native modules for current Node.js version (if node_modules exists)
if [ -d "node_modules" ]; then
    echo -e "${YELLOW}🔧 Ensuring native modules are built for current Node.js version...${NC}"
    npm rebuild better-sqlite3 2>&1 | grep -v "npm WARN" || true
    echo ""
fi

# Check if database exists, if not run setup
if [ ! -f "db/app.db" ]; then
    echo -e "${YELLOW}⚠️  Database not found. Running setup...${NC}"
    node setupDatabase.js
    echo ""
fi

# Function to run a test
run_test() {
    local test_file=$1
    local test_name=$2
    
    if [ ! -f "$test_file" ]; then
        echo -e "${RED}❌ Test file not found: $test_file${NC}"
        return 1
    fi
    
    echo -e "${BLUE}Running: $test_name${NC}"
    echo "-----------------------------------"
    
    if node "$test_file"; then
        echo -e "${GREEN}✅ $test_name passed${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}❌ $test_name failed${NC}"
        echo ""
        return 1
    fi
}

# If a specific test is provided, run only that
if [ $# -gt 0 ]; then
    test_name=$1
    case $test_name in
        "unit"|"encryption-unit"|"test-encryption-unit")
            run_test "test-encryption-unit.js" "Encryption Unit Tests"
            ;;
        "--unit"|"-u")
            # Run unit test group
            PASSED=0
            FAILED=0

            if run_test "test-encryption-unit.js" "Encryption Unit Tests"; then
                ((PASSED++))
            else
                ((FAILED++))
            fi

            if run_test "test-vaults-db.js" "Vault Database Unit Tests"; then
                ((PASSED++))
            else
                ((FAILED++))
            fi

            if run_test "test-password-strength.js" "Password Strength Calculator Tests"; then
                ((PASSED++))
            else
                ((FAILED++))
            fi

            if run_test "test-password-generation.js" "Password Generation Tests"; then
                ((PASSED++))
            else
                ((FAILED++))
            fi

            if run_test "test-security-advanced.js" "Advanced Security Tests"; then
                ((PASSED++))
            else
                ((FAILED++))
            fi

            print_summary
            if [ $FAILED -eq 0 ]; then
                exit 0
            else
                exit 1
            fi
            ;;
        "api"|"test-api")
            run_test "test-api.js" "API Integration Tests"
            ;;
        "integration"|"--integration"|"-i")
            # Run integration test group
            PASSED=0
            FAILED=0

            # Ensure server is running
            if ! curl -s http://localhost:3000/api/ping > /dev/null 2>&1; then
                echo -e "${RED}❌ Server is not running on port 3000${NC}"
                print_summary
                exit 1
            fi

            if run_test "test-api.js" "API Integration Tests"; then
                ((PASSED++))
            else
                ((FAILED++))
            fi

            if run_test "test-encryption.js" "Encryption Integration Tests"; then
                ((PASSED++))
            else
                ((FAILED++))
            fi

            if run_test "test-vaults.js" "Vault Integration Tests"; then
                ((PASSED++))
            else
                ((FAILED++))
            fi

            if run_test "test-master-password.js" "Master Password Flow Tests"; then
                ((PASSED++))
            else
                ((FAILED++))
            fi

            if run_test "test-password-ui.js" "Password UI Features Tests"; then
                ((PASSED++))
            else
                ((FAILED++))
            fi

            if run_test "test-shared-vaults.js" "Shared Vaults Tests"; then
                ((PASSED++))
            else
                ((FAILED++))
            fi

            print_summary
            if [ $FAILED -eq 0 ]; then
                exit 0
            else
                exit 1
            fi
            ;;
        "encryption"|"test-encryption")
            run_test "test-encryption.js" "Encryption Integration Tests"
            ;;
        "vaults"|"test-vaults")
            run_test "test-vaults.js" "Vault Integration Tests"
            ;;
        "vaults-db"|"test-vaults-db")
            run_test "test-vaults-db.js" "Vault Database Unit Tests"
            ;;
        "master-password"|"test-master-password"|"mp")
            run_test "test-master-password.js" "Master Password Flow Tests"
            ;;
        "password-ui"|"test-password-ui"|"ui")
            run_test "test-password-ui.js" "Password UI Features Tests"
            ;;
        "password-strength"|"test-password-strength"|"strength")
            run_test "test-password-strength.js" "Password Strength Calculator Tests"
            ;;
        "password-generation"|"test-password-generation"|"gen")
            run_test "test-password-generation.js" "Password Generation Tests"
            ;;
        "shared-vaults"|"test-shared-vaults"|"shared")
            run_test "test-shared-vaults.js" "Shared Vaults Tests"
            ;;
        "security-bugs"|"test-security-bugs")
            run_test "test-security-bugs.js" "Security Bugs Tests"
            ;;
        "security"|"--security"|"-s"|"test-security")
            # Run security-focused test group
            PASSED=0
            FAILED=0

            # Start server if required by tests
            if ! curl -s http://localhost:3000/api/ping > /dev/null 2>&1; then
                echo -e "${YELLOW}⚠️  Server not running; some security tests may require the server${NC}"
            fi

            if run_test "test-security-advanced.js" "Advanced Security Tests"; then
                ((PASSED++))
            else
                ((FAILED++))
            fi

            if run_test "test-input-validation.js" "Input Validation Tests"; then
                ((PASSED++))
            else
                ((FAILED++))
            fi

            if run_test "test-injection-attacks.js" "Injection Attack Tests"; then
                ((PASSED++))
            else
                ((FAILED++))
            fi

            if run_test "test-security-bugs.js" "Security Bugs Tests"; then
                ((PASSED++))
            else
                ((FAILED++))
            fi

            print_summary
            if [ $FAILED -eq 0 ]; then
                exit 0
            else
                exit 1
            fi
            ;;
        "advanced-security"|"test-security-advanced")
            run_test "test-security-advanced.js" "Advanced Security Tests"
            ;;
        "all")
            # Run all tests (fall through to default behavior)
            ;;
        *)
            echo -e "${RED}❌ Unknown test: $test_name${NC}"
            echo ""
            echo "Available tests:"
            echo "  unit, encryption-unit    - Encryption unit tests (no server required)"
            echo "  api                     - API integration tests (server required)"
            echo "  encryption              - Encryption integration tests (server required)"
            echo "  vaults                  - Vault integration tests (server required)"
            echo "  vaults-db               - Vault database unit tests (no server required)"
            echo "  master-password, mp     - Master password flow tests (server required)"
            echo "  password-ui, ui         - Password UI features tests (server required)"
            echo "  password-strength, strength - Password strength calculator tests (no server required)"
            echo "  password-generation, gen - Password generation tests (no server required)"
            echo "  shared-vaults, shared   - Shared vaults tests (server required)"
            echo "  security-bugs, security - Security bugs tests (server required)"
            echo "  advanced-security       - Advanced security tests (memory, sessions, crypto)"
            echo "  all                     - Run all tests"
            echo "  --unit, -u             - Run unit test group"
            echo "  --integration, -i      - Run integration test group"
            echo "  --security, -s         - Run security test group"
            exit 1
            ;;
    esac
    
    # If "all" was specified, continue to run all tests
    if [ "$test_name" != "all" ]; then
        exit 0
    fi
fi

# Run all tests
echo -e "${BLUE}Running all tests...${NC}"
echo ""

PASSED=0
FAILED=0

# 1. Unit tests (no server required)
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Unit Tests (No server required)${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if run_test "test-encryption-unit.js" "Encryption Unit Tests"; then
    ((PASSED++))
else
    ((FAILED++))
fi

if run_test "test-vaults-db.js" "Vault Database Unit Tests"; then
    ((PASSED++))
else
    ((FAILED++))
fi

if run_test "test-password-strength.js" "Password Strength Calculator Tests"; then
    ((PASSED++))
else
    ((FAILED++))
fi

if run_test "test-password-generation.js" "Password Generation Tests"; then
    ((PASSED++))
else
    ((FAILED++))
fi


# 2. Integration tests (server required)
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Integration Tests (Server required)${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check if server is running
if ! curl -s http://localhost:3000/api/ping > /dev/null 2>&1; then
    echo -e "${RED}❌ Server is not running on port 3000${NC}"
    echo -e "${YELLOW}💡 Start the server with: ./rerun.sh${NC}"
    echo ""
    print_summary
    echo -e "  ${YELLOW}Skipped: 6 (server not running)${NC}"
    exit 1
fi

if run_test "test-api.js" "API Integration Tests"; then
    ((PASSED++))
else
    ((FAILED++))
fi

if run_test "test-encryption.js" "Encryption Integration Tests"; then
    ((PASSED++))
else
    ((FAILED++))
fi

if run_test "test-vaults.js" "Vault Integration Tests"; then
    ((PASSED++))
else
    ((FAILED++))
fi

if run_test "test-master-password.js" "Master Password Flow Tests"; then
    ((PASSED++))
else
    ((FAILED++))
fi

if run_test "test-password-ui.js" "Password UI Features Tests"; then
    ((PASSED++))
else
    ((FAILED++))
fi

if run_test "test-shared-vaults.js" "Shared Vaults Tests"; then
    ((PASSED++))
else
    ((FAILED++))
fi

# 3. Security tests
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Security Tests (May require server)${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if run_test "test-security-advanced.js" "Advanced Security Tests"; then
    ((PASSED++))
else
    ((FAILED++))
fi

if run_test "test-input-validation.js" "Input Validation Tests"; then
    ((PASSED++))
else
    ((FAILED++))
fi

if run_test "test-injection-attacks.js" "Injection Attack Tests"; then
    ((PASSED++))
else
    ((FAILED++))
fi

if run_test "test-security-bugs.js" "Security Bugs Tests"; then
    ((PASSED++))
else
    ((FAILED++))
fi

# Summary
print_summary
if [ $FAILED -eq 0 ]; then
    exit 0
else
    exit 1
fi
