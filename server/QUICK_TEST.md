# Quick Test Guide

## 🚀 Quick Start

### Step 1: Setup Database
```bash
cd server
node setupDatabase.js
```

### Step 2: Start Server
```bash
node index.js
```
Keep this terminal open - the server should show: `🚀 Server running at http://localhost:3000`

### Step 3: Run Tests

**In a NEW terminal window:**

#### Option A: Run Unit Tests (Fastest - No server needed)
```bash
cd server
node test-encryption-unit.js
```

#### Option B: Run Full Encryption Tests (Requires server)
```bash
cd server
node test-encryption.js
```

#### Option C: Run All API Tests
```bash
cd server
node test-api.js
```

## 📋 What Each Test Does

### `test-encryption-unit.js`
- Tests encryption functions directly
- No server required
- Fast execution
- Tests: encryption, decryption, error handling, edge cases

### `test-encryption.js`
- Tests full API with encryption
- Requires server running
- Tests: API endpoints, password encryption/decryption, security

### `test-api.js`
- Tests basic API functionality
- Requires server running
- Tests: auth, CRUD operations

## ✅ Expected Results

All tests should show:
```
🎉 All tests passed!
```

If tests fail, check:
1. Server is running on port 3000
2. Database is set up (`node setupDatabase.js`)
3. No other process is using port 3000

## 🔍 Quick Manual Test

1. Register a user:
```bash
curl -X POST http://localhost:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test123"}'
```

2. Save the token, then create an item with password:
```bash
curl -X POST http://localhost:3000/api/items \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"name":"Test","password":"secret123","masterPassword":"test123"}'
```

3. Get items without master password (password hidden):
```bash
curl -X GET http://localhost:3000/api/items \
  -H "Authorization: Bearer YOUR_TOKEN"
```

4. Get items with master password (password decrypted):
```bash
curl -X GET "http://localhost:3000/api/items?masterPassword=test123" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

See `TESTING.md` for detailed documentation.

