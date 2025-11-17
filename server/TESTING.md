# Testing Guide for Password Encryption

This guide explains how to test the password encryption functionality.
# Testing Token :
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsInVzZXJuYW1lIjoidGVzdHVzZXIyIiwiaWF0IjoxNzYzNDAyNDU0LCJleHAiOjE3NjQwMDcyNTR9.HRWvQhAc2zpsPpKFSOX4tMW85QW9U_rzf4jXo1xr_sI
```
## Prerequisites

1. **Start the server** (in one terminal):
   ```bash
   cd server
   node index.js
   ```

2. **Setup the database** (if not already done):
   ```bash
   cd server
   node setupDatabase.js
   ```

## Test Files

### 1. Unit Tests (No server required)
**File:** `test-encryption-unit.js`

Tests the encryption utilities directly without needing the server running.

```bash
cd server
node test-encryption-unit.js
```

**What it tests:**
- ✅ Salt generation
- ✅ Encryption and decryption
- ✅ Error handling (wrong passwords, corrupted data)
- ✅ Special characters and unicode
- ✅ Long text encryption
- ✅ Ciphertext format validation

### 2. API Integration Tests (Server required)
**File:** `test-encryption.js`

Tests the full API with encryption features.

```bash
cd server
node test-encryption.js
```

**What it tests:**
- ✅ User registration with encryption salt
- ✅ Creating items with encrypted passwords
- ✅ Retrieving items without master password (passwords hidden)
- ✅ Retrieving items with master password (passwords decrypted)
- ✅ Wrong master password fails decryption
- ✅ Updating item passwords
- ✅ Multiple items with different passwords
- ✅ Raw passwords never exposed

### 3. General API Tests
**File:** `test-api.js`

Tests basic API functionality (auth, CRUD operations).

```bash
cd server
node test-api.js
```

### 4. Vault Integration Tests (Server required)
**File:** `test-vaults.js`

Tests vault functionality including vault creation, item filtering, and access control.

```bash
cd server
node test-vaults.js
```

**What it tests:**
- ✅ Default vault creation on registration
- ✅ Vault retrieval and listing
- ✅ Items filtered by vault
- ✅ Items associated with correct vault
- ✅ Vault access control (users can only access their vaults)
- ✅ Integration with password encryption
- ✅ Vault isolation

### 5. Vault Database Unit Tests (No server required)
**File:** `test-vaults-db.js`

Tests vault database operations directly without needing the server running.

```bash
cd server
node test-vaults-db.js
```

**What it tests:**
- ✅ Vault table structure
- ✅ Items table with vault_id foreign key
- ✅ Vault creation and retrieval
- ✅ Item-vault associations
- ✅ Foreign key constraints
- ✅ Cascade deletes
- ✅ Vault isolation

### 6. Master Password Flow Tests (Server required)
**File:** `test-master-password.js`

Tests the complete master password flow including encryption, decryption, and error handling.

```bash
cd server
node test-master-password.js
```

**What it tests:**
- ✅ Creating items with encrypted passwords
- ✅ Creating items without passwords (no master password needed)
- ✅ Creating items with password but no master password (should fail)
- ✅ Retrieving items without master password (passwords hidden)
- ✅ Retrieving items with correct master password (passwords decrypted)
- ✅ Retrieving items with wrong master password (decryption fails)
- ✅ Multiple items with different passwords
- ✅ Updating item passwords with master password
- ✅ Updating passwords without master password (should fail)
- ✅ Updating other fields without master password (should work)
- ✅ Encrypted passwords never exposed in raw form

### 7. Password UI Features Tests (Server required)
**File:** `test-password-ui.js`

Tests the improved password UI features including website, username, and notes formatting.

```bash
cd server
node test-password-ui.js
```

**What it tests:**
- ✅ Creating items with website, username, password, and notes
- ✅ Description parsing (extracting username and notes)
- ✅ Creating items with only website and password
- ✅ Creating items with username but no notes
- ✅ Creating items with notes but no username
- ✅ Updating item username and notes
- ✅ Verifying items without master password hide passwords
- ✅ Multiple items with different structures
- ✅ Structured description format validation

### 8. Password Strength Calculator Tests (No server required)
**File:** `test-password-strength.js`

Tests the password strength calculation logic (custom fallback when zxcvbn unavailable).

```bash
cd server
node test-password-strength.js
```

**What it tests:**
- ✅ Empty password handling
- ✅ Short password detection
- ✅ Character variety checks (lowercase, uppercase, numbers, special)
- ✅ Length-based scoring
- ✅ Common pattern detection and penalization
- ✅ Strength level classification (Very Weak to Strong)
- ✅ Feedback message generation
- ✅ Score capping at maximum
- ✅ Real-world password strength assessment

### 9. Password Generation Tests (No server required)
**File:** `test-password-generation.js`

Tests the password generation logic for creating strong, random passwords.

```bash
cd server
node test-password-generation.js
```

**What it tests:**
- ✅ Default password generation (16 chars, all types)
- ✅ Character type inclusion (lowercase, uppercase, numbers, special)
- ✅ Custom length support
- ✅ Password shuffling (randomization)
- ✅ Character set customization
- ✅ Minimum length enforcement
- ✅ Password uniqueness
- ✅ Required character type enforcement
- ✅ Error handling for invalid configurations

## Running Tests

### Using the Test Script

The easiest way to run tests is using the test script:

```bash
cd server
./test.sh [test-name]
```

**Available test names:**
- `unit` or `encryption-unit` - Encryption unit tests (no server required)
- `api` - API integration tests (server required)
- `encryption` - Encryption integration tests (server required)
- `vaults` - Vault integration tests (server required)
- `vaults-db` - Vault database unit tests (no server required)
- `master-password` or `mp` - Master password flow tests (server required)
- `password-ui` or `ui` - Password UI features tests (server required)
- `password-strength` or `strength` - Password strength calculator tests (no server required)
- `password-generation` or `gen` - Password generation tests (no server required)
- `all` - Run all tests

**Examples:**
```bash
# Run all tests
./test.sh all

# Run only master password tests
./test.sh master-password

# Run only unit tests (no server needed)
./test.sh unit

# Run password strength tests (no server needed)
./test.sh password-strength

# Run password generation tests (no server needed)
./test.sh password-generation

# Run password UI tests (server required)
./test.sh password-ui
```

## Manual Testing

### 1. Test Registration
```bash
curl -X POST http://localhost:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"mypassword123"}'
```

### 2. Test Login
```bash
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"mypassword123"}'
```

Save the token from the response.

### 3. Create Item WITHOUT Password
```bash
curl -X POST http://localhost:3000/api/items \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{"name":"My Account","description":"Test account"}'
```

### 4. Create Item WITH Encrypted Password
```bash
curl -X POST http://localhost:3000/api/items \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{
    "name":"Bank Account",
    "description":"My bank",
    "password":"MySecretPassword123",
    "masterPassword":"mypassword123"
  }'
```

### 5. Get Items WITHOUT Master Password (passwords hidden)
```bash
curl -X GET http://localhost:3000/api/items \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

**Expected:** Items returned with `hasPassword: true` but no `password` field.

### 6. Get Items WITH Master Password (passwords decrypted)
```bash
curl -X GET "http://localhost:3000/api/items?masterPassword=mypassword123" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

**Expected:** Items returned with decrypted `password` field.

### 7. Update Item Password
```bash
curl -X PUT http://localhost:3000/api/items/ITEM_ID \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{
    "password":"NewPassword456",
    "masterPassword":"mypassword123"
  }'
```

### 8. Test Wrong Master Password
```bash
curl -X GET "http://localhost:3000/api/items?masterPassword=wrongpassword" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

**Expected:** Items returned with `password: null` and `decryptionError` field.

### 9. Get Vaults
```bash
curl -X GET http://localhost:3000/api/vaults \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

**Expected:** List of vaults for the authenticated user, including "Default Vault".

### 10. Get Items by Vault
```bash
curl -X GET "http://localhost:3000/api/items?vault_id=1" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

**Expected:** Items filtered by the specified vault_id.

### 11. Create Item in Specific Vault
```bash
curl -X POST http://localhost:3000/api/items \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{
    "name":"Vault Item",
    "description":"Item in specific vault",
    "vault_id":1
  }'
```

**Expected:** Item created and associated with the specified vault.

## Verification Checklist

### Encryption
- [ ] Passwords are encrypted before storage
- [ ] Encrypted passwords are never exposed without master password
- [ ] Correct master password decrypts passwords successfully
- [ ] Wrong master password fails decryption
- [ ] Each encryption uses a unique IV (same password, different ciphertext)
- [ ] Database contains encrypted data, not plaintext
- [ ] Update operations re-encrypt passwords correctly
- [ ] Multiple items can have different encrypted passwords

### Vaults
- [ ] Default vault is created on user registration
- [ ] Users can retrieve their vaults
- [ ] Items are filtered by vault
- [ ] Items are associated with correct vault
- [ ] Users cannot access other users' vaults
- [ ] Items default to default vault if no vault_id specified
- [ ] Vault isolation works correctly

## Database Inspection

### Verify Passwords are Encrypted
```bash
cd server
sqlite3 db/app.db "SELECT id, name, password FROM items LIMIT 5;"
```

**Expected:** The `password` column should contain encrypted data in format: `iv:tag:encrypted` (hex strings), NOT plaintext passwords.

### Verify Vault Structure
```bash
cd server
sqlite3 db/app.db "SELECT * FROM vaults;"
```

**Expected:** Each user should have at least one vault (Default Vault).

### Verify Items Have Vault Association
```bash
cd server
sqlite3 db/app.db "SELECT id, name, vault_id FROM items LIMIT 5;"
```

**Expected:** All items should have a `vault_id` that references a valid vault.

## Troubleshooting

### "User encryption salt not found"
- **Solution:** Re-register the user. Old users created before encryption was added don't have a salt.

### "Decryption failed"
- **Cause:** Wrong master password
- **Solution:** Use the same password used during registration/login

### Tests fail with connection errors
- **Solution:** Make sure the server is running on port 3000

### Database errors
- **Solution:** Run `node setupDatabase.js` to ensure schema is up to date

