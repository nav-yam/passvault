// cd server
// node test-vaults-db.js
//
// Unit tests for vault database operations (no server required)

const db = require('better-sqlite3')('./db/app.db');
const bcrypt = require('bcrypt');

let passed = 0;
let failed = 0;
let testUserId = null;
let testVaultId = null;

function test(name, testFn) {
    try {
        const result = testFn();
        if (result) {
            console.log(`✅ ${name}`);
            passed++;
            return true;
        } else {
            console.log(`❌ ${name}`);
            failed++;
            return false;
        }
    } catch (error) {
        console.log(`❌ ${name} - Error: ${error.message}`);
        failed++;
        return false;
    }
}

async function setupTestUser() {
    // Create a test user
    const username = `dbtest_${Date.now()}`;
    const password = 'testpassword123';
    const passwordHash = await bcrypt.hash(password, 10);
    
    const stmt = db.prepare('INSERT INTO users (username, password_hash, encryption_salt) VALUES (?, ?, ?)');
    const result = stmt.run(username, passwordHash, 'testsalt123');
    testUserId = result.lastInsertRowid;
    
    return { username, password, userId: testUserId };
}

function cleanup() {
    if (testUserId) {
        // Delete items first (foreign key constraint)
        db.prepare('DELETE FROM items WHERE user_id = ?').run(testUserId);
        // Delete vaults
        db.prepare('DELETE FROM vaults WHERE user_id = ?').run(testUserId);
        // Delete user
        db.prepare('DELETE FROM users WHERE id = ?').run(testUserId);
    }
}

console.log('🧪 Testing Vault Database Operations (Unit Tests)\n');
console.log('='.repeat(60));

// Wrap everything in async IIFE to support await
(async () => {
    // Setup
    let testUser = null;
    try {
        testUser = await setupTestUser();
    } catch (error) {
        console.error('Failed to setup test user:', error);
        process.exit(1);
    }

// Test 1: Vaults table exists
test('Vaults table exists', () => {
    try {
        const result = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='vaults'").get();
        return result !== undefined;
    } catch (error) {
        return false;
    }
});

// Test 2: Items table has vault_id column
test('Items table has vault_id column', () => {
    try {
        const result = db.prepare("PRAGMA table_info(items)").all();
        return result.some(col => col.name === 'vault_id');
    } catch (error) {
        return false;
    }
});

// Test 3: Create default vault
test('Create default vault for user', () => {
    const stmt = db.prepare('INSERT INTO vaults (name, user_id) VALUES (?, ?)');
    const result = stmt.run('Default Vault', testUserId);
    testVaultId = result.lastInsertRowid;
    return result.lastInsertRowid > 0;
});

// Test 4: Vault has correct structure
test('Vault has correct structure', () => {
    const vault = db.prepare('SELECT * FROM vaults WHERE id = ?').get(testVaultId);
    return vault && 
           vault.id === testVaultId &&
           vault.name === 'Default Vault' &&
           vault.user_id === testUserId &&
           vault.created_at !== null;
});

// Test 5: Create item with vault_id
let testItemId = null;
test('Create item with vault_id', () => {
    const stmt = db.prepare('INSERT INTO items (name, description, user_id, vault_id) VALUES (?, ?, ?, ?)');
    const result = stmt.run('Test Item', 'Test Description', testUserId, testVaultId);
    testItemId = result.lastInsertRowid;
    return result.lastInsertRowid > 0;
});

// Test 6: Item has vault_id
test('Item has vault_id field', () => {
    const item = db.prepare('SELECT * FROM items WHERE id = ?').get(testItemId);
    return item && item.vault_id === testVaultId;
});

// Test 7: Query items by vault_id
test('Query items by vault_id', () => {
    const items = db.prepare('SELECT * FROM items WHERE vault_id = ? AND user_id = ?').all(testVaultId, testUserId);
    return items.length > 0 && items[0].id === testItemId;
});

// Test 8: Foreign key constraint - cannot create item with invalid vault_id
test('Foreign key constraint prevents invalid vault_id', () => {
    try {
        const stmt = db.prepare('INSERT INTO items (name, user_id, vault_id) VALUES (?, ?, ?)');
        stmt.run('Invalid Item', testUserId, 99999);
        return false; // Should have failed
    } catch (error) {
        return true; // Expected to fail
    }
});

// Test 9: Get all vaults for user
test('Get all vaults for user', () => {
    const vaults = db.prepare('SELECT * FROM vaults WHERE user_id = ?').all(testUserId);
    return vaults.length > 0 && vaults.some(v => v.id === testVaultId);
});

// Test 10: Update item vault_id
test('Update item vault_id', () => {
    // Create another vault
    const stmt = db.prepare('INSERT INTO vaults (name, user_id) VALUES (?, ?)');
    const result = stmt.run('Test Vault 2', testUserId);
    const newVaultId = result.lastInsertRowid;
    
    // Update item to new vault
    const updateStmt = db.prepare('UPDATE items SET vault_id = ? WHERE id = ?');
    updateStmt.run(newVaultId, testItemId);
    
    // Verify
    const item = db.prepare('SELECT * FROM items WHERE id = ?').get(testItemId);
    return item.vault_id === newVaultId;
});

// Test 11: Cascade delete - deleting vault should delete items
test('Cascade delete - deleting vault deletes items', () => {
    // Create a vault and item
    const vaultStmt = db.prepare('INSERT INTO vaults (name, user_id) VALUES (?, ?)');
    const vaultResult = vaultStmt.run('Cascade Test Vault', testUserId);
    const cascadeVaultId = vaultResult.lastInsertRowid;
    
    const itemStmt = db.prepare('INSERT INTO items (name, user_id, vault_id) VALUES (?, ?, ?)');
    const itemResult = itemStmt.run('Cascade Test Item', testUserId, cascadeVaultId);
    const cascadeItemId = itemResult.lastInsertRowid;
    
    // Delete vault
    db.prepare('DELETE FROM vaults WHERE id = ?').run(cascadeVaultId);
    
    // Verify item is deleted
    const item = db.prepare('SELECT * FROM items WHERE id = ?').get(cascadeItemId);
    return item === undefined;
});

// Test 12: Multiple items in same vault
test('Multiple items can exist in same vault', () => {
    const stmt = db.prepare('INSERT INTO items (name, user_id, vault_id) VALUES (?, ?, ?)');
    const result1 = stmt.run('Item 1', testUserId, testVaultId);
    const result2 = stmt.run('Item 2', testUserId, testVaultId);
    
    const items = db.prepare('SELECT * FROM items WHERE vault_id = ?').all(testVaultId);
    return items.length >= 2;
});

// Test 13: Items isolated by vault
test('Items are isolated by vault', () => {
    // Create another vault
    const vaultStmt = db.prepare('INSERT INTO vaults (name, user_id) VALUES (?, ?)');
    const vaultResult = vaultStmt.run('Isolation Test Vault', testUserId);
    const isolationVaultId = vaultResult.lastInsertRowid;
    
    // Create item in new vault
    const itemStmt = db.prepare('INSERT INTO items (name, user_id, vault_id) VALUES (?, ?, ?)');
    itemStmt.run('Isolation Item', testUserId, isolationVaultId);
    
    // Query items in first vault
    const items = db.prepare('SELECT * FROM items WHERE vault_id = ?').all(testVaultId);
    
    // Should not include the isolation item
    return !items.some(item => item.name === 'Isolation Item');
});

// Test 14: Default vault is created on user registration (simulated)
test('Default vault creation logic works', () => {
    // Check if default vault exists for test user
    const defaultVault = db.prepare('SELECT * FROM vaults WHERE user_id = ? AND name = ?').get(testUserId, 'Default Vault');
    return defaultVault !== undefined;
});

// Test 15: Vault name uniqueness per user (not enforced by DB, but should be checked in app)
test('Multiple vaults can exist for same user', () => {
    const stmt = db.prepare('INSERT INTO vaults (name, user_id) VALUES (?, ?)');
    const result1 = stmt.run('Vault A', testUserId);
    const result2 = stmt.run('Vault B', testUserId);
    
    const vaults = db.prepare('SELECT * FROM vaults WHERE user_id = ?').all(testUserId);
    return vaults.length >= 2;
});

    // Cleanup
    cleanup();

    // Summary
    console.log('\n' + '='.repeat(60));
    console.log(`📊 Results: ${passed} passed, ${failed} failed`);
    console.log('='.repeat(60));

    if (failed === 0) {
        console.log('\n🎉 All database unit tests passed!');
        console.log('\n✅ Vault database operations are working correctly:');
        console.log('   - Vault table structure');
        console.log('   - Items table with vault_id foreign key');
        console.log('   - Vault creation and retrieval');
        console.log('   - Item-vault associations');
        console.log('   - Foreign key constraints');
        console.log('   - Cascade deletes');
        console.log('   - Vault isolation');
        process.exit(0);
    } else {
        console.log('\n⚠️  Some database unit tests failed');
        process.exit(1);
    }
})();

