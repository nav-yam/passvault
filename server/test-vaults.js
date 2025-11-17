// cd server
// node test-vaults.js
//
// Integration tests for vault functionality

const http = require('http');

const API_URL = 'http://localhost:3000';
let token = null;
let userId = null;
let defaultVaultId = null;

// Simple function to make HTTP requests
function request(method, path, data, authToken) {
    return new Promise((resolve, reject) => {
        const url = new URL(path, API_URL);
        const body = data ? JSON.stringify(data) : null;

        const options = {
            method: method,
            hostname: url.hostname,
            port: url.port,
            path: url.pathname + (url.search || ''),
            headers: {
                'Content-Type': 'application/json',
            }
        };

        if (authToken) {
            options.headers['Authorization'] = `Bearer ${authToken}`;
        }

        if (body) {
            options.headers['Content-Length'] = Buffer.byteLength(body);
        }

        const req = http.request(options, (res) => {
            let responseData = '';
            res.on('data', chunk => responseData += chunk);
            res.on('end', () => {
                try {
                    const json = responseData ? JSON.parse(responseData) : {};
                    resolve({ status: res.statusCode, data: json });
                } catch (e) {
                    resolve({ status: res.statusCode, data: responseData });
                }
            });
        });

        req.on('error', reject);
        if (body) req.write(body);
        req.end();
    });
}

// Test functions
async function test(name, testFn) {
    try {
        const result = await testFn();
        if (result) {
            console.log(`✅ ${name}`);
            return true;
        } else {
            console.log(`❌ ${name}`);
            return false;
        }
    } catch (error) {
        console.log(`❌ ${name} - Error: ${error.message}`);
        return false;
    }
}

// Run all tests
async function runTests() {
    console.log('🧪 Testing Vault Functionality\n');
    console.log('='.repeat(60));

    let passed = 0;
    let failed = 0;

    // Test 1: Register new user (should create default vault)
    const username = `vaulttest_${Date.now()}`;
    const password = 'password123';
    const registerResult = await test('Register new user creates default vault', async () => {
        const res = await request('POST', '/api/register', { username, password });
        if (res.status === 201 && res.data.token && res.data.user) {
            token = res.data.token;
            userId = res.data.user.id;
            return true;
        }
        return false;
    });
    registerResult ? passed++ : failed++;

    // Test 2: Get vaults after registration
    const getVaultsResult = await test('Get vaults returns default vault', async () => {
        const res = await request('GET', '/api/vaults', null, token);
        if (res.status === 200 && Array.isArray(res.data) && res.data.length > 0) {
            const defaultVault = res.data.find(v => v.name === 'Default Vault');
            if (defaultVault) {
                defaultVaultId = defaultVault.id;
                return true;
            }
        }
        return false;
    });
    getVaultsResult ? passed++ : failed++;

    // Test 3: Verify default vault has correct structure
    const vaultStructureResult = await test('Default vault has correct structure', async () => {
        const res = await request('GET', '/api/vaults', null, token);
        if (res.status === 200 && res.data.length > 0) {
            const vault = res.data[0];
            return vault.id && vault.name === 'Default Vault' && vault.created_at;
        }
        return false;
    });
    vaultStructureResult ? passed++ : failed++;

    // Test 4: Get items without vault_id (should use default vault)
    const getItemsDefaultResult = await test('Get items without vault_id uses default vault', async () => {
        const res = await request('GET', '/api/items', null, token);
        return res.status === 200 && Array.isArray(res.data);
    });
    getItemsDefaultResult ? passed++ : failed++;

    // Test 5: Create item without vault_id (should use default vault)
    let item1Id = null;
    const createItem1Result = await test('Create item without vault_id uses default vault', async () => {
        const res = await request('POST', '/api/items', 
            { name: 'Item 1', description: 'First item' }, 
            token);
        if (res.status === 200 && res.data.id) {
            item1Id = res.data.id;
            return true;
        }
        return false;
    });
    createItem1Result ? passed++ : failed++;

    // Test 6: Create item with explicit vault_id
    let item2Id = null;
    const createItem2Result = await test('Create item with explicit vault_id', async () => {
        const res = await request('POST', '/api/items', 
            { name: 'Item 2', description: 'Second item', vault_id: defaultVaultId }, 
            token);
        if (res.status === 200 && res.data.id) {
            item2Id = res.data.id;
            return true;
        }
        return false;
    });
    createItem2Result ? passed++ : failed++;

    // Test 7: Get items filtered by vault_id
    const getItemsByVaultResult = await test('Get items filtered by vault_id', async () => {
        const res = await request('GET', `/api/items?vault_id=${defaultVaultId}`, null, token);
        if (res.status === 200 && Array.isArray(res.data)) {
            // Should have both items
            return res.data.length >= 2 && 
                   res.data.some(item => item.id === item1Id) &&
                   res.data.some(item => item.id === item2Id);
        }
        return false;
    });
    getItemsByVaultResult ? passed++ : failed++;

    // Test 8: Verify items have vault_id
    const itemsHaveVaultIdResult = await test('Items have vault_id field', async () => {
        const res = await request('GET', `/api/items?vault_id=${defaultVaultId}`, null, token);
        if (res.status === 200 && Array.isArray(res.data) && res.data.length > 0) {
            return res.data.every(item => item.vault_id === defaultVaultId);
        }
        return false;
    });
    itemsHaveVaultIdResult ? passed++ : failed++;

    // Test 9: Get vaults without token (should fail)
    const noTokenVaultsResult = await test('Get vaults without token (should fail)', async () => {
        const res = await request('GET', '/api/vaults');
        return res.status === 401;
    });
    noTokenVaultsResult ? passed++ : failed++;

    // Test 10: Access vault that doesn't belong to user (should fail)
    const wrongVaultResult = await test('Access vault that doesn\'t belong to user (should fail)', async () => {
        const res = await request('GET', '/api/items?vault_id=99999', null, token);
        return res.status === 403;
    });
    wrongVaultResult ? passed++ : failed++;

    // Test 11: Create item with invalid vault_id (should fail)
    const invalidVaultItemResult = await test('Create item with invalid vault_id (should fail)', async () => {
        const res = await request('POST', '/api/items', 
            { name: 'Invalid Item', vault_id: 99999 }, 
            token);
        return res.status === 403;
    });
    invalidVaultItemResult ? passed++ : failed++;

    // Test 12: Update item vault_id
    const updateVaultIdResult = await test('Update item vault_id (should work but stay in same vault for now)', async () => {
        // Since we only have one vault, updating vault_id to the same vault should work
        const res = await request('PUT', `/api/items/${item1Id}`, 
            { vault_id: defaultVaultId }, 
            token);
        return res.status === 200;
    });
    updateVaultIdResult ? passed++ : failed++;

    // Test 13: Items are isolated by vault
    const vaultIsolationResult = await test('Items are correctly associated with vault', async () => {
        const res = await request('GET', `/api/items?vault_id=${defaultVaultId}`, null, token);
        if (res.status === 200 && Array.isArray(res.data)) {
            // All items should belong to the default vault
            const allInDefaultVault = res.data.every(item => item.vault_id === defaultVaultId);
            // Should have our test items
            const hasTestItems = res.data.some(item => item.id === item1Id) &&
                                res.data.some(item => item.id === item2Id);
            return allInDefaultVault && hasTestItems;
        }
        return false;
    });
    vaultIsolationResult ? passed++ : failed++;

    // Test 14: Get items with master password and vault filtering
    const getItemsWithPasswordResult = await test('Get items with master password respects vault filter', async () => {
        // First create an item with password
        const createRes = await request('POST', '/api/items', 
            { 
                name: 'Item with Password', 
                description: 'Test item',
                password: 'SecretPassword123',
                masterPassword: password,
                vault_id: defaultVaultId
            }, 
            token);
        
        if (createRes.status === 200) {
            const itemId = createRes.data.id;
            // Get items with master password
            const res = await request('GET', `/api/items?vault_id=${defaultVaultId}&masterPassword=${password}`, null, token);
            if (res.status === 200 && Array.isArray(res.data)) {
                const item = res.data.find(i => i.id === itemId);
                return item && item.password === 'SecretPassword123';
            }
        }
        return false;
    });
    getItemsWithPasswordResult ? passed++ : failed++;

    // Test 15: Verify default vault is created on login (for existing users)
    const loginResult = await test('Login works with vault system', async () => {
        const res = await request('POST', '/api/login', { username, password });
        if (res.status === 200 && res.data.token) {
            token = res.data.token; // Update token
            // Check that vaults are accessible
            const vaultsRes = await request('GET', '/api/vaults', null, token);
            return vaultsRes.status === 200 && vaultsRes.data.length > 0;
        }
        return false;
    });
    loginResult ? passed++ : failed++;

    // Cleanup: Delete test items
    if (item1Id) {
        await request('DELETE', `/api/items/${item1Id}`, null, token);
    }
    if (item2Id) {
        await request('DELETE', `/api/items/${item2Id}`, null, token);
    }

    // Summary
    console.log('\n' + '='.repeat(60));
    console.log(`📊 Results: ${passed} passed, ${failed} failed`);
    console.log('='.repeat(60));

    if (failed === 0) {
        console.log('\n🎉 All vault tests passed!');
        console.log('\n✅ Vault functionality is working correctly:');
        console.log('   - Default vault creation on registration');
        console.log('   - Vault retrieval and listing');
        console.log('   - Items filtered by vault');
        console.log('   - Items associated with correct vault');
        console.log('   - Vault access control');
        console.log('   - Integration with password encryption');
        process.exit(0);
    } else {
        console.log('\n⚠️  Some vault tests failed');
        process.exit(1);
    }
}

// Start tests
runTests().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
});

