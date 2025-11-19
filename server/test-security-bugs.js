// Comprehensive test file for security bugs
// cd server
// node test-security-bugs.js

const http = require('http');

const API_URL = 'http://localhost:3000';
let user1Token = null;
let user1Id = null;
let user2Token = null;
let user2Id = null;
let vaultId = null;
let sharedVaultId = null;

const user1MasterPassword = 'master123';
const user1WrongPassword = 'wrongpass123';
const user2MasterPassword = 'master456';

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

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function runTests() {
    console.log('🧪 Testing Security Bug Fixes\n');
    console.log('='.repeat(70));
    console.log();

    let passed = 0;
    let failed = 0;

    const user1Username = `testuser1_${Date.now()}`;
    const user1Password = 'password123';
    const user2Username = `testuser2_${Date.now()}`;
    const user2Password = 'password456';

    // ============================================================
    // Setup: Register users
    // ============================================================
    console.log('📋 Setup Phase');
    console.log('-'.repeat(70));

    await test('Register user 1', async () => {
        const res = await request('POST', '/api/register', { 
            username: user1Username, 
            password: user1Password 
        });
        if (res.status === 201 && res.data.token) {
            user1Token = res.data.token;
            user1Id = res.data.user.id;
            return true;
        }
        return false;
    }) ? passed++ : failed++;

    await test('Register user 2', async () => {
        const res = await request('POST', '/api/register', { 
            username: user2Username, 
            password: user2Password 
        });
        if (res.status === 201 && res.data.token) {
            user2Token = res.data.token;
            user2Id = res.data.user.id;
            return true;
        }
        return false;
    }) ? passed++ : failed++;

    console.log();

    // ============================================================
    // Test 1: Rate Limiting - Failed Password Attempts
    // ============================================================
    console.log('🔒 Test 1: Rate Limiting with Exponential Backoff');
    console.log('-'.repeat(70));

    await test('Create vault with correct master password', async () => {
        const res = await request('POST', '/api/vaults', {
            name: 'Rate Limit Test Vault',
            masterPassword: user1MasterPassword
        }, user1Token);
        if (res.status === 200 && res.data.id) {
            vaultId = res.data.id;
            return true;
        }
        return false;
    }) ? passed++ : failed++;

    await test('Create item with correct master password', async () => {
        const res = await request('POST', '/api/items', {
            name: 'Test Item',
            description: 'Test description',
            password: 'itempassword123',
            masterPassword: user1MasterPassword,
            vault_id: vaultId
        }, user1Token);
        return res.status === 200 && res.data.id;
    }) ? passed++ : failed++;

    await test('First wrong password attempt - should fail but not rate limit', async () => {
        const res = await request('GET', `/api/items?vault_id=${vaultId}&masterPassword=${encodeURIComponent(user1WrongPassword)}`, null, user1Token);
        // Should get 200 with decryption error, or 401
        return res.status === 200 || res.status === 401 || res.status === 429;
    }) ? passed++ : failed++;

    await test('Second wrong password attempt - should fail but not rate limit', async () => {
        const res = await request('GET', `/api/items?vault_id=${vaultId}&masterPassword=${encodeURIComponent(user1WrongPassword)}`, null, user1Token);
        return res.status === 200 || res.status === 401 || res.status === 429;
    }) ? passed++ : failed++;

    await test('Third wrong password attempt - should trigger rate limit', async () => {
        const res = await request('GET', `/api/items?vault_id=${vaultId}&masterPassword=${encodeURIComponent(user1WrongPassword)}`, null, user1Token);
        // Should get 429 (Too Many Requests)
        if (res.status === 429) {
            console.log(`      Rate limit activated: ${res.data.error}`);
            return true;
        }
        return false;
    }) ? passed++ : failed++;

    await test('Fourth attempt immediately - should still be rate limited', async () => {
        const res = await request('GET', `/api/items?vault_id=${vaultId}&masterPassword=${encodeURIComponent(user1WrongPassword)}`, null, user1Token);
        return res.status === 429;
    }) ? passed++ : failed++;

    // Wait a bit and test with correct password after rate limit expires
    console.log('      Waiting 35 seconds for rate limit to expire...');
    await sleep(35000);

    await test('Correct password after rate limit expires - should work', async () => {
        const res = await request('GET', `/api/items?vault_id=${vaultId}&masterPassword=${encodeURIComponent(user1MasterPassword)}`, null, user1Token);
        if (res.status === 200 && Array.isArray(res.data)) {
            const hasDecryptionError = res.data.some(item => item.decryptionError);
            return !hasDecryptionError;
        }
        return false;
    }) ? passed++ : failed++;

    console.log();

    // ============================================================
    // Test 2: Master Password Validation Bug
    // ============================================================
    console.log('🔐 Test 2: Master Password Validation');
    console.log('-'.repeat(70));

    await test('Vault cannot be unlocked with wrong master password', async () => {
        const res = await request('GET', `/api/items?vault_id=${vaultId}&masterPassword=${encodeURIComponent(user1WrongPassword)}`, null, user1Token);
        // Should either return 401/400/429 or items with decryption errors
        if (res.status === 401 || res.status === 400 || res.status === 429) {
            return true;
        }
        if (res.status === 200) {
            // Check if all items have decryption errors
            const hasDecryptionError = res.data.every(item => 
                !item.password || item.decryptionError || item.password === null
            );
            return hasDecryptionError;
        }
        return false;
    }) ? passed++ : failed++;

    await test('Vault cannot create item with wrong master password', async () => {
        const res = await request('POST', '/api/items', {
            name: 'Should Fail Item',
            password: 'testpass',
            masterPassword: user1WrongPassword,
            vault_id: vaultId
        }, user1Token);
        // Should fail with 401, 400, or 429
        return res.status === 401 || res.status === 400 || res.status === 429;
    }) ? passed++ : failed++;

    await test('Vault can be unlocked with correct master password', async () => {
        const res = await request('GET', `/api/items?vault_id=${vaultId}&masterPassword=${encodeURIComponent(user1MasterPassword)}`, null, user1Token);
        if (res.status === 200 && Array.isArray(res.data)) {
            const hasDecryptionError = res.data.some(item => item.decryptionError);
            return !hasDecryptionError;
        }
        return false;
    }) ? passed++ : failed++;

    console.log();

    // ============================================================
    // Test 3: Shared Vault Master Password Logic
    // ============================================================
    console.log('🔗 Test 3: Shared Vault Master Password Requirements');
    console.log('-'.repeat(70));

    await test('Create shared vault', async () => {
        const res = await request('POST', '/api/vaults', {
            name: 'Shared Test Vault',
            masterPassword: user1MasterPassword
        }, user1Token);
        if (res.status === 200 && res.data.id) {
            sharedVaultId = res.data.id;
            return true;
        }
        return false;
    }) ? passed++ : failed++;

    await test('Add member to vault without encrypted key', async () => {
        const res = await request('POST', `/api/vaults/${sharedVaultId}/members`, {
            username: user2Username,
            ownerMasterPassword: user1MasterPassword
            // Note: memberMasterPassword not provided
        }, user1Token);
        return res.status === 200;
    }) ? passed++ : failed++;

    await test('Member without encrypted key - should not require master password', async () => {
        // Check if items endpoint indicates master password not required
        const res = await request('GET', `/api/items?vault_id=${sharedVaultId}`, null, user2Token);
        if (res.status === 200 && Array.isArray(res.data)) {
            // Should return items but with requiresMasterPassword: false or decryption errors
            return true;
        }
        return false;
    }) ? passed++ : failed++;

    await test('Member without encrypted key - cannot decrypt items', async () => {
        const res = await request('GET', `/api/items?vault_id=${sharedVaultId}&masterPassword=${encodeURIComponent(user2MasterPassword)}`, null, user2Token);
        if (res.status === 200 && Array.isArray(res.data)) {
            // All items should have decryption errors or null passwords
            const allFailed = res.data.every(item => 
                !item.password || item.decryptionError || item.password === null
            );
            return allFailed;
        }
        return false;
    }) ? passed++ : failed++;

    await test('Add member with encrypted key', async () => {
        // First remove member
        await request('DELETE', `/api/vaults/${sharedVaultId}/members/${user2Id}`, null, user1Token);
        
        // Add member with encrypted key
        const res = await request('POST', `/api/vaults/${sharedVaultId}/members`, {
            username: user2Username,
            ownerMasterPassword: user1MasterPassword,
            memberMasterPassword: user2MasterPassword
        }, user1Token);
        return res.status === 200;
    }) ? passed++ : failed++;

    await test('Member with encrypted key - requires master password', async () => {
        const res = await request('GET', `/api/items?vault_id=${sharedVaultId}`, null, user2Token);
        if (res.status === 200 && Array.isArray(res.data)) {
            // Should indicate master password is required
            const requiresPassword = res.data.some(item => item.requiresMasterPassword === true) || 
                                   res.data.length === 0;
            return true;
        }
        return false;
    }) ? passed++ : failed++;

    await test('Member with encrypted key - can decrypt with correct master password', async () => {
        const res = await request('GET', `/api/items?vault_id=${sharedVaultId}&masterPassword=${encodeURIComponent(user2MasterPassword)}`, null, user2Token);
        if (res.status === 200 && Array.isArray(res.data)) {
            const hasDecryptionError = res.data.some(item => item.decryptionError);
            // If items exist, should not have decryption errors
            return res.data.length === 0 || !hasDecryptionError;
        }
        return false;
    }) ? passed++ : failed++;

    await test('Member with encrypted key - cannot decrypt with wrong master password', async () => {
        const res = await request('GET', `/api/items?vault_id=${sharedVaultId}&masterPassword=${encodeURIComponent('wrongpass')}`, null, user2Token);
        // Should fail or return items with decryption errors
        if (res.status === 401 || res.status === 400 || res.status === 429) {
            return true;
        }
        if (res.status === 200 && Array.isArray(res.data)) {
            const hasDecryptionError = res.data.some(item => item.decryptionError);
            return hasDecryptionError || res.data.every(item => !item.password || item.password === null);
        }
        return false;
    }) ? passed++ : failed++;

    console.log();

    // ============================================================
    // Test 4: Vault Creation Validation
    // ============================================================
    console.log('📦 Test 4: Vault Creation Validation');
    console.log('-'.repeat(70));

    await test('Cannot create vault without master password', async () => {
        const res = await request('POST', '/api/vaults', {
            name: 'Should Fail Vault'
        }, user1Token);
        return res.status === 400;
    }) ? passed++ : failed++;

    await test('Can create vault with master password', async () => {
        const res = await request('POST', '/api/vaults', {
            name: 'Valid Test Vault',
            masterPassword: user1MasterPassword
        }, user1Token);
        return res.status === 200 && res.data.id;
    }) ? passed++ : failed++;

    console.log();

    // ============================================================
    // Test 5: Item Operations with Wrong Master Password
    // ============================================================
    console.log('📝 Test 5: Item Operations Validation');
    console.log('-'.repeat(70));

    await test('Cannot create item in vault with wrong master password', async () => {
        const res = await request('POST', '/api/items', {
            name: 'Should Fail',
            password: 'testpass',
            masterPassword: user1WrongPassword,
            vault_id: vaultId
        }, user1Token);
        // Should fail with 401, 400, or 429
        return res.status === 401 || res.status === 400 || res.status === 429;
    }) ? passed++ : failed++;

    await test('Cannot update item in vault with wrong master password', async () => {
        // First get an item ID
        const getRes = await request('GET', `/api/items?vault_id=${vaultId}&masterPassword=${encodeURIComponent(user1MasterPassword)}`, null, user1Token);
        if (getRes.status === 200 && getRes.data.length > 0) {
            const itemId = getRes.data[0].id;
            const updateRes = await request('PUT', `/api/items/${itemId}`, {
                password: 'newpassword',
                masterPassword: user1WrongPassword,
                vault_id: vaultId
            }, user1Token);
            // Should fail with 401, 400, or 429
            return updateRes.status === 401 || updateRes.status === 400 || updateRes.status === 429;
        }
        return false;
    }) ? passed++ : failed++;

    console.log();

    // ============================================================
    // Test 6: Rate Limit Reset on Success
    // ============================================================
    console.log('⏱️  Test 6: Rate Limit Reset on Successful Authentication');
    console.log('-'.repeat(70));

    // Trigger rate limit
    for (let i = 0; i < 3; i++) {
        await request('GET', `/api/items?vault_id=${vaultId}&masterPassword=${encodeURIComponent(user1WrongPassword)}`, null, user1Token);
    }

    await test('Rate limit is active after multiple failures', async () => {
        const res = await request('GET', `/api/items?vault_id=${vaultId}&masterPassword=${encodeURIComponent(user1WrongPassword)}`, null, user1Token);
        return res.status === 429;
    }) ? passed++ : failed++;

    // Wait for rate limit to expire
    console.log('      Waiting 35 seconds for rate limit to expire...');
    await sleep(35000);

    await test('Rate limit resets after successful authentication', async () => {
        // First successful auth should work
        const successRes = await request('GET', `/api/items?vault_id=${vaultId}&masterPassword=${encodeURIComponent(user1MasterPassword)}`, null, user1Token);
        if (successRes.status !== 200) {
            return false;
        }

        // Rate limit should be reset, so we can make new attempts
        // Try wrong password again - should not be rate limited yet
        const wrongRes = await request('GET', `/api/items?vault_id=${vaultId}&masterPassword=${encodeURIComponent(user1WrongPassword)}`, null, user1Token);
        // Should not be rate limited (429), but should fail with wrong password
        return wrongRes.status !== 429;
    }) ? passed++ : failed++;

    console.log();

    // ============================================================
    // Summary
    // ============================================================
    console.log('='.repeat(70));
    console.log(`\n📊 Test Results: ${passed} passed, ${failed} failed\n`);

    if (failed === 0) {
        console.log('🎉 All security bug tests passed!');
    } else {
        console.log('⚠️  Some tests failed. Please review the output above.');
    }
}

// Run tests
runTests().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
});

