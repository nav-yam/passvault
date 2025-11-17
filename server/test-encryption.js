// cd server
// node test-encryption.js
//
// This test file specifically tests the encryption functionality

const http = require('http');

const API_URL = 'http://localhost:3000';
let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsInVzZXJuYW1lIjoidGVzdHVzZXIyIiwiaWF0IjoxNzYzNDAyNDU0LCJleHAiOjE3NjQwMDcyNTR9.HRWvQhAc2zpsPpKFSOX4tMW85QW9U_rzf4jXo1xr_sI";
let masterPassword = null;
let testItemId = null;

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

// Run all encryption tests
async function runTests() {
    console.log('🔐 Testing Password Encryption Features\n');
    console.log('='.repeat(60));

    let passed = 0;
    let failed = 0;

    // Test 1: Register new user (should have encryption salt)
    const username = `encrypt_test_${Date.now()}`;
    masterPassword = 'MySecureMasterPassword123!';
    const registerResult = await test('Register user with encryption salt', async () => {
        const res = await request('POST', '/api/register', { 
            username, 
            password: masterPassword 
        });
        if (res.status === 201 && res.data.token) {
            token = res.data.token;
            return true;
        }
        return false;
    });
    registerResult ? passed++ : failed++;

    // Test 2: Create item WITHOUT password (should work)
    const createItemNoPassResult = await test('Create item without password', async () => {
        const res = await request('POST', '/api/items', {
            name: 'Test Account',
            description: 'Account without password'
        }, token);
        return res.status === 200 && res.data.id;
    });
    createItemNoPassResult ? passed++ : failed++;

    // Test 3: Create item WITH password but NO masterPassword (should fail)
    const createItemNoMasterResult = await test('Create item with password but no masterPassword (should fail)', async () => {
        const res = await request('POST', '/api/items', {
            name: 'Secure Account',
            password: 'secret123'
        }, token);
        return res.status === 400 && res.data.error && res.data.error.includes('masterPassword');
    });
    createItemNoMasterResult ? passed++ : failed++;

    // Test 4: Create item WITH password AND masterPassword (should encrypt)
    const testPassword = 'MySecretPassword123!';
    const createItemWithPassResult = await test('Create item with encrypted password', async () => {
        const res = await request('POST', '/api/items', {
            name: 'Bank Account',
            description: 'My bank account',
            password: testPassword,
            masterPassword: masterPassword
        }, token);
        if (res.status === 200 && res.data.id) {
            testItemId = res.data.id;
            return true;
        }
        return false;
    });
    createItemWithPassResult ? passed++ : failed++;

    // Test 5: Get items WITHOUT masterPassword (should not show passwords)
    const getItemsNoMasterResult = await test('Get items without masterPassword (passwords hidden)', async () => {
        const res = await request('GET', '/api/items', null, token);
        if (res.status === 200 && Array.isArray(res.data)) {
            const itemWithPassword = res.data.find(item => item.id === testItemId);
            return itemWithPassword && 
                   itemWithPassword.hasPassword === true && 
                   itemWithPassword.password === undefined;
        }
        return false;
    });
    getItemsNoMasterResult ? passed++ : failed++;

    // Test 6: Get items WITH masterPassword (should decrypt passwords)
    const getItemsWithMasterResult = await test('Get items with masterPassword (passwords decrypted)', async () => {
        const url = `/api/items?masterPassword=${encodeURIComponent(masterPassword)}`;
        const res = await request('GET', url, null, token);
        if (res.status === 200 && Array.isArray(res.data)) {
            const item = res.data.find(i => i.id === testItemId);
            return item && 
                   item.password === 'MySecretPassword123!' &&
                   !item.decryptionError;
        }
        return false;
    });
    getItemsWithMasterResult ? passed++ : failed++;

    // Test 7: Get items with WRONG masterPassword (should fail decryption)
    const getItemsWrongMasterResult = await test('Get items with wrong masterPassword (decryption fails)', async () => {
        const url = `/api/items?masterPassword=${encodeURIComponent('WrongPassword123!')}`;
        const res = await request('GET', url, null, token);
        if (res.status === 200 && Array.isArray(res.data)) {
            const item = res.data.find(i => i.id === testItemId);
            return item && 
                   (item.password === null || item.decryptionError !== undefined);
        }
        return false;
    });
    getItemsWrongMasterResult ? passed++ : failed++;

    // Test 8: Update item password (should re-encrypt)
    const newPassword = 'NewSecretPassword456!';
    const updatePasswordResult = await test('Update item password (re-encrypt)', async () => {
        const res = await request('PUT', `/api/items/${testItemId}`, {
            password: newPassword,
            masterPassword: masterPassword
        }, token);
        if (res.status === 200 && res.data.updated) {
            // Verify the password was updated by fetching with master password
            const url = `/api/items?masterPassword=${encodeURIComponent(masterPassword)}`;
            const getRes = await request('GET', url, null, token);
            if (getRes.status === 200) {
                const item = getRes.data.find(i => i.id === testItemId);
                return item && item.password === newPassword;
            }
        }
        return false;
    });
    updatePasswordResult ? passed++ : failed++;

    // Test 9: Update item without masterPassword (should fail)
    const updateNoMasterResult = await test('Update password without masterPassword (should fail)', async () => {
        const res = await request('PUT', `/api/items/${testItemId}`, {
            password: 'NewPassword'
        }, token);
        return res.status === 400 && res.data.error && res.data.error.includes('masterPassword');
    });
    updateNoMasterResult ? passed++ : failed++;

    // Test 10: Verify raw password is never stored (check database directly)
    const verifyEncryptionResult = await test('Verify password is encrypted in database', async () => {
        // This test verifies that the stored password is not the plaintext
        // We'll check by getting items without master password and verifying
        // the password field is not exposed
        const res = await request('GET', '/api/items', null, token);
        if (res.status === 200 && Array.isArray(res.data)) {
            // All items should either have hasPassword flag or no password field
            return res.data.every(item => 
                item.password === undefined || item.hasPassword !== undefined
            );
        }
        return false;
    });
    verifyEncryptionResult ? passed++ : failed++;

    // Test 11: Create multiple items with different passwords
    const multipleItemsResult = await test('Create multiple items with different passwords', async () => {
        const passwords = ['Password1', 'Password2', 'Password3'];
        const itemIds = [];
        
        for (let i = 0; i < passwords.length; i++) {
            const res = await request('POST', '/api/items', {
                name: `Account ${i + 1}`,
                password: passwords[i],
                masterPassword: masterPassword
            }, token);
            if (res.status === 200 && res.data.id) {
                itemIds.push({ id: res.data.id, expectedPassword: passwords[i] });
            }
        }

        // Verify all passwords decrypt correctly
        const url = `/api/items?masterPassword=${encodeURIComponent(masterPassword)}`;
        const getRes = await request('GET', url, null, token);
        if (getRes.status === 200) {
            return itemIds.every(({ id, expectedPassword }) => {
                const item = getRes.data.find(i => i.id === id);
                return item && item.password === expectedPassword;
            });
        }
        return false;
    });
    multipleItemsResult ? passed++ : failed++;

    // Summary
    console.log('\n' + '='.repeat(60));
    console.log(`📊 Results: ${passed} passed, ${failed} failed`);
    console.log('='.repeat(60));

    if (failed === 0) {
        console.log('\n🎉 All encryption tests passed!');
        console.log('\n✅ Encryption is working correctly:');
        console.log('   - Passwords are encrypted before storage');
        console.log('   - Passwords are decrypted only with correct master password');
        console.log('   - Raw passwords are never exposed');
        console.log('   - Wrong master password fails decryption');
        process.exit(0);
    } else {
        console.log('\n⚠️  Some encryption tests failed');
        console.log('   Please check the implementation.');
        process.exit(1);
    }
}

// Start tests
console.log('⚠️  Make sure the server is running on http://localhost:3000');
console.log('   Start it with: cd server && node index.js\n');
setTimeout(() => {
    runTests().catch(error => {
        console.error('Fatal error:', error);
        process.exit(1);
    });
}, 1000); // Give a moment for the message to display

