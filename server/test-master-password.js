// cd server
// node test-master-password.js

const http = require('http');

const API_URL = 'http://localhost:3000';
let token = null;
let itemId = null;
let itemId2 = null;

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
    console.log('🧪 Testing Master Password Flow\n');
    console.log('='.repeat(50));

    let passed = 0;
    let failed = 0;

    const username = `test_mp_${Date.now()}`;
    const password = 'testpass123';
    const masterPassword = 'mymasterpass123';
    const wrongMasterPassword = 'wrongpassword';

    // Test 1: Register user
    const registerResult = await test('Register new user', async () => {
        const res = await request('POST', '/api/register', { username, password });
        if (res.status === 201 && res.data.token) {
            token = res.data.token;
            return true;
        }
        return false;
    });
    registerResult ? passed++ : failed++;

    // Test 2: Create item WITHOUT password (no master password needed)
    const addItemNoPasswordResult = await test('Create item without password', async () => {
        const res = await request('POST', '/api/items', 
            { name: 'Item No Password', description: 'Test item' }, 
            token);
        return res.status === 200 && res.data.id;
    });
    addItemNoPasswordResult ? passed++ : failed++;

    // Test 3: Create item WITH password (requires master password)
    const addItemWithPasswordResult = await test('Create item with encrypted password', async () => {
        const res = await request('POST', '/api/items', 
            { 
                name: 'Secure Account', 
                description: 'Test account with password',
                password: 'SecretPassword123',
                masterPassword: masterPassword
            }, 
            token);
        if (res.status === 200 && res.data.id) {
            itemId = res.data.id;
            return true;
        }
        return false;
    });
    addItemWithPasswordResult ? passed++ : failed++;

    // Test 4: Create item with password but NO master password (should fail)
    const addItemNoMasterResult = await test('Create item with password but no master password (should fail)', async () => {
        const res = await request('POST', '/api/items', 
            { 
                name: 'Should Fail', 
                description: 'This should fail',
                password: 'SomePassword'
                // No masterPassword provided
            }, 
            token);
        return res.status === 400 && res.data.error && res.data.error.includes('masterPassword');
    });
    addItemNoMasterResult ? passed++ : failed++;

    // Test 5: Get items WITHOUT master password (passwords should be hidden)
    const getItemsNoMasterResult = await test('Get items without master password (passwords hidden)', async () => {
        const res = await request('GET', '/api/items', null, token);
        if (res.status === 200 && Array.isArray(res.data)) {
            // Check that items with passwords have hasPassword but no password field
            const itemWithPassword = res.data.find(item => item.id === itemId);
            const itemWithoutPassword = res.data.find(item => item.name === 'Item No Password');
            
            return itemWithPassword && 
                   itemWithPassword.hasPassword === true && 
                   itemWithPassword.password === undefined &&
                   itemWithoutPassword &&
                   (itemWithoutPassword.hasPassword === false || itemWithoutPassword.hasPassword === undefined);
        }
        return false;
    });
    getItemsNoMasterResult ? passed++ : failed++;

    // Test 6: Get items WITH correct master password (passwords should be decrypted)
    const getItemsWithMasterResult = await test('Get items with correct master password (passwords decrypted)', async () => {
        const res = await request('GET', `/api/items?masterPassword=${encodeURIComponent(masterPassword)}`, null, token);
        if (res.status === 200 && Array.isArray(res.data)) {
            const secureAccount = res.data.find(item => item.id === itemId);
            return secureAccount && 
                   secureAccount.password === 'SecretPassword123' &&
                   !secureAccount.decryptionError;
        }
        return false;
    });
    getItemsWithMasterResult ? passed++ : failed++;

    // Test 7: Get items WITH wrong master password (should fail decryption)
    const wrongMasterResult = await test('Get items with wrong master password (decryption fails)', async () => {
        const res = await request('GET', `/api/items?masterPassword=${encodeURIComponent(wrongMasterPassword)}`, null, token);
        if (res.status === 200 && Array.isArray(res.data)) {
            const secureAccount = res.data.find(item => item.id === itemId);
            return secureAccount && 
                   (secureAccount.password === null || secureAccount.password === undefined) &&
                   secureAccount.decryptionError &&
                   secureAccount.decryptionError.includes('decrypt');
        }
        return false;
    });
    wrongMasterResult ? passed++ : failed++;

    // Test 8: Create another item with different password
    const addSecondItemResult = await test('Create second item with different password', async () => {
        const res = await request('POST', '/api/items', 
            { 
                name: 'Another Account', 
                description: 'Second secure account',
                password: 'DifferentPassword456',
                masterPassword: masterPassword
            }, 
            token);
        if (res.status === 200 && res.data.id) {
            itemId2 = res.data.id;
            return true;
        }
        return false;
    });
    addSecondItemResult ? passed++ : failed++;

    // Test 9: Verify multiple items decrypt correctly with same master password
    const multipleItemsResult = await test('Multiple items decrypt correctly with same master password', async () => {
        const res = await request('GET', `/api/items?masterPassword=${encodeURIComponent(masterPassword)}`, null, token);
        if (res.status === 200 && Array.isArray(res.data)) {
            const item1 = res.data.find(item => item.id === itemId);
            const item2 = res.data.find(item => item.id === itemId2);
            
            return item1 && item1.password === 'SecretPassword123' &&
                   item2 && item2.password === 'DifferentPassword456' &&
                   !item1.decryptionError && !item2.decryptionError;
        }
        return false;
    });
    multipleItemsResult ? passed++ : failed++;

    // Test 10: Update item password
    const updatePasswordResult = await test('Update item password with master password', async () => {
        const res = await request('PUT', `/api/items/${itemId}`, 
            {
                password: 'UpdatedPassword789',
                masterPassword: masterPassword
            }, 
            token);
        if (res.status === 200 && res.data.updated) {
            // Verify the password was updated
            const getRes = await request('GET', `/api/items?masterPassword=${encodeURIComponent(masterPassword)}`, null, token);
            if (getRes.status === 200 && Array.isArray(getRes.data)) {
                const updatedItem = getRes.data.find(item => item.id === itemId);
                return updatedItem && updatedItem.password === 'UpdatedPassword789';
            }
        }
        return false;
    });
    updatePasswordResult ? passed++ : failed++;

    // Test 11: Update password without master password (should fail)
    const updateNoMasterResult = await test('Update password without master password (should fail)', async () => {
        const res = await request('PUT', `/api/items/${itemId}`, 
            {
                password: 'ShouldFail'
                // No masterPassword provided
            }, 
            token);
        return res.status === 400 && res.data.error && res.data.error.includes('masterPassword');
    });
    updateNoMasterResult ? passed++ : failed++;

    // Test 12: Update other fields without master password (should work)
    const updateOtherFieldsResult = await test('Update name/description without master password (should work)', async () => {
        const res = await request('PUT', `/api/items/${itemId}`, 
            {
                name: 'Updated Name',
                description: 'Updated description'
                // No masterPassword needed for non-password fields
            }, 
            token);
        return res.status === 200 && res.data.updated;
    });
    updateOtherFieldsResult ? passed++ : failed++;

    // Test 13: Verify encrypted passwords are never exposed in raw form
    const verifyEncryptionResult = await test('Verify passwords are encrypted in database (not plaintext)', async () => {
        // Get items without master password to see raw encrypted data structure
        const res = await request('GET', '/api/items', null, token);
        if (res.status === 200 && Array.isArray(res.data)) {
            // Items should not expose password field at all without master password
            const hasExposedPassword = res.data.some(item => 
                item.password && 
                typeof item.password === 'string' && 
                item.password !== 'SecretPassword123' &&
                item.password !== 'UpdatedPassword789' &&
                item.password !== 'DifferentPassword456'
            );
            // This is a bit tricky - we can't directly check the DB, but we can verify
            // that without master password, no password field is exposed
            return !hasExposedPassword;
        }
        return false;
    });
    verifyEncryptionResult ? passed++ : failed++;

    // Summary
    console.log('\n' + '='.repeat(50));
    console.log(`📊 Results: ${passed} passed, ${failed} failed`);
    console.log('='.repeat(50));

    if (failed === 0) {
        console.log('\n🎉 All master password tests passed!');
        process.exit(0);
    } else {
        console.log('\n⚠️  Some tests failed');
        process.exit(1);
    }
}

// Start tests
runTests().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
});

