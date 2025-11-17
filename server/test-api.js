// cd server
// node test-api.js

const http = require('http');

const API_URL = 'http://localhost:3000';
let token = null;

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
    console.log('🧪 Testing API Endpoints\n');
    console.log('='.repeat(50));

    let passed = 0;
    let failed = 0;

    // Test 1: Ping
    const pingResult = await test('Ping /api/ping', async () => {
        const res = await request('GET', '/api/ping');
        return res.status === 200 && res.data.message === 'pong';
    });
    pingResult ? passed++ : failed++;

    // Test 2: Register
    const username = `testuser_${Date.now()}`;
    const password = 'password123';
    const registerResult = await test('Register new user', async () => {
        const res = await request('POST', '/api/register', { username, password });
        if (res.status === 201 && res.data.token) {
            token = res.data.token;
            return true;
        }
        return false;
    });
    registerResult ? passed++ : failed++;

    // Test 3: Register duplicate (should fail)
    const duplicateResult = await test('Register duplicate (should fail)', async () => {
        const res = await request('POST', '/api/register', { username, password });
        return res.status === 409;
    });
    duplicateResult ? passed++ : failed++;

    // Test 4: Login
    const loginResult = await test('Login', async () => {
        const res = await request('POST', '/api/login', { username, password });
        if (res.status === 200 && res.data.token) {
            token = res.data.token;
            return true;
        }
        return false;
    });
    loginResult ? passed++ : failed++;

    // Test 5: Login wrong password (should fail)
    const wrongPassResult = await test('Login wrong password (should fail)', async () => {
        const res = await request('POST', '/api/login', { username, password: 'wrong' });
        return res.status === 401;
    });
    wrongPassResult ? passed++ : failed++;

    // Test 6: Get items without token (should fail)
    const noTokenResult = await test('Get items without token (should fail)', async () => {
        const res = await request('GET', '/api/items');
        return res.status === 401;
    });
    noTokenResult ? passed++ : failed++;

    // Test 7: Get items with token
    const getItemsResult = await test('Get items with token', async () => {
        const res = await request('GET', '/api/items', null, token);
        return res.status === 200;
    });
    getItemsResult ? passed++ : failed++;

    // Test 8: Add item
    const addItemResult = await test('Add item', async () => {
        const res = await request('POST', '/api/items', 
            { name: 'Test Item', description: 'Test description' }, 
            token);
        return res.status === 200 && res.data.id;
    });
    addItemResult ? passed++ : failed++;

    // Test 9: Get items again (should have the item)
    const getItemsAgainResult = await test('Get items after adding', async () => {
        const res = await request('GET', '/api/items', null, token);
        return res.status === 200 && Array.isArray(res.data) && res.data.length > 0;
    });
    getItemsAgainResult ? passed++ : failed++;

    // Test 10: Delete item
    let itemId = null;
    const getItemsForDelete = await request('GET', '/api/items', null, token);
    if (getItemsForDelete.status === 200 && getItemsForDelete.data.length > 0) {
        itemId = getItemsForDelete.data[0].id;
        const deleteResult = await test('Delete item', async () => {
            const res = await request('DELETE', `/api/items/${itemId}`, null, token);
            return res.status === 200;
        });
        deleteResult ? passed++ : failed++;
    }

    // Summary
    console.log('\n' + '='.repeat(50));
    console.log(`📊 Results: ${passed} passed, ${failed} failed`);
    console.log('='.repeat(50));

    if (failed === 0) {
        console.log('\n🎉 All tests passed!');
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