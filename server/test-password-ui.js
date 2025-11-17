// cd server
// node test-password-ui.js
//
// Tests for improved password UI features:
// - Website/Username/Notes format
// - Structured description parsing
// - Password item creation with new fields

const http = require('http');

const API_URL = 'http://localhost:3000';
let token = null;
let itemIds = [];

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

// Helper function to parse description (matches client-side logic)
function parseItemDescription(description) {
    if (!description) return { username: '', notes: '' };
    
    const usernameMatch = description.match(/Username:\s*(.+?)(?:\s*\||$)/i);
    const notesMatch = description.match(/Notes:\s*(.+?)$/i);
    
    if (usernameMatch || notesMatch) {
        return {
            username: usernameMatch ? usernameMatch[1].trim() : '',
            notes: notesMatch ? notesMatch[1].trim() : ''
        };
    }
    
    return { username: '', notes: description };
}

// Helper function to format description (matches client-side logic)
function formatItemDescription(username, notes) {
    const parts = [];
    if (username) parts.push(`Username: ${username}`);
    if (notes) parts.push(`Notes: ${notes}`);
    return parts.join(' | ') || '';
}

// Run all tests
async function runTests() {
    console.log('🧪 Testing Password UI Features\n');
    console.log('='.repeat(50));

    let passed = 0;
    let failed = 0;

    const username = `test_ui_${Date.now()}`;
    const password = 'testpass123';
    const masterPassword = 'mymasterpass123';

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

    // Test 2: Create item with website, username, password, and notes
    let itemId1 = null;
    const createFullItemResult = await test('Create item with website, username, password, notes', async () => {
        const website = 'github.com';
        const username = 'testuser@example.com';
        const itemPassword = 'SecurePass123!';
        const notes = 'Personal GitHub account';
        
        const description = formatItemDescription(username, notes);
        
        const res = await request('POST', '/api/items', {
            name: website,
            description: description,
            password: itemPassword,
            masterPassword: masterPassword
        }, token);
        
        if (res.status === 200 && res.data.id) {
            itemId1 = res.data.id;
            itemIds.push(itemId1);
            return true;
        }
        return false;
    });
    createFullItemResult ? passed++ : failed++;

    // Test 3: Verify item can be retrieved and parsed correctly
    const verifyParsingResult = await test('Verify item description parsing (username and notes)', async () => {
        const res = await request('GET', `/api/items?masterPassword=${encodeURIComponent(masterPassword)}`, null, token);
        if (res.status === 200 && Array.isArray(res.data)) {
            const item = res.data.find(i => i.id === itemId1);
            if (item) {
                const parsed = parseItemDescription(item.description);
                return parsed.username === 'testuser@example.com' && 
                       parsed.notes === 'Personal GitHub account' &&
                       item.name === 'github.com';
            }
        }
        return false;
    });
    verifyParsingResult ? passed++ : failed++;

    // Test 4: Create item with only website and password (no username/notes)
    let itemId2 = null;
    const createMinimalItemResult = await test('Create item with only website and password', async () => {
        const res = await request('POST', '/api/items', {
            name: 'gmail.com',
            description: '',
            password: 'EmailPass456!',
            masterPassword: masterPassword
        }, token);
        
        if (res.status === 200 && res.data.id) {
            itemId2 = res.data.id;
            itemIds.push(itemId2);
            return true;
        }
        return false;
    });
    createMinimalItemResult ? passed++ : failed++;

    // Test 5: Verify minimal item parsing (empty username/notes)
    const verifyMinimalParsingResult = await test('Verify minimal item parsing (empty username/notes)', async () => {
        const res = await request('GET', `/api/items?masterPassword=${encodeURIComponent(masterPassword)}`, null, token);
        if (res.status === 200 && Array.isArray(res.data)) {
            const item = res.data.find(i => i.id === itemId2);
            if (item) {
                const parsed = parseItemDescription(item.description);
                return parsed.username === '' && 
                       parsed.notes === '' &&
                       item.name === 'gmail.com';
            }
        }
        return false;
    });
    verifyMinimalParsingResult ? passed++ : failed++;

    // Test 6: Create item with username but no notes
    let itemId3 = null;
    const createUsernameOnlyResult = await test('Create item with username but no notes', async () => {
        const description = formatItemDescription('admin@site.com', '');
        const res = await request('POST', '/api/items', {
            name: 'example.com',
            description: description,
            password: 'AdminPass789!',
            masterPassword: masterPassword
        }, token);
        
        if (res.status === 200 && res.data.id) {
            itemId3 = res.data.id;
            itemIds.push(itemId3);
            return true;
        }
        return false;
    });
    createUsernameOnlyResult ? passed++ : failed++;

    // Test 7: Verify username-only item parsing
    const verifyUsernameOnlyResult = await test('Verify username-only item parsing', async () => {
        const res = await request('GET', `/api/items?masterPassword=${encodeURIComponent(masterPassword)}`, null, token);
        if (res.status === 200 && Array.isArray(res.data)) {
            const item = res.data.find(i => i.id === itemId3);
            if (item) {
                const parsed = parseItemDescription(item.description);
                return parsed.username === 'admin@site.com' && 
                       parsed.notes === '';
            }
        }
        return false;
    });
    verifyUsernameOnlyResult ? passed++ : failed++;

    // Test 8: Create item with notes but no username
    let itemId4 = null;
    const createNotesOnlyResult = await test('Create item with notes but no username', async () => {
        const description = formatItemDescription('', 'This is a test account');
        const res = await request('POST', '/api/items', {
            name: 'test.com',
            description: description,
            password: 'TestPass123!',
            masterPassword: masterPassword
        }, token);
        
        if (res.status === 200 && res.data.id) {
            itemId4 = res.data.id;
            itemIds.push(itemId4);
            return true;
        }
        return false;
    });
    createNotesOnlyResult ? passed++ : failed++;

    // Test 9: Verify notes-only item parsing
    const verifyNotesOnlyResult = await test('Verify notes-only item parsing', async () => {
        const res = await request('GET', `/api/items?masterPassword=${encodeURIComponent(masterPassword)}`, null, token);
        if (res.status === 200 && Array.isArray(res.data)) {
            const item = res.data.find(i => i.id === itemId4);
            if (item) {
                const parsed = parseItemDescription(item.description);
                return parsed.username === '' && 
                       parsed.notes === 'This is a test account';
            }
        }
        return false;
    });
    verifyNotesOnlyResult ? passed++ : failed++;

    // Test 10: Update item with new username and notes
    const updateItemResult = await test('Update item username and notes', async () => {
        const newDescription = formatItemDescription('newuser@example.com', 'Updated notes');
        const res = await request('PUT', `/api/items/${itemId1}`, {
            description: newDescription
        }, token);
        
        if (res.status === 200 && res.data.updated) {
            // Verify update
            const getRes = await request('GET', `/api/items?masterPassword=${encodeURIComponent(masterPassword)}`, null, token);
            if (getRes.status === 200 && Array.isArray(getRes.data)) {
                const item = getRes.data.find(i => i.id === itemId1);
                if (item) {
                    const parsed = parseItemDescription(item.description);
                    return parsed.username === 'newuser@example.com' && 
                           parsed.notes === 'Updated notes';
                }
            }
        }
        return false;
    });
    updateItemResult ? passed++ : failed++;

    // Test 11: Verify items without master password hide passwords but show structure
    const verifyHiddenPasswordsResult = await test('Verify items without master password hide passwords', async () => {
        const res = await request('GET', '/api/items', null, token);
        if (res.status === 200 && Array.isArray(res.data)) {
            const item = res.data.find(i => i.id === itemId1);
            return item && 
                   item.hasPassword === true && 
                   item.password === undefined &&
                   item.name === 'github.com';
        }
        return false;
    });
    verifyHiddenPasswordsResult ? passed++ : failed++;

    // Test 12: Verify multiple items with different structures
    const verifyMultipleItemsResult = await test('Verify multiple items with different structures', async () => {
        const res = await request('GET', `/api/items?masterPassword=${encodeURIComponent(masterPassword)}`, null, token);
        if (res.status === 200 && Array.isArray(res.data)) {
            const items = res.data.filter(i => itemIds.includes(i.id));
            return items.length === 4 &&
                   items.every(item => item.name && item.password);
        }
        return false;
    });
    verifyMultipleItemsResult ? passed++ : failed++;

    // Cleanup: Delete test items
    for (const id of itemIds) {
        await request('DELETE', `/api/items/${id}`, null, token);
    }

    // Summary
    console.log('\n' + '='.repeat(50));
    console.log(`📊 Results: ${passed} passed, ${failed} failed`);
    console.log('='.repeat(50));

    if (failed === 0) {
        console.log('\n🎉 All password UI tests passed!');
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

