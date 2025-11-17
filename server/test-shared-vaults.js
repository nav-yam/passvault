const http = require('http');

const API_URL = 'http://localhost:3000';
let ownerToken = null;
let ownerUserId = null;
let memberToken = null;
let memberUserId = null;
let sharedVaultId = null;
const ownerMasterPassword = 'owner_master_123';
const memberMasterPassword = 'member_master_456';

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

async function runTests() {
    console.log('🧪 Testing Shared Vaults Functionality\n');
    console.log('='.repeat(60));

    let passed = 0;
    let failed = 0;

    const ownerUsername = `owner_${Date.now()}`;
    const memberUsername = `member_${Date.now()}`;
    const ownerPassword = 'owner123';
    const memberPassword = 'member123';

    const ownerRegister = await test('Register owner user', async () => {
        const res = await request('POST', '/api/register', { username: ownerUsername, password: ownerPassword });
        if (res.status === 201 && res.data.token) {
            ownerToken = res.data.token;
            ownerUserId = res.data.user.id;
            return true;
        }
        return false;
    });
    ownerRegister ? passed++ : failed++;

    const memberRegister = await test('Register member user', async () => {
        const res = await request('POST', '/api/register', { username: memberUsername, password: memberPassword });
        if (res.status === 201 && res.data.token) {
            memberToken = res.data.token;
            memberUserId = res.data.user.id;
            return true;
        }
        return false;
    });
    memberRegister ? passed++ : failed++;

    const createVault = await test('Owner creates shared vault', async () => {
        const res = await request('POST', '/api/vaults', {
            name: 'Shared Team Vault',
            masterPassword: ownerMasterPassword
        }, ownerToken);
        if (res.status === 200 && res.data.id) {
            sharedVaultId = res.data.id;
            return true;
        }
        return false;
    });
    createVault ? passed++ : failed++;

    const addItemToVault = await test('Owner adds item to shared vault', async () => {
        const res = await request('POST', '/api/items', {
            name: 'Shared Password',
            description: 'Username: shared_user | Notes: Team password',
            password: 'shared_password_123',
            masterPassword: ownerMasterPassword,
            vault_id: sharedVaultId
        }, ownerToken);
        return res.status === 200 && res.data.id;
    });
    addItemToVault ? passed++ : failed++;

    const memberCannotAccess = await test('Member cannot access vault before being added', async () => {
        const res = await request('GET', `/api/items?vault_id=${sharedVaultId}`, null, memberToken);
        return res.status === 403;
    });
    memberCannotAccess ? passed++ : failed++;

    const addMember = await test('Owner adds member to vault', async () => {
        const res = await request('POST', `/api/vaults/${sharedVaultId}/members`, {
            username: memberUsername,
            ownerMasterPassword: ownerMasterPassword,
            memberMasterPassword: memberMasterPassword
        }, ownerToken);
        return res.status === 200 && res.data.success;
    });
    addMember ? passed++ : failed++;

    const memberCanAccess = await test('Member can access vault after being added', async () => {
        const res = await request('GET', `/api/items?vault_id=${sharedVaultId}`, null, memberToken);
        return res.status === 200 && Array.isArray(res.data);
    });
    memberCanAccess ? passed++ : failed++;

    const memberCanDecrypt = await test('Member can decrypt items with their master password', async () => {
        const res = await request('GET', `/api/items?vault_id=${sharedVaultId}&masterPassword=${encodeURIComponent(memberMasterPassword)}`, null, memberToken);
        if (res.status === 200 && res.data.length > 0) {
            const item = res.data[0];
            return item.password === 'shared_password_123' && !item.decryptionError;
        }
        return false;
    });
    memberCanDecrypt ? passed++ : failed++;

    const memberCanAddItem = await test('Member can add item to shared vault', async () => {
        const res = await request('POST', '/api/items', {
            name: 'Member Added Item',
            description: 'Username: member_user',
            password: 'member_item_pass',
            masterPassword: memberMasterPassword,
            vault_id: sharedVaultId
        }, memberToken);
        return res.status === 200 && res.data.id;
    });
    memberCanAddItem ? passed++ : failed++;

    const ownerCanSeeMemberItem = await test('Owner can see member-added item', async () => {
        const res = await request('GET', `/api/items?vault_id=${sharedVaultId}&masterPassword=${encodeURIComponent(ownerMasterPassword)}`, null, ownerToken);
        if (res.status === 200) {
            const memberItem = res.data.find(item => item.name === 'Member Added Item');
            return memberItem && memberItem.password === 'member_item_pass';
        }
        return false;
    });
    ownerCanSeeMemberItem ? passed++ : failed++;

    const listMembers = await test('Owner can list vault members', async () => {
        const res = await request('GET', `/api/vaults/${sharedVaultId}/members`, null, ownerToken);
        if (res.status === 200 && Array.isArray(res.data)) {
            return res.data.length === 1 && res.data[0].username === memberUsername;
        }
        return false;
    });
    listMembers ? passed++ : failed++;

    const memberSeesSharedVault = await test('Member sees shared vault in vault list', async () => {
        const res = await request('GET', '/api/vaults', null, memberToken);
        if (res.status === 200 && Array.isArray(res.data)) {
            const sharedVault = res.data.find(v => v.id === sharedVaultId);
            return sharedVault !== undefined;
        }
        return false;
    });
    memberSeesSharedVault ? passed++ : failed++;

    const removeMember = await test('Owner can remove member from vault', async () => {
        const res = await request('DELETE', `/api/vaults/${sharedVaultId}/members/${memberUserId}`, null, ownerToken);
        return res.status === 200 && res.data.success;
    });
    removeMember ? passed++ : failed++;

    const memberCannotAccessAfterRemoval = await test('Member cannot access vault after removal', async () => {
        const res = await request('GET', `/api/items?vault_id=${sharedVaultId}`, null, memberToken);
        return res.status === 403;
    });
    memberCannotAccessAfterRemoval ? passed++ : failed++;

    const memberCannotAddAfterRemoval = await test('Member cannot add items after removal', async () => {
        const res = await request('POST', '/api/items', {
            name: 'Should Fail',
            vault_id: sharedVaultId
        }, memberToken);
        return res.status === 403;
    });
    memberCannotAddAfterRemoval ? passed++ : failed++;

    const nonOwnerCannotAddMember = await test('Non-owner cannot add members', async () => {
        const res = await request('POST', `/api/vaults/${sharedVaultId}/members`, {
            username: 'someuser',
            ownerMasterPassword: ownerMasterPassword,
            memberMasterPassword: 'pass'
        }, memberToken);
        return res.status === 403;
    });
    nonOwnerCannotAddMember ? passed++ : failed++;

    const invalidMasterPassword = await test('Invalid master password fails decryption', async () => {
        const res = await request('GET', `/api/items?vault_id=${sharedVaultId}&masterPassword=${encodeURIComponent('wrong_password')}`, null, ownerToken);
        if (res.status === 200 && res.data.length > 0) {
            return res.data.some(item => item.decryptionError);
        }
        return false;
    });
    invalidMasterPassword ? passed++ : failed++;

    const updateItemInSharedVault = await test('Member can update item in shared vault', async () => {
        const res = await request('GET', `/api/items?vault_id=${sharedVaultId}&masterPassword=${encodeURIComponent(ownerMasterPassword)}`, null, ownerToken);
        if (res.status === 200 && res.data.length > 0) {
            const itemId = res.data[0].id;
            const updateRes = await request('PUT', `/api/items/${itemId}`, {
                name: 'Updated Name',
                masterPassword: ownerMasterPassword
            }, ownerToken);
            return updateRes.status === 200;
        }
        return false;
    });
    updateItemInSharedVault ? passed++ : failed++;

    const deleteItemInSharedVault = await test('Member can delete item in shared vault', async () => {
        const res = await request('GET', `/api/items?vault_id=${sharedVaultId}&masterPassword=${encodeURIComponent(ownerMasterPassword)}`, null, ownerToken);
        if (res.status === 200 && res.data.length > 0) {
            const itemId = res.data[res.data.length - 1].id;
            const deleteRes = await request('DELETE', `/api/items/${itemId}`, null, ownerToken);
            return deleteRes.status === 200;
        }
        return false;
    });
    deleteItemInSharedVault ? passed++ : failed++;

    console.log('\n' + '='.repeat(60));
    console.log(`\n📊 Results: ${passed} passed, ${failed} failed\n`);

    if (failed === 0) {
        console.log('🎉 All shared vault tests passed!');
        process.exit(0);
    } else {
        console.log('⚠️  Some tests failed');
        process.exit(1);
    }
}

runTests().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
});

