const http = require('http');
const crypto = require('crypto');

const API_URL = 'http://localhost:3000';
let ownerToken = null;
let memberToken = null;
let sharedVaultId = null;
let inviteCode = null;
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
    console.log('🧪 Testing Invite Code Flow\n');

    const ownerUsername = `owner_inv_${Date.now()}`;
    const memberUsername = `member_inv_${Date.now()}`;
    const ownerPassword = 'owner123';
    const memberPassword = 'member123';

    await test('Register owner', async () => {
        const res = await request('POST', '/api/register', { username: ownerUsername, password: ownerPassword });
        if (res.status === 201) {
            ownerToken = res.data.token;
            return true;
        }
        return false;
    });

    await test('Register member', async () => {
        const res = await request('POST', '/api/register', { username: memberUsername, password: memberPassword });
        if (res.status === 201) {
            memberToken = res.data.token;
            return true;
        }
        return false;
    });

    await test('Owner creates shared vault', async () => {
        const res = await request('POST', '/api/vaults', {
            name: 'Invite Flow Vault',
            masterPassword: ownerMasterPassword
        }, ownerToken);
        if (res.status === 200) {
            sharedVaultId = res.data.id;
            return true;
        }
        return false;
    });

    await test('Owner adds member and gets Invite Code', async () => {
        const res = await request('POST', `/api/vaults/${sharedVaultId}/members`, {
            username: memberUsername,
            ownerMasterPassword: ownerMasterPassword
        }, ownerToken);
        
        if (res.status === 200 && res.data.inviteCode) {
            inviteCode = res.data.inviteCode;
            console.log(`   🔑 Received Invite Code: ${inviteCode}`);
            return true;
        }
        console.log('   ❌ No invite code returned:', res.data);
        return false;
    });

    await test('Member sees vault as Pending', async () => {
        const res = await request('GET', '/api/vaults', null, memberToken);
        if (res.status === 200) {
            const vault = res.data.find(v => v.id === sharedVaultId);
            return vault && vault.is_pending === true;
        }
        return false;
    });

    await test('Member accepts invite', async () => {
        const res = await request('POST', `/api/vaults/${sharedVaultId}/accept-invite`, {
            inviteCode: inviteCode,
            masterPassword: memberMasterPassword
        }, memberToken);
        
        return res.status === 200 && res.data.success;
    });

    await test('Member sees vault as Active (not pending)', async () => {
        const res = await request('GET', '/api/vaults', null, memberToken);
        if (res.status === 200) {
            const vault = res.data.find(v => v.id === sharedVaultId);
            return vault && !vault.is_pending;
        }
        return false;
    });

    await test('Member can add item to shared vault', async () => {
        const res = await request('POST', '/api/items', {
            name: 'Member Item',
            description: 'Added after invite acceptance',
            password: 'member_pass',
            masterPassword: memberMasterPassword,
            vault_id: sharedVaultId
        }, memberToken);
        
        return res.status === 200 && res.data.id;
    });
    
    console.log('\n✨ Test Complete');
}

runTests();
