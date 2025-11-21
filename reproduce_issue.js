const http = require('http');

const API_URL = 'http://localhost:3000';
let ownerToken = null;
let memberToken = null;
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
    console.log('🧪 Reproducing Shared Vault Issue\n');

    const ownerUsername = `owner_${Date.now()}`;
    const memberUsername = `member_${Date.now()}`;
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
            name: 'Shared Vault Repro',
            masterPassword: ownerMasterPassword
        }, ownerToken);
        if (res.status === 200) {
            sharedVaultId = res.data.id;
            return true;
        }
        return false;
    });

    // Add member WITHOUT providing memberMasterPassword
    await test('Owner adds member WITHOUT member password', async () => {
        const res = await request('POST', `/api/vaults/${sharedVaultId}/members`, {
            username: memberUsername,
            ownerMasterPassword: ownerMasterPassword,
            // memberMasterPassword: memberMasterPassword // OMITTED
        }, ownerToken);
        console.log('Add member response:', res.data);
        return res.status === 200;
    });

    // Try to add item as member
    await test('Member tries to add item to shared vault', async () => {
        const res = await request('POST', '/api/items', {
            name: 'Member Item',
            description: 'Should fail or succeed?',
            password: 'member_pass',
            masterPassword: memberMasterPassword,
            vault_id: sharedVaultId
        }, memberToken);
        
        console.log('Member add item response:', res.status, res.data);
        
        if (res.status === 200) {
            console.log('UNEXPECTED: Member successfully added item despite missing vault key encryption?');
            return false; 
        } else {
            console.log('EXPECTED FAILURE: Member failed to add item');
            return true;
        }
    });
}

runTests();
