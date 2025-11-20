const http = require('http');
const { spawn } = require('child_process');
const path = require('path');

const API_URL = 'http://localhost:3000/api';
let serverProcess;
let isExternalServer = false;

function request(method, path, data) {
    return new Promise((resolve, reject) => {
        const url = new URL(path, 'http://localhost:3000'); // Base URL needed for URL constructor
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

async function startServer() {
    return new Promise((resolve, reject) => {
        // First check if server is already running
        const req = http.request({
            hostname: 'localhost',
            port: 3000,
            path: '/api/ping',
            method: 'GET',
            timeout: 1000
        }, (res) => {
            console.log('✅ Server already running');
            isExternalServer = true;
            resolve();
        });

        req.on('error', (e) => {
            // Server not running, start it
            console.log('🚀 Starting server...');
            serverProcess = spawn('node', ['index.js'], {
                cwd: path.join(__dirname),
                stdio: 'pipe'
            });

            serverProcess.stdout.on('data', (data) => {
                const output = data.toString();
                // Only log if not just a ping log to avoid noise
                if (!output.includes('/api/ping')) {
                    console.log('[SERVER]', output.trim());
                }
                if (output.includes('Server running')) {
                    resolve();
                }
            });

            serverProcess.stderr.on('data', (data) => {
                console.error('[SERVER ERROR]', data.toString().trim());
            });

            serverProcess.on('error', (err) => {
                reject(err);
            });
        });

        req.end();
    });
}

function stopServer() {
    if (serverProcess && !isExternalServer) {
        console.log('🛑 Stopping server...');
        serverProcess.kill();
    }
}

async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function runTests() {
    try {
        console.log('🚀 Starting Login Rate Limit Tests...');
        await startServer();
        console.log('✅ Server started');

        // 1. Register a user
        const username = `ratelimit_test_${Date.now()}`;
        const password = 'StrongPassword123!';
        
        try {
            const res = await request('POST', '/api/register', { username, password });
            if (res.status === 201) {
                console.log('✅ User registered');
            } else {
                 throw new Error(`Registration failed: ${JSON.stringify(res.data)}`);
            }
        } catch (error) {
            console.error('❌ Registration failed:', error);
            process.exit(1);
        }

        // 2. Attempt login with wrong password 3 times
        console.log('🔄 Attempting 3 wrong passwords...');
        for (let i = 1; i <= 3; i++) {
            const res = await request('POST', '/api/login', { username, password: 'WrongPassword' });
            
            if (res.status === 401) {
                console.log(`✅ Attempt ${i} failed as expected (401)`);
            } else if (res.status === 429) {
                 if (i === 3) {
                     console.log(`✅ Attempt ${i} triggered rate limit (429) as expected`);
                 } else {
                     console.error(`❌ Attempt ${i} triggered rate limit prematurely`);
                 }
            } else {
                console.error(`❌ Attempt ${i} failed with unexpected status: ${res.status}`);
            }
        }

        // 3. Verify 4th attempt is blocked
        console.log('🔒 Verifying lockout on 4th attempt...');
        const res4 = await request('POST', '/api/login', { username, password: 'WrongPassword' });
        if (res4.status === 429) {
            console.log('✅ 4th attempt rate limited (429)');
            console.log('   Response:', res4.data);
        } else {
            console.error(`❌ 4th attempt failed with unexpected status: ${res4.status}`);
        }

        // 4. Verify correct password is ALSO blocked during lockout
        console.log('🔒 Verifying correct password is also blocked...');
        const resCorrect = await request('POST', '/api/login', { username, password });
        if (resCorrect.status === 429) {
            console.log('✅ Correct password attempt rate limited (429)');
        } else {
            console.error(`❌ Correct password attempt failed with unexpected status: ${resCorrect.status}`);
        }

        // 5. Wait for lockout to expire (30s)
        console.log('⏳ Waiting 32 seconds for lockout to expire...');
        await sleep(32000);

        // 6. Verify login works again
        console.log('🔓 Verifying login after lockout...');
        const resFinal = await request('POST', '/api/login', { username, password });
        if (resFinal.status === 200) {
            console.log('✅ Login successful after lockout expired');
        } else {
            console.error(`❌ Login failed after lockout expired: ${resFinal.status}`, resFinal.data);
        }

    } catch (error) {
        console.error('Test failed:', error);
    } finally {
        stopServer();
        process.exit(0);
    }
}

runTests();
