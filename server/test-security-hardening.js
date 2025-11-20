const http = require('http');
const db = require('better-sqlite3')('./db/app.db');
const { hashPassword, verifyPassword } = require('./utils/encryption');

const API_URL = 'http://localhost:3000';

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

// Test runner
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
    console.log('🛡️  Testing Security Hardening Features\n');
    console.log('='.repeat(50));

    let passed = 0;
    let failed = 0;

    // 1. Test Argon2id Hashing (Unit Test)
    const argonResult = await test('Argon2id Hashing & Verification', async () => {
        const password = 'securePassword123!';
        const hash = await hashPassword(password);
        
        // Verify it looks like an Argon2 hash
        if (!hash.startsWith('$argon2')) {
            console.log('   Hash does not start with $argon2');
            return false;
        }

        // Verify correct password works
        const valid = await verifyPassword(password, hash);
        if (!valid) {
            console.log('   Password verification failed');
            return false;
        }

        // Verify wrong password fails
        const invalid = await verifyPassword('wrongPassword', hash);
        if (invalid) {
            console.log('   Wrong password was accepted');
            return false;
        }

        return true;
    });
    argonResult ? passed++ : failed++;

    // 2. Test Audit Logs (Integration Test)
    const auditResult = await test('Audit Logs for Failed Login', async () => {
        const username = `audit_test_${Date.now()}`;
        const password = 'password123';

        // Register first
        await request('POST', '/api/register', { username, password });

        // Attempt login with WRONG password
        await request('POST', '/api/login', { username, password: 'wrongPassword' });

        // Check database for audit log
        const user = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
        if (!user) {
            console.log('   User not found in DB');
            return false;
        }

        const log = db.prepare('SELECT * FROM audit_logs WHERE user_id = ? AND action = ? ORDER BY id DESC LIMIT 1').get(user.id, 'LOGIN_FAILED');
        
        if (!log) {
            console.log('   No audit log entry found');
            return false;
        }

        if (log.action !== 'LOGIN_FAILED') {
            console.log(`   Wrong action: ${log.action}`);
            return false;
        }

        // Verify encrypted details
        if (!log.encrypted_details || !log.encrypted_details.includes('Invalid password')) {
            console.log('   Details missing or incorrect');
            return false;
        }

        return true;
    });
    auditResult ? passed++ : failed++;

    // 3. Test Migration from Bcrypt to Argon2id (Integration Test)
    const migrationResult = await test('Migration: Bcrypt -> Argon2id', async () => {
        const bcrypt = require('bcrypt');
        const username = `migration_test_${Date.now()}`;
        const password = 'legacyPassword123';
        
        // Manually insert a user with a bcrypt hash (simulate old user)
        const saltRounds = 10;
        const bcryptHash = await bcrypt.hash(password, saltRounds);
        const encryptionSalt = require('crypto').randomBytes(32).toString('hex');
        
        const stmt = db.prepare('INSERT INTO users (username, password_hash, encryption_salt, key_derivation_algo) VALUES (?, ?, ?, ?)');
        const info = stmt.run(username, bcryptHash, encryptionSalt, 'pbkdf2'); // Old algo
        
        // Verify insertion
        const userBefore = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
        if (!userBefore.password_hash.startsWith('$2b$') && !userBefore.password_hash.startsWith('$2a$')) {
            console.log('   Failed to setup legacy user');
            return false;
        }

        // Login with the user (should trigger migration)
        const loginRes = await request('POST', '/api/login', { username, password });
        
        if (loginRes.status !== 200) {
            console.log(`   Login failed: ${loginRes.status}`);
            return false;
        }

        // Verify database has been updated
        const userAfter = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
        
        // Should now be Argon2id
        if (!userAfter.password_hash.startsWith('$argon2')) {
            console.log('   Password hash was NOT migrated to Argon2');
            return false;
        }

        // Algo flag should be updated
        if (userAfter.key_derivation_algo !== 'argon2') {
            console.log(`   Algo flag not updated: ${userAfter.key_derivation_algo}`);
            return false;
        }

        console.log('   ✅ User successfully migrated from Bcrypt to Argon2id');
        return true;
    });
    migrationResult ? passed++ : failed++;

    // 4. Test Pepper Sensitivity (Process Isolation Test)
    const pepperResult = await test('Pepper Sensitivity', async () => {
        const { execSync } = require('child_process');
        const fs = require('fs');
        
        // Create a temporary script that tries to verify a hash with a DIFFERENT pepper
        const password = 'pepperTestPassword';
        const hash = await hashPassword(password); // Generated with current PEPPER
        
        const tempScript = `
            const { verifyPassword } = require('./utils/encryption');
            
            async function run() {
                const password = '${password}';
                const hash = '${hash}';
                const isValid = await verifyPassword(password, hash);
                if (isValid) process.exit(1); // Should FAIL to verify with wrong pepper
                process.exit(0); // Success if it fails to verify
            }
            run();
        `;
        
        fs.writeFileSync('temp_pepper_test.js', tempScript);
        
        try {
            // Run with a DIFFERENT pepper
            execSync('PEPPER=wrong-pepper node temp_pepper_test.js', { stdio: 'pipe' });
            // If exit code 0, it means verifyPassword returned false (good)
            return true;
        } catch (error) {
            console.log('   Hash verification succeeded despite wrong pepper (or script failed)');
            return false;
        } finally {
            if (fs.existsSync('temp_pepper_test.js')) fs.unlinkSync('temp_pepper_test.js');
        }
    });
    pepperResult ? passed++ : failed++;

    // Summary
    console.log('\n' + '='.repeat(50));
    console.log(`📊 Results: ${passed} passed, ${failed} failed`);
    console.log('='.repeat(50));

    if (failed === 0) {
        console.log('\n🎉 All security tests passed!');
        process.exit(0);
    } else {
        console.log('\n⚠️  Some security tests failed');
        process.exit(1);
    }
}

runTests().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
});
