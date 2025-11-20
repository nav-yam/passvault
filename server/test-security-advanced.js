/**
 * Advanced Security Tests
 * 
 * Tests for:
 * - Memory cleanup and zeroization
 * - Session management (creation, timeout, invalidation)
 * - Argon2 key derivation and migration
 * - Path security and traversal prevention
 * - Key manager functionality
 */

const assert = require('assert');
const { zeroizeBuffer, zeroizeString, SecureString, KeyManager } = require('./utils/memoryCleanup');
const { SessionManager } = require('./utils/sessionManager');
const { deriveKeyArgon2Sync, generateSalt } = require('./utils/encryption');
const { sanitizeFilename, validatePath, isValidFilename } = require('./middleware/pathSecurity');
const path = require('path');

console.log('🧪 Advanced Security Tests\n');
console.log('='.repeat(70));
console.log();

let passed = 0;
let failed = 0;

function test(name, testFn) {
    try {
        testFn();
        console.log(`✅ ${name}`);
        passed++;
        return true;
    } catch (error) {
        console.log(`❌ ${name}`);
       console.log(`   Error: ${error.message}`);
        failed++;
        return false;
    }
}

async function asyncTest(name, testFn) {
    try {
        await testFn();
        console.log(`✅ ${name}`);
        passed++;
        return true;
    } catch (error) {
        console.log(`❌ ${name}`);
        console.log(`   Error: ${error.message}`);
        failed++;
        return false;
    }
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================
// Test 1: Memory Cleanup - Buffer Zeroization
// ============================================================
console.log('🔒 Test 1: Memory Cleanup - Buffer Zeroization');
console.log('-'.repeat(70));

test('zeroizeBuffer should overwrite buffer with zeros', () => {
    const buffer = Buffer.from('sensitive-data-123', 'utf8');
    const originalLength =buffer.length;
    
    zeroizeBuffer(buffer);
    
    // Check buffer is all zeros
    for (let i = 0; i < buffer.length; i++) {
        assert.strictEqual(buffer[i], 0, `Byte at index ${i} not zeroized`);
    }
    
    assert.strictEqual(buffer.length, originalLength, 'Buffer length changed');
});

test('zeroizeString should return null', () => {
    const str = 'my-password-123';
    const result = zeroizeString(str);
    
    assert.strictEqual(result, null, 'zeroizeString should return null');
});

test('zeroizeBuffer should handle null/undefined gracefully', () => {
    assert.doesNotThrow(() => zeroizeBuffer(null));
    assert.doesNotThrow(() => zeroizeBuffer(undefined));
    assert.doesNotThrow(() => zeroizeBuffer('not-a-buffer'));
});

console.log();

// ============================================================
// Test 2: Memory Cleanup - SecureString Class
// ============================================================
console.log('🔐 Test 2: Memory Cleanup - SecureString Class');
console.log('-'.repeat(70));

test('SecureString should store and retrieve value', () => {
    const secureStr = new SecureString('test-password', 60000);
    
    assert.strictEqual(secureStr.getValue(), 'test-password');
    assert.strictEqual(secureStr.isDestroyed(), false);
    
    secureStr.destroy();
});

test('SecureString should auto-destroy after TTL', async () => {
    const secureStr = new SecureString('short-lived', 100); // 100ms TTL
    
    assert.strictEqual(secureStr.getValue(), 'short-lived');
    
    await sleep(150);
    
    // Should be destroyed
    assert.strictEqual(secureStr.isExpired(), true);
    // Explicit destroy is still needed to clear the timeout
    secureStr.destroy();
});

test('SecureString should return null after destroy', () => {
    const secureStr = new SecureString('to-be-destroyed', 60000);
    
    assert.strictEqual(secureStr.getValue(), 'to-be-destroyed');
    
    secureStr.destroy();
    
    assert.strictEqual(secureStr.getValue(), null);
    assert.strictEqual(secureStr.isDestroyed(), true);
});

test('SecureString should track access count', () => {
    const secureStr = new SecureString('tracked', 60000);
    
    secureStr.getValue();
    secureStr.getValue();
    secureStr.getValue();
    
    const metadata = secureStr.getMetadata();
    assert.strictEqual(metadata.accessed, 3);
    
    secureStr.destroy();
});

console.log();

// ============================================================
// Test 3: Memory Cleanup - KeyManager
// ============================================================
console.log('🔑 Test 3: Memory Cleanup - KeyManager');
console.log('-'.repeat(70));

test('KeyManager should store and retrieve keys', () => {
    const manager = new KeyManager();
    const testKey = Buffer.from('0123456789abcdef0123456789abcdef', 'hex');
    
    const stored = manager.storeKey('test-key-1', testKey, 60000);
    assert.strictEqual(stored, true);
    
    const retrieved = manager.retrieveKey('test-key-1');
    assert.deepStrictEqual(retrieved, testKey);
    
    manager.shutdown();
});

test('KeyManager should return null for non-existent keys', () => {
    const manager = new KeyManager();
    
    const retrieved = manager.retrieveKey('non-existent');
    assert.strictEqual(retrieved, null);
    
    manager.shutdown();
});

test('KeyManager should clear specific keys', () => {
    const manager = new KeyManager();
    const testKey = Buffer.from('abcdef1234567890abcdef1234567890', 'hex');
    
    manager.storeKey('to-delete', testKey, 60000);
    assert.notStrictEqual(manager.retrieveKey('to-delete'), null);
    
    manager.clearKey('to-delete');
    assert.strictEqual(manager.retrieveKey('to-delete'), null);
    
    manager.shutdown();
});

test('KeyManager should clearAll keys', () => {
    const manager = new KeyManager();
    const key1 = Buffer.from('11111111111111111111111111111111', 'hex');
    const key2 = Buffer.from('22222222222222222222222222222222', 'hex');
    
    manager.storeKey('key-1', key1, 60000);
    manager.storeKey('key-2', key2, 60000);
    
    const count = manager.clearAll();
    assert.strictEqual(count, 2);
    
    assert.strictEqual(manager.retrieveKey('key-1'), null);
    assert.strictEqual(manager.retrieveKey('key-2'), null);
    
    manager.shutdown();
});

test('KeyManager should auto-expire keys after TTL', async () => {
    const manager = new KeyManager();
    const testKey = Buffer.from('33333333333333333333333333333333', 'hex');
    
    manager.storeKey('expiring-key', testKey, 100); // 100ms TTL
    
    // Immediately available
    assert.notStrictEqual(manager.retrieveKey('expiring-key'), null);
    
    // Wait for expiration
    await sleep(150);
    
    // Should be expired
    assert.strictEqual(manager.retrieveKey('expiring-key'), null);
    
    manager.shutdown();
});

console.log();

// ============================================================
// Test 4: Session Management
// ============================================================
console.log('🎫 Test 4: Session Management');
console.log('-'.repeat(70));

test('SessionManager should create sessions', () => {
    const manager = new SessionManager();
    const session = manager.createSession(1, 'test-token-123', {
        ipAddress: '127.0.0.1',
        userAgent: 'Test Agent'
    });
    
    assert.strictEqual(session.userId, 1);
    assert.strictEqual(session.data.ipAddress, '127.0.0.1');
    
    manager.shutdown();
});

test('SessionManager should retrieve and refresh sessions', () => {
    const manager = new SessionManager();
    manager.createSession(1, 'token-456', {});
    
    const session1 = manager.getSession('token-456');
    assert.notStrictEqual(session1, null);
    
    const firstActivity = session1.lastActivity;
    
    // Small delay
    const start = Date.now();
    while (Date.now() - start < 10) {
        // busy wait for 10ms
    }
    
    // Retrieve again (should refresh)
    const session2 = manager.getSession('token-456');
    assert.notStrictEqual(session2, null);
    assert.ok(session2.lastActivity >= firstActivity, 'Session should be refreshed');
    
    manager.shutdown();
});

test('SessionManager should invalidate specific sessions', () => {
    const manager = new SessionManager();
    manager.createSession(1, 'token-to-invalidate', {});
    
    assert.notStrictEqual(manager.getSession('token-to-invalidate'), null);
    
    const invalidated = manager.invalidateSession('token-to-invalidate');
    assert.strictEqual(invalidated, true);
    
    assert.strictEqual(manager.getSession('token-to-invalidate'), null);
    
    manager.shutdown();
});

test('SessionManager should invalidate all user sessions', () => {
    const manager = new SessionManager();
    
    manager.createSession(1, 'user1-token1', {});
    manager.createSession(1, 'user1-token2', {});
    manager.createSession(2, 'user2-token1', {});
    
    const count = manager.invalidateUserSessions(1);
    assert.strictEqual(count, 2);
    
    // User 1 sessions should be gone
    assert.strictEqual(manager.getSession('user1-token1'), null);
    assert.strictEqual(manager.getSession('user1-token2'), null);
    
    // User 2 session should remain
    assert.notStrictEqual(manager.getSession('user2-token1'), null);
    
    manager.shutdown();
});

test('SessionManager should track active session counts', () => {
    const manager = new SessionManager();
    
    manager.createSession(1, 'session-a', {});
    manager.createSession(2, 'session-b', {});
    manager.createSession(1, 'session-c', {});
    
    assert.strictEqual(manager.getActiveSessionCount(), 3);
    assert.strictEqual(manager.getActiveUserCount(), 2);
    
    manager.shutdown();
});

console.log();

// ============================================================
// Test 5: Argon2 Key Derivation
// ============================================================
console.log('🔐 Test 5: Argon2 Key Derivation');
console.log('-'.repeat(70));

test('deriveKeyArgon2Sync should generate consistent keys', () => {
    const password = 'test-password-123';
    const salt = generateSalt();
    
    const key1 = deriveKeyArgon2Sync(password, salt);
    const key2 = deriveKeyArgon2Sync(password, salt);
    
    assert.deepStrictEqual(key1, key2, 'Keys should be consistent for same password/salt');
    assert.strictEqual(key1.length, 32, 'Key should be 32 bytes');
});

test('deriveKeyArgon2Sync should generate different keys for different salts', () => {
    const password = 'same-password';
    const salt1 = generateSalt();
    const salt2 = generateSalt();
    
    const key1 = deriveKeyArgon2Sync(password, salt1);
    const key2 = deriveKeyArgon2Sync(password, salt2);
    
    assert.notDeepStrictEqual(key1, key2, 'Keys should differ for different salts');
});

test('deriveKeyArgon2Sync should generate different keys for different passwords', () => {
    const salt = generateSalt();
    const key1 = deriveKeyArgon2Sync('password1', salt);
    const key2 = deriveKeyArgon2Sync('password2', salt);
    
    assert.notDeepStrictEqual(key1, key2, 'Keys should differ for different passwords');
});

console.log();

// ============================================================
// Test 6: Path Security
// ============================================================
console.log('🛡️  Test 6: Path Security');
console.log('-'.repeat(70));

test('sanitizeFilename should remove path traversal sequences', () => {
    assert.strictEqual(sanitizeFilename('../../../etc/passwd'), 'etcpasswd');
    assert.strictEqual(sanitizeFilename('../../file.txt'), 'file.txt');
    assert.strictEqual(sanitizeFilename('./hidden'), 'hidden');
});

test('sanitizeFilename should remove dangerous characters', () => {
    assert.strictEqual(sanitizeFilename('file<>:|').includes('<'), false);
    assert.strictEqual(sanitizeFilename('test*?.txt').includes('*'), false);
    assert.strictEqual(sanitizeFilename('path\\to\\file').includes('\\'), false);
});

test('sanitizeFilename should throw on empty result', () => {
    assert.throws(() => sanitizeFilename('...'), Error);
    assert.throws(() => sanitizeFilename('///'), Error);
});

test('sanitizeFilename should throw on leading dot', () => {
    assert.throws(() => sanitizeFilename('.hiddenfile'), Error);
});

test('validatePath should prevent directory traversal', () => {
    const basePath = '/var/app/data';
    
    assert.throws(() => validatePath(basePath, '../../../etc/passwd'), Error);
    assert.throws(() => validatePath(basePath, '../../outside'), Error);
});

test('validatePath should allow safe paths', () => {
    const basePath = '/var/app/data';
    
    assert.doesNotThrow(() => validatePath(basePath, 'subfolder/file.txt'));
    assert.doesNotThrow(() => validatePath(basePath, 'document.pdf'));
});

test('isValidFilename should validate against whitelist', () => {
    assert.strictEqual(isValidFilename('valid-file_name.txt'), true);
    assert.strictEqual(isValidFilename('Document 2024.pdf'), true);
    assert.strictEqual(isValidFilename('test@email.com'), true);
});

test('isValidFilename should reject invalid filenames', () => {
    assert.strictEqual(isValidFilename('../traversal'), false);
    assert.strictEqual(isValidFilename('.hidden'), false);
    assert.strictEqual(isValidFilename('path/to/file'), false);
    assert.strictEqual(isValidFilename(''), false);
});

console.log();

// ============================================================
// Summary
// ============================================================
console.log('='.repeat(70));
console.log(`\n📊 Test Results: ${passed} passed, ${failed} failed\n`);

if (failed === 0) {
    console.log('🎉 All advanced security tests passed!');
    process.exit(0);
} else {
    console.log(`⚠️  ${failed} test(s) failed. Please review the output above.`);
    process.exit(1);
}
