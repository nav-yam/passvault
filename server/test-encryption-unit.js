// cd server
// node test-encryption-unit.js
//
// Unit tests for encryption utilities (no server required)

const { encrypt, decrypt, generateSalt } = require('./utils/encryption');

let passed = 0;
let failed = 0;

function test(name, testFn) {
    try {
        const result = testFn();
        if (result) {
            console.log(`✅ ${name}`);
            passed++;
            return true;
        } else {
            console.log(`❌ ${name}`);
            failed++;
            return false;
        }
    } catch (error) {
        console.log(`❌ ${name} - Error: ${error.message}`);
        failed++;
        return false;
    }
}

console.log('🔐 Testing Encryption Utilities (Unit Tests)\n');
console.log('='.repeat(60));

// Test 1: Generate salt
test('Generate salt returns Buffer', () => {
    const salt = generateSalt();
    return Buffer.isBuffer(salt) && salt.length === 32;
});

// Test 2: Encrypt and decrypt basic text
test('Encrypt and decrypt basic text', () => {
    const plaintext = 'Hello, World!';
    const masterPassword = 'MyMasterPassword123';
    const salt = generateSalt();
    
    const encrypted = encrypt(plaintext, masterPassword, salt);
    const decrypted = decrypt(encrypted, masterPassword, salt);
    
    return decrypted === plaintext;
});

// Test 3: Encrypt empty string
test('Encrypt empty string returns null', () => {
    const masterPassword = 'MyMasterPassword123';
    const salt = generateSalt();
    
    const encrypted = encrypt('', masterPassword, salt);
    return encrypted === null;
});

// Test 4: Decrypt empty string
test('Decrypt null/empty returns null', () => {
    const masterPassword = 'MyMasterPassword123';
    const salt = generateSalt();
    
    const decrypted = decrypt(null, masterPassword, salt);
    return decrypted === null;
});

// Test 5: Different passwords produce different ciphertexts
test('Same plaintext produces different ciphertexts (IV randomness)', () => {
    const plaintext = 'Same text';
    const masterPassword = 'MyMasterPassword123';
    const salt = generateSalt();
    
    const encrypted1 = encrypt(plaintext, masterPassword, salt);
    const encrypted2 = encrypt(plaintext, masterPassword, salt);
    
    // Should be different due to random IV
    return encrypted1 !== encrypted2;
});

// Test 6: Wrong master password fails decryption
test('Wrong master password fails decryption', () => {
    const plaintext = 'Secret message';
    const correctPassword = 'CorrectPassword123';
    const wrongPassword = 'WrongPassword123';
    const salt = generateSalt();
    
    const encrypted = encrypt(plaintext, correctPassword, salt);
    
    try {
        decrypt(encrypted, wrongPassword, salt);
        return false; // Should have thrown an error
    } catch (error) {
        return true; // Expected to fail
    }
});

// Test 7: Wrong salt fails decryption
test('Wrong salt fails decryption', () => {
    const plaintext = 'Secret message';
    const masterPassword = 'MyMasterPassword123';
    const salt1 = generateSalt();
    const salt2 = generateSalt();
    
    const encrypted = encrypt(plaintext, masterPassword, salt1);
    
    try {
        decrypt(encrypted, masterPassword, salt2);
        return false; // Should have thrown an error
    } catch (error) {
        return true; // Expected to fail
    }
});

// Test 8: Encrypt special characters
test('Encrypt and decrypt special characters', () => {
    const plaintext = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    const masterPassword = 'MyMasterPassword123';
    const salt = generateSalt();
    
    const encrypted = encrypt(plaintext, masterPassword, salt);
    const decrypted = decrypt(encrypted, masterPassword, salt);
    
    return decrypted === plaintext;
});

// Test 9: Encrypt unicode characters
test('Encrypt and decrypt unicode characters', () => {
    const plaintext = 'Hello 世界 🌍 测试';
    const masterPassword = 'MyMasterPassword123';
    const salt = generateSalt();
    
    const encrypted = encrypt(plaintext, masterPassword, salt);
    const decrypted = decrypt(encrypted, masterPassword, salt);
    
    return decrypted === plaintext;
});

// Test 10: Encrypt long text
test('Encrypt and decrypt long text', () => {
    const plaintext = 'A'.repeat(10000); // 10KB of text
    const masterPassword = 'MyMasterPassword123';
    const salt = generateSalt();
    
    const encrypted = encrypt(plaintext, masterPassword, salt);
    const decrypted = decrypt(encrypted, masterPassword, salt);
    
    return decrypted === plaintext;
});

// Test 11: Corrupted ciphertext fails decryption
test('Corrupted ciphertext fails decryption', () => {
    const plaintext = 'Secret message';
    const masterPassword = 'MyMasterPassword123';
    const salt = generateSalt();
    
    const encrypted = encrypt(plaintext, masterPassword, salt);
    const corrupted = encrypted.slice(0, -5) + 'XXXXX'; // Corrupt the end
    
    try {
        decrypt(corrupted, masterPassword, salt);
        return false; // Should have thrown an error
    } catch (error) {
        return true; // Expected to fail
    }
});

// Test 12: Invalid ciphertext format fails
test('Invalid ciphertext format fails decryption', () => {
    const masterPassword = 'MyMasterPassword123';
    const salt = generateSalt();
    
    try {
        decrypt('invalid:format', masterPassword, salt);
        return false; // Should have thrown an error
    } catch (error) {
        return true; // Expected to fail
    }
});

// Test 13: Verify ciphertext format
test('Encrypted text has correct format (iv:tag:encrypted)', () => {
    const plaintext = 'Test message';
    const masterPassword = 'MyMasterPassword123';
    const salt = generateSalt();
    
    const encrypted = encrypt(plaintext, masterPassword, salt);
    const parts = encrypted.split(':');
    
    return parts.length === 3 && 
           parts[0].length > 0 && // IV (hex)
           parts[1].length > 0 && // Tag (hex)
           parts[2].length > 0;   // Encrypted data (hex)
});

// Summary
console.log('\n' + '='.repeat(60));
console.log(`📊 Results: ${passed} passed, ${failed} failed`);
console.log('='.repeat(60));

if (failed === 0) {
    console.log('\n🎉 All unit tests passed!');
    console.log('\n✅ Encryption utilities are working correctly:');
    console.log('   - AES-256-GCM encryption/decryption');
    console.log('   - PBKDF2 key derivation');
    console.log('   - Random IV generation');
    console.log('   - Authentication tag verification');
    console.log('   - Error handling for invalid inputs');
    process.exit(0);
} else {
    console.log('\n⚠️  Some unit tests failed');
    process.exit(1);
}

