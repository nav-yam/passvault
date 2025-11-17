// cd server
// node test-password-generation.js
//
// Unit tests for password generation logic
// Tests password generator function (matches client-side logic)

// Password generator function (matches client-side logic)
function generateStrongPassword(length = 16, options = {}) {
    const {
        includeUppercase = true,
        includeLowercase = true,
        includeNumbers = true,
        includeSpecial = true
    } = options;

    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const numbers = '0123456789';
    const special = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    let charset = '';
    if (includeLowercase) charset += lowercase;
    if (includeUppercase) charset += uppercase;
    if (includeNumbers) charset += numbers;
    if (includeSpecial) charset += special;

    if (charset.length === 0) {
        throw new Error('At least one character set must be enabled');
    }

    // Ensure at least one character from each enabled category
    let password = '';
    if (includeLowercase) password += lowercase[Math.floor(Math.random() * lowercase.length)];
    if (includeUppercase) password += uppercase[Math.floor(Math.random() * uppercase.length)];
    if (includeNumbers) password += numbers[Math.floor(Math.random() * numbers.length)];
    if (includeSpecial) password += special[Math.floor(Math.random() * special.length)];

    // Fill the rest randomly
    for (let i = password.length; i < length; i++) {
        password += charset[Math.floor(Math.random() * charset.length)];
    }

    // Shuffle the password
    password = password.split('').sort(() => Math.random() - 0.5).join('');

    return password;
}

// Test function
function test(name, testFn) {
    try {
        const result = testFn();
        if (result === true) {
            console.log(`✅ ${name}`);
            return true;
        } else {
            console.log(`❌ ${name}`);
            if (typeof result === 'string') {
                console.log(`   ${result}`);
            }
            return false;
        }
    } catch (error) {
        console.log(`❌ ${name} - Error: ${error.message}`);
        return false;
    }
}

// Helper function to check if password contains character type
function hasCharacterType(password, regex) {
    return regex.test(password);
}

// Run all tests
function runTests() {
    console.log('🧪 Testing Password Generation\n');
    console.log('='.repeat(50));

    let passed = 0;
    let failed = 0;

    // Test 1: Default password generation
    const defaultResult = test('Default password generation (16 chars, all types)', () => {
        const password = generateStrongPassword();
        return password.length === 16;
    });
    defaultResult ? passed++ : failed++;

    // Test 2: Password contains lowercase
    const lowercaseResult = test('Generated password contains lowercase letters', () => {
        const password = generateStrongPassword();
        return hasCharacterType(password, /[a-z]/);
    });
    lowercaseResult ? passed++ : failed++;

    // Test 3: Password contains uppercase
    const uppercaseResult = test('Generated password contains uppercase letters', () => {
        const password = generateStrongPassword();
        return hasCharacterType(password, /[A-Z]/);
    });
    uppercaseResult ? passed++ : failed++;

    // Test 4: Password contains numbers
    const numbersResult = test('Generated password contains numbers', () => {
        const password = generateStrongPassword();
        return hasCharacterType(password, /[0-9]/);
    });
    numbersResult ? passed++ : failed++;

    // Test 5: Password contains special characters
    const specialResult = test('Generated password contains special characters', () => {
        const password = generateStrongPassword();
        return hasCharacterType(password, /[^a-zA-Z0-9]/);
    });
    specialResult ? passed++ : failed++;

    // Test 6: Custom length
    const customLengthResult = test('Password generation respects custom length', () => {
        const password12 = generateStrongPassword(12);
        const password20 = generateStrongPassword(20);
        return password12.length === 12 && password20.length === 20;
    });
    customLengthResult ? passed++ : failed++;

    // Test 7: Password is shuffled
    const shuffledResult = test('Generated password is shuffled (not predictable)', () => {
        // Generate multiple passwords and check they're different
        const passwords = [];
        for (let i = 0; i < 10; i++) {
            passwords.push(generateStrongPassword());
        }
        // At least some should be different (very unlikely all 10 are identical)
        const unique = new Set(passwords);
        return unique.size > 1;
    });
    shuffledResult ? passed++ : failed++;

    // Test 8: Password with only lowercase
    const onlyLowercaseResult = test('Password generation with only lowercase', () => {
        const password = generateStrongPassword(12, { 
            includeUppercase: false, 
            includeNumbers: false, 
            includeSpecial: false 
        });
        return password.length === 12 && 
               hasCharacterType(password, /[a-z]/) &&
               !hasCharacterType(password, /[A-Z]/) &&
               !hasCharacterType(password, /[0-9]/) &&
               !hasCharacterType(password, /[^a-zA-Z0-9]/);
    });
    onlyLowercaseResult ? passed++ : failed++;

    // Test 9: Password with only uppercase and numbers
    const upperNumbersResult = test('Password generation with uppercase and numbers only', () => {
        const password = generateStrongPassword(14, { 
            includeLowercase: false, 
            includeSpecial: false 
        });
        return password.length === 14 && 
               hasCharacterType(password, /[A-Z]/) &&
               hasCharacterType(password, /[0-9]/) &&
               !hasCharacterType(password, /[a-z]/) &&
               !hasCharacterType(password, /[^a-zA-Z0-9]/);
    });
    upperNumbersResult ? passed++ : failed++;

    // Test 10: Minimum length enforcement
    const minLengthResult = test('Password respects minimum length (at least 4 for all types)', () => {
        const password = generateStrongPassword(8);
        return password.length === 8;
    });
    minLengthResult ? passed++ : failed++;

    // Test 11: All character types present in default generation
    const allTypesResult = test('Default generation includes all character types', () => {
        const password = generateStrongPassword();
        return hasCharacterType(password, /[a-z]/) &&
               hasCharacterType(password, /[A-Z]/) &&
               hasCharacterType(password, /[0-9]/) &&
               hasCharacterType(password, /[^a-zA-Z0-9]/);
    });
    allTypesResult ? passed++ : failed++;

    // Test 12: Error when no character sets enabled
    const errorResult = test('Error thrown when no character sets enabled', () => {
        try {
            generateStrongPassword(10, {
                includeUppercase: false,
                includeLowercase: false,
                includeNumbers: false,
                includeSpecial: false
            });
            return 'Should have thrown an error';
        } catch (error) {
            return error.message.includes('character set');
        }
    });
    errorResult ? passed++ : failed++;

    // Test 13: Password uniqueness (very unlikely to generate same password twice)
    const uniquenessResult = test('Generated passwords are unique', () => {
        const passwords = new Set();
        for (let i = 0; i < 100; i++) {
            passwords.add(generateStrongPassword());
        }
        // With 100 passwords of length 16, collisions are extremely unlikely
        return passwords.size > 95; // Allow for very rare collisions
    });
    uniquenessResult ? passed++ : failed++;

    // Test 14: Password length consistency
    const lengthConsistencyResult = test('Password length is consistent', () => {
        const lengths = [8, 12, 16, 20, 24];
        return lengths.every(len => {
            const password = generateStrongPassword(len);
            return password.length === len;
        });
    });
    lengthConsistencyResult ? passed++ : failed++;

    // Test 15: Password contains required characters from each enabled type
    const requiredCharsResult = test('Password contains at least one of each enabled character type', () => {
        for (let i = 0; i < 20; i++) {
            const password = generateStrongPassword(16);
            const hasLower = hasCharacterType(password, /[a-z]/);
            const hasUpper = hasCharacterType(password, /[A-Z]/);
            const hasNum = hasCharacterType(password, /[0-9]/);
            const hasSpec = hasCharacterType(password, /[^a-zA-Z0-9]/);
            
            if (!hasLower || !hasUpper || !hasNum || !hasSpec) {
                return `Missing required character type in: ${password}`;
            }
        }
        return true;
    });
    requiredCharsResult ? passed++ : failed++;

    // Summary
    console.log('\n' + '='.repeat(50));
    console.log(`📊 Results: ${passed} passed, ${failed} failed`);
    console.log('='.repeat(50));

    if (failed === 0) {
        console.log('\n🎉 All password generation tests passed!');
        process.exit(0);
    } else {
        console.log('\n⚠️  Some tests failed');
        process.exit(1);
    }
}

// Start tests
runTests();

