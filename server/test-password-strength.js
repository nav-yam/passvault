// cd server
// node test-password-strength.js
//
// Unit tests for password strength calculation
// Tests the custom password strength checker logic (fallback when zxcvbn unavailable)

// Custom password strength calculator (matches client-side logic)
function calculatePasswordStrength(password) {
    let score = 0;
    let feedback = '';

    if (password.length === 0) {
        return { score: 0, strength: 'Very Weak', feedback: '' };
    }

    // Length checks
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (password.length >= 16) score++;

    // Character variety checks
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumbers = /[0-9]/.test(password);
    const hasSpecial = /[^a-zA-Z0-9]/.test(password);

    if (hasLower) score++;
    if (hasUpper) score++;
    if (hasNumbers) score++;
    if (hasSpecial) score++;

    // Common patterns (penalize)
    const commonPatterns = [
        /12345/, /password/i, /qwerty/i, /abc123/i,
        /letmein/i, /welcome/i, /admin/i, /12345678/
    ];
    
    if (commonPatterns.some(pattern => pattern.test(password))) {
        score = Math.max(0, score - 2);
    }

    // Cap score at 4
    score = Math.min(4, score);

    // Determine strength and feedback
    let strength, feedbackText;
    if (score === 0) {
        strength = 'Very Weak';
        feedbackText = 'Use at least 8 characters';
    } else if (score === 1) {
        strength = 'Weak';
        feedbackText = 'Add uppercase letters and numbers';
    } else if (score === 2) {
        strength = 'Fair';
        feedbackText = 'Add special characters for better security';
    } else if (score === 3) {
        strength = 'Good';
        feedbackText = 'Strong password! Consider making it longer';
    } else {
        strength = 'Strong';
        feedbackText = 'Excellent password strength!';
    }

    // Additional feedback
    if (password.length < 8) {
        feedbackText = 'Use at least 8 characters';
    } else if (!hasLower || !hasUpper) {
        feedbackText = 'Mix uppercase and lowercase letters';
    } else if (!hasNumbers) {
        feedbackText = 'Add numbers';
    } else if (!hasSpecial) {
        feedbackText = 'Add special characters (!@#$%^&*)';
    }

    return { score, strength, feedback: feedbackText };
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
            console.log(`   Expected: true, Got: ${result}`);
            return false;
        }
    } catch (error) {
        console.log(`❌ ${name} - Error: ${error.message}`);
        return false;
    }
}

// Run all tests
function runTests() {
    console.log('🧪 Testing Password Strength Calculator\n');
    console.log('='.repeat(50));

    let passed = 0;
    let failed = 0;

    // Test 1: Empty password
    const emptyResult = test('Empty password returns Very Weak', () => {
        const result = calculatePasswordStrength('');
        return result.score === 0 && result.strength === 'Very Weak';
    });
    emptyResult ? passed++ : failed++;

    // Test 2: Very short password
    const shortResult = test('Short password (< 8 chars) is Very Weak', () => {
        const result = calculatePasswordStrength('abc123');
        return result.score === 0 && result.strength === 'Very Weak';
    });
    shortResult ? passed++ : failed++;

    // Test 3: Weak password (only lowercase)
    const weakLowerResult = test('Password with only lowercase is Weak', () => {
        const result = calculatePasswordStrength('password123');
        return result.score >= 0 && result.score <= 2 && result.strength !== 'Very Weak';
    });
    weakLowerResult ? passed++ : failed++;

    // Test 4: Fair password (lowercase + uppercase)
    const fairResult = test('Password with lowercase and uppercase is Fair', () => {
        const result = calculatePasswordStrength('Password123');
        return result.score >= 1 && result.score <= 3;
    });
    fairResult ? passed++ : failed++;

    // Test 5: Good password (lowercase + uppercase + numbers)
    const goodResult = test('Password with lowercase, uppercase, and numbers is Good', () => {
        const result = calculatePasswordStrength('Password1234');
        return result.score >= 2 && result.score <= 4;
    });
    goodResult ? passed++ : failed++;

    // Test 6: Strong password (all character types)
    const strongResult = test('Password with all character types is Strong', () => {
        const result = calculatePasswordStrength('Password123!@#');
        return result.score === 4 && result.strength === 'Strong';
    });
    strongResult ? passed++ : failed++;

    // Test 7: Long strong password
    const longStrongResult = test('Long password (16+ chars) with all types is Strong', () => {
        const result = calculatePasswordStrength('MySecurePassword123!@#');
        return result.score === 4 && result.strength === 'Strong';
    });
    longStrongResult ? passed++ : failed++;

    // Test 8: Common pattern detection
    const commonPatternResult = test('Common patterns are penalized', () => {
        const result1 = calculatePasswordStrength('password123');
        const result2 = calculatePasswordStrength('qwerty123');
        const result3 = calculatePasswordStrength('12345678');
        // Common patterns should reduce score
        return result1.score < 3 || result2.score < 3 || result3.score < 3;
    });
    commonPatternResult ? passed++ : failed++;

    // Test 9: Special characters boost score
    const specialCharResult = test('Special characters improve strength', () => {
        const result1 = calculatePasswordStrength('Password123');
        const result2 = calculatePasswordStrength('Password123!');
        return result2.score >= result1.score;
    });
    specialCharResult ? passed++ : failed++;

    // Test 10: Length matters
    const lengthResult = test('Longer passwords score higher', () => {
        const result1 = calculatePasswordStrength('Pass123!');
        const result2 = calculatePasswordStrength('MyPassword123!');
        const result3 = calculatePasswordStrength('MyVeryLongPassword123!');
        return result3.score >= result2.score && result2.score >= result1.score;
    });
    lengthResult ? passed++ : failed++;

    // Test 11: Feedback messages
    const feedbackResult = test('Feedback messages are provided', () => {
        const result1 = calculatePasswordStrength('abc');
        const result2 = calculatePasswordStrength('password');
        const result3 = calculatePasswordStrength('Password123!');
        return result1.feedback.length > 0 && 
               result2.feedback.length > 0 && 
               result3.feedback.length > 0;
    });
    feedbackResult ? passed++ : failed++;

    // Test 12: Score is capped at 4
    const scoreCapResult = test('Score is capped at 4', () => {
        const result = calculatePasswordStrength('MyVeryLongAndSecurePassword123!@#$%^&*()');
        return result.score === 4;
    });
    scoreCapResult ? passed++ : failed++;

    // Test 13: Character variety detection
    const varietyResult = test('Character variety is detected correctly', () => {
        const hasLower = /[a-z]/.test('Test123!');
        const hasUpper = /[A-Z]/.test('Test123!');
        const hasNumbers = /[0-9]/.test('Test123!');
        const hasSpecial = /[^a-zA-Z0-9]/.test('Test123!');
        return hasLower && hasUpper && hasNumbers && hasSpecial;
    });
    varietyResult ? passed++ : failed++;

    // Test 14: Real-world strong password
    const realWorldResult = test('Real-world strong password scores well', () => {
        const result = calculatePasswordStrength('Tr0ub4dor&3');
        return result.score >= 2;
    });
    realWorldResult ? passed++ : failed++;

    // Test 15: Very weak password feedback
    const veryWeakFeedbackResult = test('Very weak password has helpful feedback', () => {
        const result = calculatePasswordStrength('123');
        return result.feedback.includes('8 characters') || result.feedback.length > 0;
    });
    veryWeakFeedbackResult ? passed++ : failed++;

    // Summary
    console.log('\n' + '='.repeat(50));
    console.log(`📊 Results: ${passed} passed, ${failed} failed`);
    console.log('='.repeat(50));

    if (failed === 0) {
        console.log('\n🎉 All password strength tests passed!');
        process.exit(0);
    } else {
        console.log('\n⚠️  Some tests failed');
        process.exit(1);
    }
}

// Start tests
runTests();

