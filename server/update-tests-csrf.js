const fs = require('fs');

const testFiles = [
    'test-encryption.js',
    'test-vaults.js', 
    'test-master-password.js',
    'test-password-ui.js',
    'test-shared-vaults.js',
    'test-security-bugs.js'
];

testFiles.forEach(file => {
    if (!fs.existsSync(file)) {
        console.log(`Skipping ${file} - not found`);
        return;
    }
    
    let content = fs.readFileSync(file, 'utf8');
    
    // Skip if already updated
    if (content.includes('csrfToken') && content.includes('X-CSRF-Token')) {
        console.log(`${file}: Already has CSRF support`);
        return;
    }
    
    // Add csrfToken variable after token variable
    if (content.includes('let token =') && !content.includes('let csrfToken =')) {
        content = content.replace(/(let token =[^;]+;)/, "$1\nlet csrfToken = null;");
    }
    
    // Update request function to accept csrfTokenParam
    if (content.includes("function request(method, path, data, authToken)")) {
        content = content.replace(
            /function request\(method, path, data, authToken\)/,
            "function request(method, path, data, authToken, csrfTokenParam)"
        );
    }
    
    // Add CSRF token to headers
    if (content.includes("if (authToken) {") && !content.includes("X-CSRF-Token")) {
        content = content.replace(
            /(if \(authToken\) \{[^}]+\})/,
            `$1

        // Include CSRF token for state-changing requests
        const csrf = csrfTokenParam || csrfToken;
        if (csrf && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
            options.headers['X-CSRF-Token'] = csrf;
        }`
        );
    }
    
    // Update response to include headers
    if (content.includes("resolve({ status: res.statusCode, data: json });") && !content.includes("headers: res.headers")) {
        content = content.replace(
            /resolve\(\{ status: res\.statusCode, data: json \}\);?/g,
            "resolve({ status: res.statusCode, data: json, headers: res.headers });"
        );
        content = content.replace(
            /resolve\(\{ status: res\.statusCode, data: responseData \}\);?/g,
            "resolve({ status: res.statusCode, data: responseData, headers: res.headers });"
        );
    }
    
    fs.writeFileSync(file, content, 'utf8');
    console.log(`${file}: Updated with CSRF support`);
});

console.log('\nDone! Note: You still need to manually add code to get CSRF token after login.');
