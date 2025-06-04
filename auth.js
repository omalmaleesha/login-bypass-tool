// SecureBank Authentication System
// WARNING: This is for educational purposes only - demonstrates client-side security vulnerabilities

// Obfuscated credentials storage
const _0x4a2b = ['YWRtaW4=', 'cGFzc3dvcmQxMjM=', 'dXNlcg==', 'bXlzZWNyZXQ='];
const _0x1c3d = {
    'primary': atob(_0x4a2b[0]),
    'secondary': atob(_0x4a2b[2])
};

// Additional obfuscation layer - ROT13 encoded strings
function _0x2e4f(str) {
    return str.replace(/[a-zA-Z]/g, function(c) {
        return String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26);
    });
}

// Hidden validation keys (ROT13 encoded)
const _0x5g6h = {
    'k1': _0x2e4f('cnffjbeq123'),  // password123
    'k2': _0x2e4f('zlfrperg')      // mysecret
};

// Simulated server response delay
function simulateNetworkDelay() {
    return new Promise(resolve => setTimeout(resolve, Math.random() * 2000 + 1000));
}

// Hash function for password validation
function generateHash(input) {
    return CryptoJS.SHA256(input).toString();
}

// Credential validation function
function validateCredentials(username, password) {
    // Multiple validation paths to confuse analysis
    const validUsers = [_0x1c3d.primary, _0x1c3d.secondary];
    const validPasswords = [atob(_0x4a2b[1]), atob(_0x4a2b[3])];
    
    // Primary validation path
    if (username === validUsers[0] && password === validPasswords[0]) {
        return { valid: true, role: 'admin', message: 'Administrator access granted' };
    }
    
    // Secondary validation path
    if (username === validUsers[1] && password === validPasswords[1]) {
        return { valid: true, role: 'user', message: 'User access granted' };
    }
    
    // Hidden validation path using ROT13 decoded values
    if (username === 'admin' && password === _0x2e4f('cnffjbeq123')) {
        return { valid: true, role: 'admin', message: 'Hidden admin access' };
    }
    
    // Hash-based validation (for advanced reverse engineering)
    const expectedHash = '0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e';
    if (username === 'secure_user' && generateHash(password) === expectedHash) {
        return { valid: true, role: 'secure', message: 'Secure hash validation passed' };
    }
    
    return { valid: false, message: 'Invalid credentials' };
}

// DOM elements
const loginForm = document.getElementById('loginForm');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const loginBtn = document.getElementById('loginBtn');
const btnText = document.getElementById('btnText');
const spinner = document.getElementById('spinner');
const errorMessage = document.getElementById('errorMessage');
const successMessage = document.getElementById('successMessage');
const dashboard = document.getElementById('dashboard');
const logoutBtn = document.getElementById('logoutBtn');

// Login form submission handler
loginForm.addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    
    // Clear previous messages
    errorMessage.style.display = 'none';
    successMessage.style.display = 'none';
    
    // Show loading state
    loginBtn.disabled = true;
    btnText.textContent = 'Signing In...';
    spinner.style.display = 'inline-block';
    
    try {
        // Simulate network request
        await simulateNetworkDelay();
        
        // Validate credentials
        const result = validateCredentials(username, password);
        
        if (result.valid) {
            // Success
            successMessage.textContent = result.message;
            successMessage.style.display = 'block';
            
            // Store session (client-side only - security vulnerability!)
            sessionStorage.setItem('authenticated', 'true');
            sessionStorage.setItem('username', username);
            sessionStorage.setItem('role', result.role);
            
            // Redirect to dashboard after delay
            setTimeout(() => {
                showDashboard();
            }, 1500);
            
        } else {
            // Failure
            errorMessage.textContent = result.message;
            errorMessage.style.display = 'block';
        }
        
    } catch (error) {
        errorMessage.textContent = 'An error occurred. Please try again.';
        errorMessage.style.display = 'block';
    } finally {
        // Reset button state
        loginBtn.disabled = false;
        btnText.textContent = 'Sign In';
        spinner.style.display = 'none';
    }
});

// Show dashboard function
function showDashboard() {
    document.querySelector('.login-box').style.display = 'none';
    dashboard.style.display = 'block';
}

// Logout functionality
logoutBtn.addEventListener('click', function() {
    sessionStorage.clear();
    dashboard.style.display = 'none';
    document.querySelector('.login-box').style.display = 'block';
    
    // Clear form
    usernameInput.value = '';
    passwordInput.value = '';
    errorMessage.style.display = 'none';
    successMessage.style.display = 'none';
});

// Check if user is already authenticated on page load
window.addEventListener('load', function() {
    if (sessionStorage.getItem('authenticated') === 'true') {
        showDashboard();
    }
});

// Debug function (hidden in production)
function _debugCredentials() {
    console.log('Valid credentials:');
    console.log('1. admin / password123');
    console.log('2. user / mysecret');
    console.log('3. secure_user / hello123 (hash-based)');
}

// Anti-debugging measures (basic)
setInterval(function() {
    if (window.console && (console.firebug || console.table && /firebug/i.test(console.table()))) {
        alert('Developer tools detected!');
    }
}, 1000);
