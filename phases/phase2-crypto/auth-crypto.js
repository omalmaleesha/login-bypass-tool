// SecureBank Cryptographic Authentication System - Phase 2
// WARNING: This is for educational purposes only - demonstrates hash-based authentication vulnerabilities

// Precomputed password hashes (MD5, SHA-1, SHA-256, bcrypt-style)
const HASH_DATABASE = {
    // MD5 hashes
    'md5': {
        '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8': 'password',
        '21232f297a57a5a743894a0e4a801fc3': 'admin',
        'ee11cbb19052e40b07aac0ca060c23ee': 'user',
        '5d41402abc4b2a76b9719d911017c592': 'hello',
        'e99a18c428cb38d5f260853678922e03': 'abc123'
    },
    
    // SHA-1 hashes
    'sha1': {
        '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8': 'password',
        'd033e22ae348aeb5660fc2140aec35850c4da997': 'admin',
        '12dea96fec20593566ab75692c9949596833adc9': 'secret',
        'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d': 'hello',
        '6367c48dd193d56ea7b0baad25b19455e529f5ee': 'test123'
    },
    
    // SHA-256 hashes
    'sha256': {
        '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8': 'password',
        '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918': 'admin',
        '0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e': 'hello123',
        'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f': 'secret123',
        '2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b': 'secure456'
    },
    
    // Bcrypt-style hashes (simplified for demo)
    'bcrypt': {
        '$2b$10$N9qo8uLOickgx2ZMRZoMye': 'password',
        '$2b$10$92IXUNpkjO0rOQ5byMi.Ye': 'admin123',
        '$2b$10$8K1p/a0dhrxSMxlbPugqL.': 'banking456'
    }
};

// User database with different hash types
const USER_DATABASE = {
    'admin': {
        'hash': '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918',
        'type': 'sha256',
        'role': 'administrator',
        'salt': 'admin_salt_2024'
    },
    'user': {
        'hash': '12dea96fec20593566ab75692c9949455e529f5ee',
        'type': 'sha1',
        'role': 'user',
        'salt': 'user_salt_2024'
    },
    'secure_user': {
        'hash': '0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e',
        'type': 'sha256',
        'role': 'secure',
        'salt': 'secure_salt_2024'
    },
    'crypto_admin': {
        'hash': '$2b$10$N9qo8uLOickgx2ZMRZoMye',
        'type': 'bcrypt',
        'role': 'crypto_admin',
        'salt': 'bcrypt_internal'
    },
    'md5_user': {
        'hash': '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
        'type': 'md5',
        'role': 'legacy_user',
        'salt': 'legacy_salt'
    }
};

// Hash generation functions
const HashUtils = {
    md5: function(input) {
        // Simplified MD5 implementation for demo
        if (typeof CryptoJS !== 'undefined' && CryptoJS.MD5) {
            return CryptoJS.MD5(input).toString();
        }
        // Fallback: simple hash function (not real MD5)
        let hash = 0;
        for (let i = 0; i < input.length; i++) {
            const char = input.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return Math.abs(hash).toString(16).padStart(32, '0');
    },
    
    sha1: function(input) {
        if (typeof CryptoJS !== 'undefined' && CryptoJS.SHA1) {
            return CryptoJS.SHA1(input).toString();
        }
        return this.md5(input + '_sha1_fallback');
    },
    
    sha256: function(input) {
        if (typeof CryptoJS !== 'undefined' && CryptoJS.SHA256) {
            return CryptoJS.SHA256(input).toString();
        }
        return this.md5(input + '_sha256_fallback');
    },
    
    bcrypt: function(input, salt) {
        // Simplified bcrypt simulation (not real bcrypt)
        const combined = salt + input + salt;
        return '$2b$10$' + this.sha256(combined).substring(0, 22);
    },
    
    // Salted hash function
    saltedHash: function(input, salt, type) {
        const salted = salt + input + salt;
        switch (type) {
            case 'md5': return this.md5(salted);
            case 'sha1': return this.sha1(salted);
            case 'sha256': return this.sha256(salted);
            case 'bcrypt': return this.bcrypt(input, salt);
            default: return this.sha256(salted);
        }
    }
};

// Rainbow table simulation
const RainbowTable = {
    // Common passwords with their hashes
    commonPasswords: [
        'password', 'admin', 'user', 'secret', 'hello', 'test',
        'password123', 'admin123', 'user123', 'secret123', 'hello123',
        'test123', 'abc123', 'secure456', 'banking456', '123456',
        'qwerty', 'letmein', 'welcome', 'monkey', 'dragon'
    ],
    
    // Generate rainbow table for given hash type
    generate: function(hashType) {
        const table = {};
        this.commonPasswords.forEach(password => {
            const hash = HashUtils[hashType](password);
            table[hash] = password;
        });
        return table;
    },
    
    // Lookup hash in rainbow table
    lookup: function(hash, hashType) {
        const table = this.generate(hashType);
        return table[hash] || null;
    },
    
    // Brute force attack simulation
    bruteForce: function(targetHash, hashType, maxLength = 6) {
        const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
        
        // Try common passwords first
        const common = this.lookup(targetHash, hashType);
        if (common) return common;
        
        // Simple brute force (limited for demo)
        for (let len = 1; len <= Math.min(maxLength, 4); len++) {
            for (let i = 0; i < Math.pow(chars.length, len); i++) {
                let candidate = '';
                let num = i;
                for (let j = 0; j < len; j++) {
                    candidate = chars[num % chars.length] + candidate;
                    num = Math.floor(num / chars.length);
                }
                
                if (HashUtils[hashType](candidate) === targetHash) {
                    return candidate;
                }
            }
        }
        
        return null;
    }
};

// Advanced validation with timing attack simulation
function validateCredentialsAdvanced(username, password) {
    // Simulate network delay
    const startTime = Date.now();
    
    // Check if user exists
    if (!USER_DATABASE[username]) {
        // Constant time delay to prevent username enumeration
        const delay = 100 + Math.random() * 50;
        setTimeout(() => {}, delay);
        return { valid: false, message: 'Invalid credentials', timing: Date.now() - startTime };
    }
    
    const user = USER_DATABASE[username];
    const hashType = user.type;
    const storedHash = user.hash;
    const salt = user.salt;
    
    // Generate hash of provided password
    let computedHash;
    if (hashType === 'bcrypt') {
        // Simulate bcrypt verification
        computedHash = HashUtils.bcrypt(password, salt);
        // For demo, just check if it starts with the stored prefix
        if (storedHash.startsWith('$2b$10$') && password === 'password') {
            computedHash = storedHash; // Simulate match
        }
    } else {
        computedHash = HashUtils.saltedHash(password, salt, hashType);
    }
    
    // Timing attack vulnerability: different timing for different hash types
    let processingDelay;
    switch (hashType) {
        case 'md5': processingDelay = 10; break;
        case 'sha1': processingDelay = 20; break;
        case 'sha256': processingDelay = 50; break;
        case 'bcrypt': processingDelay = 200; break;
        default: processingDelay = 30;
    }
    
    // Simulate processing time
    const endTime = Date.now();
    const actualDelay = endTime - startTime;
    
    // Hash comparison (vulnerable to timing attacks)
    let isValid = false;
    if (hashType === 'bcrypt') {
        // Simplified bcrypt check
        isValid = (password === 'password' && username === 'crypto_admin');
    } else {
        // Direct hash comparison
        isValid = (computedHash === storedHash);
    }
    
    // Additional check against rainbow table (for demonstration)
    if (!isValid && HASH_DATABASE[hashType] && HASH_DATABASE[hashType][storedHash]) {
        const rainbowPassword = HASH_DATABASE[hashType][storedHash];
        if (password === rainbowPassword) {
            isValid = true;
        }
    }
    
    if (isValid) {
        return {
            valid: true,
            role: user.role,
            message: `Access granted (${hashType.toUpperCase()} verified)`,
            timing: actualDelay,
            hashType: hashType
        };
    } else {
        return {
            valid: false,
            message: 'Invalid credentials',
            timing: actualDelay,
            hashType: hashType,
            hint: `Hash type: ${hashType}, Length: ${storedHash.length}`
        };
    }
}

// Dictionary attack simulation
function performDictionaryAttack(username) {
    if (!USER_DATABASE[username]) {
        return { success: false, message: 'User not found' };
    }
    
    const user = USER_DATABASE[username];
    const targetHash = user.hash;
    const hashType = user.type;
    
    console.log(`🔍 Performing dictionary attack on ${username} (${hashType})`);
    console.log(`Target hash: ${targetHash}`);
    
    // Try rainbow table lookup
    const rainbowResult = RainbowTable.lookup(targetHash, hashType);
    if (rainbowResult) {
        console.log(`✅ Rainbow table hit: ${rainbowResult}`);
        return { success: true, password: rainbowResult, method: 'rainbow_table' };
    }
    
    // Try brute force
    console.log('🔨 Attempting brute force...');
    const bruteResult = RainbowTable.bruteForce(targetHash, hashType);
    if (bruteResult) {
        console.log(`✅ Brute force success: ${bruteResult}`);
        return { success: true, password: bruteResult, method: 'brute_force' };
    }
    
    console.log('❌ Attack failed');
    return { success: false, message: 'Password not found in dictionary or brute force range' };
}

// Timing attack demonstration
function timingAttackDemo() {
    console.log('⏱️  Timing Attack Demonstration');
    console.log('================================');
    
    const users = Object.keys(USER_DATABASE);
    const testPassword = 'wrongpassword';
    
    users.forEach(username => {
        const result = validateCredentialsAdvanced(username, testPassword);
        console.log(`${username} (${result.hashType}): ${result.timing}ms`);
    });
}

// Hash analysis tools
const HashAnalyzer = {
    identifyHashType: function(hash) {
        if (hash.startsWith('$2b$') || hash.startsWith('$2a$')) {
            return 'bcrypt';
        } else if (hash.length === 32) {
            return 'md5';
        } else if (hash.length === 40) {
            return 'sha1';
        } else if (hash.length === 64) {
            return 'sha256';
        } else {
            return 'unknown';
        }
    },
    
    analyzeHash: function(hash) {
        const type = this.identifyHashType(hash);
        const analysis = {
            hash: hash,
            type: type,
            length: hash.length,
            entropy: this.calculateEntropy(hash),
            crackable: this.assessCrackability(type, hash)
        };
        
        console.log('Hash Analysis:', analysis);
        return analysis;
    },
    
    calculateEntropy: function(str) {
        const freq = {};
        str.split('').forEach(char => {
            freq[char] = (freq[char] || 0) + 1;
        });
        
        let entropy = 0;
        const len = str.length;
        Object.values(freq).forEach(count => {
            const p = count / len;
            entropy -= p * Math.log2(p);
        });
        
        return entropy.toFixed(2);
    },
    
    assessCrackability: function(type, hash) {
        switch (type) {
            case 'md5': return 'HIGH - MD5 is cryptographically broken';
            case 'sha1': return 'MEDIUM - SHA-1 has known vulnerabilities';
            case 'sha256': return 'LOW - Strong if properly salted';
            case 'bcrypt': return 'VERY LOW - Designed to be slow';
            default: return 'UNKNOWN';
        }
    }
};

// Export functions for testing
if (typeof window !== 'undefined') {
    window.HashUtils = HashUtils;
    window.RainbowTable = RainbowTable;
    window.HashAnalyzer = HashAnalyzer;
    window.performDictionaryAttack = performDictionaryAttack;
    window.timingAttackDemo = timingAttackDemo;
    window.validateCredentialsAdvanced = validateCredentialsAdvanced;
    window.USER_DATABASE = USER_DATABASE;
    window.HASH_DATABASE = HASH_DATABASE;
}

// Replace the original validation function
if (typeof validateCredentials !== 'undefined') {
    window.originalValidateCredentials = validateCredentials;
}
window.validateCredentials = validateCredentialsAdvanced;
