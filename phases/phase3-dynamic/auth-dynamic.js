// SecureBank Dynamic Security System - Phase 3
// WARNING: This is for educational purposes only - demonstrates dynamic security mechanisms

// Time-based token system
class TimeBasedTokenSystem {
    constructor() {
        this.secret = 'SecureBank2024!@#$';
        this.tokenLifetime = 30000; // 30 seconds
        this.currentToken = null;
        this.tokenTimestamp = 0;
        this.initializeToken();
    }
    
    // Generate time-based token using current timestamp
    generateToken(timestamp = null) {
        const now = timestamp || Date.now();
        const timeSlot = Math.floor(now / this.tokenLifetime);
        
        // Simple TOTP-like algorithm
        const data = this.secret + timeSlot.toString();
        let hash = 0;
        for (let i = 0; i < data.length; i++) {
            const char = data.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        
        // Convert to 6-digit token
        const token = Math.abs(hash % 1000000).toString().padStart(6, '0');
        return token;
    }
    
    // Initialize and start token rotation
    initializeToken() {
        this.updateToken();
        setInterval(() => {
            this.updateToken();
        }, 1000); // Check every second
    }
    
    // Update current token if needed
    updateToken() {
        const now = Date.now();
        const timeSlot = Math.floor(now / this.tokenLifetime);
        const currentTimeSlot = Math.floor(this.tokenTimestamp / this.tokenLifetime);
        
        if (timeSlot !== currentTimeSlot) {
            this.currentToken = this.generateToken(now);
            this.tokenTimestamp = now;
            console.log(`🔄 Token updated: ${this.currentToken} (valid for ${this.getTimeRemaining()}s)`);
        }
    }
    
    // Get current valid token
    getCurrentToken() {
        this.updateToken();
        return this.currentToken;
    }
    
    // Validate provided token
    validateToken(providedToken) {
        const currentValid = this.getCurrentToken();
        const previousValid = this.generateToken(Date.now() - this.tokenLifetime);
        
        // Allow current and previous token (for clock skew)
        return providedToken === currentValid || providedToken === previousValid;
    }
    
    // Get remaining time for current token
    getTimeRemaining() {
        const now = Date.now();
        const timeSlot = Math.floor(now / this.tokenLifetime);
        const nextSlot = (timeSlot + 1) * this.tokenLifetime;
        return Math.ceil((nextSlot - now) / 1000);
    }
}

// CAPTCHA-like challenge system
class ChallengeSystem {
    constructor() {
        this.challenges = [
            { type: 'math', generate: this.generateMathChallenge },
            { type: 'pattern', generate: this.generatePatternChallenge },
            { type: 'sequence', generate: this.generateSequenceChallenge },
            { type: 'logic', generate: this.generateLogicChallenge }
        ];
        this.currentChallenge = null;
    }
    
    // Generate mathematical challenge
    generateMathChallenge() {
        const operations = ['+', '-', '*'];
        const op = operations[Math.floor(Math.random() * operations.length)];
        let a, b, answer;
        
        switch (op) {
            case '+':
                a = Math.floor(Math.random() * 50) + 1;
                b = Math.floor(Math.random() * 50) + 1;
                answer = a + b;
                break;
            case '-':
                a = Math.floor(Math.random() * 50) + 25;
                b = Math.floor(Math.random() * 25) + 1;
                answer = a - b;
                break;
            case '*':
                a = Math.floor(Math.random() * 12) + 1;
                b = Math.floor(Math.random() * 12) + 1;
                answer = a * b;
                break;
        }
        
        return {
            question: `What is ${a} ${op} ${b}?`,
            answer: answer.toString(),
            type: 'math'
        };
    }
    
    // Generate pattern recognition challenge
    generatePatternChallenge() {
        const patterns = [
            { sequence: [2, 4, 6, 8], next: 10, rule: 'even numbers' },
            { sequence: [1, 3, 5, 7], next: 9, rule: 'odd numbers' },
            { sequence: [1, 4, 9, 16], next: 25, rule: 'squares' },
            { sequence: [2, 6, 18, 54], next: 162, rule: 'multiply by 3' },
            { sequence: [1, 1, 2, 3, 5], next: 8, rule: 'fibonacci' }
        ];
        
        const pattern = patterns[Math.floor(Math.random() * patterns.length)];
        return {
            question: `What comes next in this sequence: ${pattern.sequence.join(', ')}, ?`,
            answer: pattern.next.toString(),
            type: 'pattern'
        };
    }
    
    // Generate sequence challenge
    generateSequenceChallenge() {
        const sequences = [
            { letters: 'ABCDE', next: 'F' },
            { letters: 'ZYXWV', next: 'U' },
            { letters: 'ACEG', next: 'I' },
            { letters: 'BDFH', next: 'J' }
        ];
        
        const seq = sequences[Math.floor(Math.random() * sequences.length)];
        return {
            question: `What letter comes next: ${seq.letters.split('').join(', ')}, ?`,
            answer: seq.next,
            type: 'sequence'
        };
    }
    
    // Generate logic challenge
    generateLogicChallenge() {
        const challenges = [
            {
                question: "If all roses are flowers and some flowers are red, can we conclude that some roses are red?",
                answer: "no",
                options: ["yes", "no"]
            },
            {
                question: "A bat and ball cost $1.10. The bat costs $1 more than the ball. How much does the ball cost? (in cents)",
                answer: "5",
                hint: "Think carefully, it's not 10 cents!"
            },
            {
                question: "How many months have 28 days?",
                answer: "12",
                hint: "All months have at least 28 days"
            }
        ];
        
        const challenge = challenges[Math.floor(Math.random() * challenges.length)];
        return {
            question: challenge.question,
            answer: challenge.answer,
            type: 'logic',
            hint: challenge.hint
        };
    }
    
    // Get new challenge
    getNewChallenge() {
        const challengeType = this.challenges[Math.floor(Math.random() * this.challenges.length)];
        this.currentChallenge = challengeType.generate.call(this);
        return this.currentChallenge;
    }
    
    // Validate challenge response
    validateChallenge(userAnswer) {
        if (!this.currentChallenge) {
            return false;
        }
        
        const correct = userAnswer.toString().toLowerCase().trim() === 
                       this.currentChallenge.answer.toString().toLowerCase().trim();
        
        if (correct) {
            this.currentChallenge = null; // Clear after successful validation
        }
        
        return correct;
    }
}

// Mock 2FA system
class TwoFactorAuth {
    constructor() {
        this.userSecrets = {
            'admin': 'JBSWY3DPEHPK3PXP',
            'user': 'HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ',
            'secure_user': 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
        };
        this.backupCodes = {
            'admin': ['123456', '789012', '345678'],
            'user': ['111111', '222222', '333333'],
            'secure_user': ['999999', '888888', '777777']
        };
    }
    
    // Generate TOTP-like code
    generateTOTP(secret, timestamp = null) {
        const now = timestamp || Date.now();
        const timeStep = Math.floor(now / 30000); // 30-second intervals
        
        // Simplified TOTP algorithm
        let hash = 0;
        const data = secret + timeStep.toString();
        for (let i = 0; i < data.length; i++) {
            const char = data.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        
        return Math.abs(hash % 1000000).toString().padStart(6, '0');
    }
    
    // Validate 2FA code
    validate2FA(username, code) {
        if (!this.userSecrets[username]) {
            return false;
        }
        
        // Check backup codes first
        if (this.backupCodes[username] && this.backupCodes[username].includes(code)) {
            // Remove used backup code
            const index = this.backupCodes[username].indexOf(code);
            this.backupCodes[username].splice(index, 1);
            return { valid: true, type: 'backup_code' };
        }
        
        // Check TOTP codes (current and previous window)
        const secret = this.userSecrets[username];
        const currentCode = this.generateTOTP(secret);
        const previousCode = this.generateTOTP(secret, Date.now() - 30000);
        
        if (code === currentCode || code === previousCode) {
            return { valid: true, type: 'totp' };
        }
        
        return { valid: false };
    }
    
    // Get current TOTP for user (for testing)
    getCurrentTOTP(username) {
        if (!this.userSecrets[username]) {
            return null;
        }
        return this.generateTOTP(this.userSecrets[username]);
    }
    
    // Get backup codes for user
    getBackupCodes(username) {
        return this.backupCodes[username] || [];
    }
}

// Initialize systems
const tokenSystem = new TimeBasedTokenSystem();
const challengeSystem = new ChallengeSystem();
const twoFactorAuth = new TwoFactorAuth();

// Enhanced validation with dynamic security
function validateCredentialsDynamic(username, password, securityToken = null, challengeAnswer = null, twoFactorCode = null) {
    console.log('🔐 Dynamic Security Validation Started');
    
    // Phase 1: Basic credential validation
    const basicValidation = validateCredentialsAdvanced(username, password);
    if (!basicValidation.valid) {
        return {
            valid: false,
            message: basicValidation.message,
            phase: 'credentials'
        };
    }
    
    console.log('✅ Phase 1: Credentials validated');
    
    // Phase 2: Time-based token validation
    if (!securityToken) {
        return {
            valid: false,
            message: 'Security token required',
            phase: 'token',
            currentToken: tokenSystem.getCurrentToken(),
            timeRemaining: tokenSystem.getTimeRemaining()
        };
    }
    
    if (!tokenSystem.validateToken(securityToken)) {
        return {
            valid: false,
            message: 'Invalid or expired security token',
            phase: 'token',
            currentToken: tokenSystem.getCurrentToken(),
            timeRemaining: tokenSystem.getTimeRemaining()
        };
    }
    
    console.log('✅ Phase 2: Security token validated');
    
    // Phase 3: Challenge validation
    if (!challengeSystem.currentChallenge) {
        const challenge = challengeSystem.getNewChallenge();
        return {
            valid: false,
            message: 'Challenge required',
            phase: 'challenge',
            challenge: challenge
        };
    }
    
    if (!challengeAnswer || !challengeSystem.validateChallenge(challengeAnswer)) {
        return {
            valid: false,
            message: 'Incorrect challenge answer',
            phase: 'challenge',
            challenge: challengeSystem.currentChallenge
        };
    }
    
    console.log('✅ Phase 3: Challenge validated');
    
    // Phase 4: Two-factor authentication
    if (!twoFactorCode) {
        return {
            valid: false,
            message: '2FA code required',
            phase: '2fa',
            currentTOTP: twoFactorAuth.getCurrentTOTP(username),
            backupCodes: twoFactorAuth.getBackupCodes(username)
        };
    }
    
    const twoFactorResult = twoFactorAuth.validate2FA(username, twoFactorCode);
    if (!twoFactorResult.valid) {
        return {
            valid: false,
            message: 'Invalid 2FA code',
            phase: '2fa',
            currentTOTP: twoFactorAuth.getCurrentTOTP(username),
            backupCodes: twoFactorAuth.getBackupCodes(username)
        };
    }
    
    console.log('✅ Phase 4: 2FA validated');
    
    // All phases passed
    return {
        valid: true,
        message: 'Multi-factor authentication successful',
        role: basicValidation.role,
        phases: ['credentials', 'token', 'challenge', '2fa'],
        twoFactorType: twoFactorResult.type
    };
}

// Timing attack demonstration for dynamic systems
function timingAttackAnalysis() {
    console.log('⏱️  Dynamic Security Timing Analysis');
    console.log('====================================');
    
    const testCases = [
        { username: 'admin', password: 'admin', description: 'Valid user, wrong password' },
        { username: 'nonexistent', password: 'password', description: 'Invalid user' },
        { username: 'admin', password: 'password123', description: 'Valid credentials' }
    ];
    
    testCases.forEach(testCase => {
        const startTime = performance.now();
        const result = validateCredentialsDynamic(testCase.username, testCase.password);
        const endTime = performance.now();
        
        console.log(`${testCase.description}: ${(endTime - startTime).toFixed(2)}ms`);
        console.log(`  Phase reached: ${result.phase || 'complete'}`);
    });
}

// Bypass detection system
class BypassDetection {
    constructor() {
        this.suspiciousActivity = [];
        this.rateLimits = new Map();
        this.maxAttempts = 5;
        this.timeWindow = 60000; // 1 minute
    }
    
    // Check for rate limiting
    checkRateLimit(identifier) {
        const now = Date.now();
        const attempts = this.rateLimits.get(identifier) || [];
        
        // Remove old attempts outside time window
        const recentAttempts = attempts.filter(time => now - time < this.timeWindow);
        
        if (recentAttempts.length >= this.maxAttempts) {
            return {
                blocked: true,
                message: 'Rate limit exceeded',
                retryAfter: Math.ceil((recentAttempts[0] + this.timeWindow - now) / 1000)
            };
        }
        
        // Add current attempt
        recentAttempts.push(now);
        this.rateLimits.set(identifier, recentAttempts);
        
        return { blocked: false };
    }
    
    // Detect automation patterns
    detectAutomation(timings) {
        // Check for too-regular timing patterns
        if (timings.length < 3) return false;
        
        const intervals = [];
        for (let i = 1; i < timings.length; i++) {
            intervals.push(timings[i] - timings[i-1]);
        }
        
        // Calculate variance
        const mean = intervals.reduce((a, b) => a + b) / intervals.length;
        const variance = intervals.reduce((sum, interval) => sum + Math.pow(interval - mean, 2), 0) / intervals.length;
        
        // Low variance suggests automation
        return variance < 100; // Threshold for "too regular"
    }
    
    // Log suspicious activity
    logSuspiciousActivity(activity) {
        this.suspiciousActivity.push({
            timestamp: Date.now(),
            ...activity
        });
        
        console.warn('🚨 Suspicious activity detected:', activity);
    }
}

const bypassDetection = new BypassDetection();

// Export for testing
if (typeof window !== 'undefined') {
    window.tokenSystem = tokenSystem;
    window.challengeSystem = challengeSystem;
    window.twoFactorAuth = twoFactorAuth;
    window.validateCredentialsDynamic = validateCredentialsDynamic;
    window.timingAttackAnalysis = timingAttackAnalysis;
    window.bypassDetection = bypassDetection;
    
    // Helper functions for testing
    window.getCurrentToken = () => tokenSystem.getCurrentToken();
    window.getNewChallenge = () => challengeSystem.getNewChallenge();
    window.getCurrentTOTP = (username) => twoFactorAuth.getCurrentTOTP(username);
    window.getBackupCodes = (username) => twoFactorAuth.getBackupCodes(username);
}

// Replace original validation function
if (typeof validateCredentials !== 'undefined') {
    window.originalValidateCredentials = validateCredentials;
}
window.validateCredentials = validateCredentialsDynamic;
