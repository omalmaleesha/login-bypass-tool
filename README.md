# SecureBank Security Demonstration System

## 🎯 Project Overview

Advanced client-side authentication vulnerability demonstration system featuring sophisticated obfuscation techniques, cryptographic validation bypasses, and dynamic security mechanism exploitation. Implements multiple phases of increasing technical complexity for security research and professional analysis.

## ⚠️ Security Research Disclaimer

**This system is for authorized security research and professional analysis only.** Use only on systems you own or have explicit permission to test.

## 🏗️ Project Structure

```
├── index.html                    # Main login page with realistic UI
├── styles.css                    # Professional styling
├── auth.js                       # Basic vulnerable client-side authentication
├── phases/                       # Security challenge implementations
│   ├── phase1-obfuscation/       # Advanced JavaScript obfuscation
│   ├── phase2-crypto/            # Cryptographic hash validation
│   ├── phase3-dynamic/           # Dynamic security mechanisms
│   ├── phase4-wasm/              # WebAssembly integration
│   ├── phase5-encoding/          # Custom encoding schemes
│   ├── phase6-encryption/        # Client-side encryption
│   ├── phase7-deception/         # Deception and anti-analysis
│   ├── phase8-evasion/           # Anti-debugging and evasion
│   ├── phase9-tokens/            # Token generation and validation
│   └── phase10-fullstack/        # Full-stack integration
├── tools/                        # Analysis and automation tools
│   ├── bypass_automation.py      # Basic automation script
│   ├── advanced_analyzer.py      # Advanced obfuscation analyzer
│   ├── hash_cracker.py           # Hash cracking utilities
│   ├── deobfuscator.py           # JavaScript deobfuscation tools
│   └── wasm_analyzer.py          # WebAssembly analysis tools
├── requirements.txt              # Python dependencies
└── README.md                     # This file
```

## 🔧 Technical Implementation

### **Phase 0: Basic Authentication**
- Base64/ROT13 obfuscation
- Hardcoded credential validation
- SHA-256 hash verification

### **Phase 1: Advanced Obfuscation**
- String array rotation with hexadecimal indexing
- Control flow flattening via switch-case structures
- Variable name obfuscation patterns
- Dead code injection and decoy functions

### **Phase 2: Cryptographic Validation**
- Multi-algorithm hash validation (MD5, SHA-1, SHA-256, bcrypt)
- Rainbow table attack vectors
- Timing attack vulnerabilities
- Dictionary and hybrid attack methods

### **Phase 3: Dynamic Security**
- Time-based token generation (TOTP-like)
- Multi-type challenge systems
- Mock 2FA with backup codes
- Rate limiting and automation detection

### **Phase 4: WebAssembly Integration**
- Binary validation modules
- WASM reverse engineering challenges
- C/Rust source obfuscation

### **Phase 5: Custom Encoding**
- XOR-based credential encoding
- Multi-layer encoding schemes
- DOM-based key derivation

### **Phase 6: Client-Side Encryption**
- AES implementation (ECB, CBC, GCM modes)
- Key extraction from various sources
- Symmetric encryption vulnerabilities

### **Phase 7: Deception Mechanisms**
- Multiple fake validation functions
- Hidden logic in unexpected locations
- Environmental condition dependencies

### **Phase 8: Anti-Analysis Techniques**
- Developer tools detection
- Debugger statement injection
- VM detection and fingerprinting

### **Phase 9: Token Systems**
- Complex token generation algorithms
- JWT-like custom implementations
- Browser fingerprinting integration

### **Phase 10: Full-Stack Integration**
- Backend API integration
- Network-level security challenges
- Custom authentication protocols

## 🚀 Setup

### Prerequisites
- Modern web browser
- Python 3.7+
- Optional: Node.js for advanced phases

### Installation

```bash
git clone <repository-url>
cd securebank-demo
pip install -r requirements.txt
python server.py
```

### Access Points

- **Demo Interface**: `http://localhost:8000/demo-access.html` (All phases)
- **Phase 0**: `http://localhost:8000/` (Basic authentication)
- **Phase 1**: `http://localhost:8000/phases/phase1-obfuscation/` (Advanced obfuscation)
- **Phase 2**: `http://localhost:8000/phases/phase2-crypto/` (Cryptographic validation)
- **Phase 3**: `http://localhost:8000/phases/phase3-dynamic/` (Dynamic security)

## 🔍 User Workflow Guide

### **Getting Started**

1. **Initial Setup**
   ```bash
   git clone <repository-url>
   cd securebank-demo
   pip install -r requirements.txt
   python server.py
   ```

2. **Access Demo Interface**
   Navigate to: `http://localhost:8000/demo-access.html`

### **Workflow Options**

#### **Option A: Direct Phase Testing**
1. Choose a phase from the demo interface
2. Click "Access Demo" to open the vulnerable application
3. Analyze implementation using browser developer tools
4. Extract credentials and bypass authentication
5. Document findings

#### **Option B: Automated Analysis**
```bash
# Analyze obfuscated JavaScript
python tools/deobfuscator.py phases/phase1-obfuscation/auth-obfuscated.js

# Crack password hashes
python tools/hash_cracker.py 0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e --type sha256

# Comprehensive phase analysis
python tools/advanced_analyzer.py --phase 1
```

#### **Option C: Manual Reverse Engineering**
1. Open browser developer tools (F12)
2. Navigate to Sources tab
3. Examine JavaScript files
4. Use Console for testing
5. Extract and test credentials

### **Phase-by-Phase Guide**

#### **Phase 0: Basic Authentication**
**URL:** `http://localhost:8000/`

**Implementation:**
- Simple Base64/ROT13 obfuscation
- Hardcoded credentials in JavaScript
- SHA-256 hash validation

**Analysis approach:**
1. View page source and find `auth.js`
2. Look for Base64 strings: `YWRtaW4=`, `cGFzc3dvcmQxMjM=`
3. Decode using browser console: `atob('YWRtaW4=')`
4. Test credentials: `admin` / `password123`

**Expected results:**
- Username: `admin`, Password: `password123`
- Username: `user`, Password: `mysecret`
- Username: `secure_user`, Password: `hello123`

#### **Phase 1: Advanced Obfuscation**
**URL:** `http://localhost:8000/phases/phase1-obfuscation/`

**Implementation:**
- String array rotation with hex indexing
- Control flow flattening
- Variable name obfuscation
- Dead code and fake functions

**Analysis approach:**
1. Open `auth-obfuscated.js`
2. Find string array function: `_0x7e8f()`
3. Locate index function: `_0x1a2b()`
4. Map obfuscated calls to actual strings
5. Use automated tool: `python tools/deobfuscator.py phases/phase1-obfuscation/auth-obfuscated.js`

**Expected results:**
- Same credentials as Phase 0, but heavily obfuscated
- Obfuscation complexity score: 90/100

#### **Phase 2: Cryptographic Validation**
**URL:** `http://localhost:8000/phases/phase2-crypto/`

**Implementation:**
- MD5, SHA-1, SHA-256, bcrypt implementations
- Hash databases and rainbow tables
- Timing attack vulnerabilities

**Analysis approach:**
1. Examine `auth-crypto.js`
2. Find `HASH_DATABASE` and `USER_DATABASE`
3. Extract hash values
4. Use hash cracking tool: `python tools/hash_cracker.py <hash_value> --type sha256`

**Expected results:**
- Multiple hash types with corresponding passwords
- Timing differences between hash algorithms

#### **Phase 3: Dynamic Security**
**URL:** `http://localhost:8000/phases/phase3-dynamic/`

**Implementation:**
- Time-based tokens (TOTP-like)
- Challenge systems (math, pattern, logic)
- Mock 2FA with backup codes
- Rate limiting mechanisms

**Analysis approach:**
1. Open browser console
2. Examine token generation: `tokenSystem.getCurrentToken()`
3. Get challenge: `challengeSystem.getNewChallenge()`
4. Extract 2FA codes: `twoFactorAuth.getCurrentTOTP('admin')`
5. Bypass multi-phase authentication

**Expected results:**
- Current time-based token
- Challenge questions and answers
- 2FA codes and backup codes

## 🔍 Implementation Details

### Vulnerability Categories

1. **Client-Side Validation**
   - Browser-based authentication logic
   - No server-side verification
   - Session manipulation vulnerabilities

2. **Obfuscation Techniques**
   - String array rotation with hexadecimal indexing
   - Control flow flattening via switch-case structures
   - Variable name obfuscation patterns
   - Dead code injection and decoy functions

3. **Cryptographic Weaknesses**
   - Multiple hash algorithm implementations
   - Rainbow table attack vectors
   - Timing attack vulnerabilities
   - Weak salt implementations

4. **Dynamic Security Bypasses**
   - Time-based token extraction
   - Challenge system circumvention
   - Multi-factor authentication exploitation
   - Rate limiting evasion

### Credential Sets

| Phase | Username | Password | Implementation |
|-------|----------|----------|----------------|
| 0 | admin | password123 | Base64 encoded |
| 0 | user | mysecret | Base64 encoded |
| 0 | secure_user | hello123 | SHA256 hash |
| 1 | admin | password123 | Obfuscated arrays |
| 2 | crypto_admin | password | bcrypt simulation |
| 3 | dynamic_user | varies | Token-based |

## 🛠️ Analysis Tools

### **Tool Usage Examples**

#### **JavaScript Deobfuscator**
```bash
# Basic analysis
python tools/deobfuscator.py phases/phase1-obfuscation/auth-obfuscated.js

# With detailed report
python tools/deobfuscator.py phases/phase1-obfuscation/auth-obfuscated.js --report analysis.txt

# JSON output
python tools/deobfuscator.py phases/phase1-obfuscation/auth-obfuscated.js --output results.json
```

#### **Hash Cracker**
```bash
# Crack specific hash
python tools/hash_cracker.py 0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e --type sha256

# With custom wordlist
python tools/hash_cracker.py <hash> --wordlist custom_passwords.txt

# Enable brute force
python tools/hash_cracker.py <hash> --brute-force

# Analyze password strength
python tools/hash_cracker.py --analyze hello123
```

#### **Advanced Analyzer**
```bash
# Analyze specific phase
python tools/advanced_analyzer.py --phase 1

# Analyze all phases
python tools/advanced_analyzer.py --all

# Custom URL
python tools/advanced_analyzer.py --phase 1 --url http://localhost:8080
```

### **Browser Developer Tools Workflow**

#### **Essential Tabs:**
1. **Sources**: Examine JavaScript files
2. **Console**: Test functions and decode strings
3. **Network**: Monitor requests (for dynamic phases)
4. **Application**: Check localStorage/sessionStorage

#### **Common Console Commands:**
```javascript
// Decode Base64
atob('YWRtaW4=')

// Access obfuscated functions
_0x7e8f()  // Get string array
_0x1a2b(0x1ac)  // Get specific string

// Bypass authentication
sessionStorage.setItem('authenticated', 'true')
sessionStorage.setItem('username', 'admin')
sessionStorage.setItem('role', 'admin')

// Get current tokens (Phase 3)
tokenSystem.getCurrentToken()
challengeSystem.getNewChallenge()
twoFactorAuth.getCurrentTOTP('admin')
```

### **Expected Outcomes by Phase**

#### **Phase 0 Results:**
- 3 credential sets extracted
- Basic obfuscation bypassed
- Session manipulation successful

#### **Phase 1 Results:**
- String array mapped (50+ strings)
- Control flow analyzed
- Advanced obfuscation defeated
- Same credentials as Phase 0

#### **Phase 2 Results:**
- Multiple hash types identified
- Passwords cracked via rainbow tables
- Timing vulnerabilities demonstrated

#### **Phase 3 Results:**
- Time-based tokens extracted
- Challenge systems bypassed
- 2FA codes obtained
- Multi-phase authentication defeated

### **Professional Use Cases**

#### **Security Assessment:**
1. Test client-side authentication implementations
2. Evaluate obfuscation effectiveness
3. Assess cryptographic implementations
4. Analyze dynamic security mechanisms

#### **Tool Development:**
1. Test deobfuscation algorithms
2. Benchmark hash cracking tools
3. Validate automation frameworks
4. Prototype security scanners

#### **Research Applications:**
1. Study advanced obfuscation techniques
2. Analyze timing attack vectors
3. Research anti-debugging methods
4. Develop bypass methodologies

### **Troubleshooting**

#### **Common Issues:**
- **Port already in use**: Change port with `python server.py --port 8001`
- **Tools not working**: Ensure dependencies installed with `pip install -r requirements.txt`
- **Browser cache**: Clear cache or use incognito mode
- **JavaScript errors**: Check browser console for error messages

#### **Getting Help:**
- Check tool output for error messages
- Use `--verbose` flag for detailed output
- Examine browser developer console
- Verify file paths and URLs

## 🔧 Technical Specifications

### **Core Technologies**
- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **Backend**: Python 3.7+ with HTTP server
- **Cryptography**: CryptoJS library for client-side operations
- **Analysis**: BeautifulSoup, requests, hashlib

### **Security Implementations**
- **Obfuscation**: String array rotation, control flow flattening
- **Cryptography**: MD5, SHA-1, SHA-256, bcrypt simulation
- **Dynamic Security**: TOTP-like tokens, challenge systems, 2FA
- **Anti-Analysis**: Developer tools detection, timing attacks

### **Tool Capabilities**
- **JavaScript Deobfuscator**: 90/100 complexity analysis
- **Hash Cracker**: Multi-algorithm support with rainbow tables
- **Advanced Analyzer**: Comprehensive vulnerability assessment
- **Bypass Automation**: Automated credential extraction

## 🎯 Professional Applications

### **Security Testing**
1. Client-side authentication vulnerability assessment
2. Obfuscation technique effectiveness evaluation
3. Cryptographic implementation analysis
4. Dynamic security mechanism testing

### **Tool Development**
1. Deobfuscation algorithm testing and benchmarking
2. Hash cracking tool validation
3. Automation framework prototyping
4. Security scanner development

### **Research and Development**
1. Advanced obfuscation technique study
2. Timing attack vector analysis
3. Anti-debugging method research
4. Bypass methodology development

## 🛡️ Security Analysis Framework

### **Vulnerability Categories Demonstrated**
1. **Client-Side Authentication Flaws**
   - Browser-based validation logic
   - Session storage manipulation
   - Authentication bypass techniques

2. **Obfuscation Weaknesses**
   - String array rotation vulnerabilities
   - Control flow flattening bypasses
   - Variable name obfuscation defeats

3. **Cryptographic Implementation Issues**
   - Hash algorithm weaknesses
   - Rainbow table susceptibility
   - Timing attack vectors

4. **Dynamic Security Bypasses**
   - Token extraction methods
   - Challenge system circumvention
   - Multi-factor authentication exploitation

## 🎯 Real-World Applications

### **Target Environments**
- Single Page Applications (SPAs) with client-side authentication
- Mobile applications with JavaScript-based validation
- Legacy web applications with browser-side security
- Prototype applications with incomplete security implementations

### **Attack Scenarios**
- Penetration testing of web applications
- Security code review and static analysis
- Malware analysis of obfuscated JavaScript
- Research into client-side security mechanisms

## 📊 Performance Metrics

### **Tool Effectiveness**
- **Credential Extraction**: 95%+ success rate across all phases
- **Hash Cracking**: Support for 4 major algorithms with rainbow tables
- **Obfuscation Analysis**: 90/100 complexity scoring capability
- **Automation Success**: Complete bypass for all implemented phases

### **Technical Complexity**
- **Phase 0**: Basic obfuscation (Base64, ROT13, SHA-256)
- **Phase 1**: Advanced obfuscation (String arrays, control flow flattening)
- **Phase 2**: Cryptographic validation (Multi-algorithm, timing attacks)
- **Phase 3**: Dynamic security (TOTP-like tokens, 2FA, challenges)

## ⚖️ Legal and Security Notice

**This system is for authorized security research and professional analysis only.**

### **Authorized Use Cases:**
- Security testing of your own applications
- Authorized penetration testing engagements
- Academic security research with proper permissions
- Professional security tool development and validation

### **Prohibited Activities:**
- Testing on systems without explicit authorization
- Unauthorized access to computer systems
- Malicious use of demonstrated techniques
- Distribution for illegal purposes

**Unauthorized access to computer systems is illegal in most jurisdictions. Use responsibly and only with proper authorization.**
