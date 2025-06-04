#!/usr/bin/env python3
"""
JavaScript Deobfuscation Tool
Analyzes obfuscated JavaScript implementations
"""

import re
import base64
import json
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional


class JavaScriptDeobfuscator:
    def __init__(self, js_content: str):
        self.js_content = js_content
        self.string_arrays = {}
        self.string_mappings = {}
        self.decoded_strings = {}
        self.function_mappings = {}
        
    def analyze(self) -> Dict:
        """Perform complete analysis of obfuscated JavaScript"""
        results = {
            'string_arrays': self.extract_string_arrays(),
            'string_mappings': self.build_string_mappings(),
            'decoded_strings': self.decode_base64_strings(),
            'credentials': self.extract_credentials(),
            'functions': self.analyze_functions(),
            'control_flow': self.analyze_control_flow(),
            'anti_debug': self.detect_anti_debug(),
            'obfuscation_score': self.calculate_obfuscation_score()
        }

        return results
    
    def extract_string_arrays(self) -> Dict[str, List[str]]:
        """Extract string arrays from obfuscated code"""
        pattern = r"function\s+(_0x[a-f0-9]+)\(\)\s*\{\s*const\s+(_0x[a-f0-9]+)\s*=\s*\[(.*?)\];"
        matches = re.findall(pattern, self.js_content, re.DOTALL | re.IGNORECASE)

        arrays = {}
        for func_name, var_name, array_content in matches:
            string_pattern = r"'([^']*)'"
            strings = re.findall(string_pattern, array_content)
            arrays[func_name] = strings

        self.string_arrays = arrays
        return arrays
    
    def build_string_mappings(self) -> Dict[str, str]:
        """Build mappings from obfuscated calls to actual strings"""
        mappings = {}

        index_pattern = r"function\s+(_0x[a-f0-9]+)\([^)]+\)\s*\{[^}]*_0x[a-f0-9]+\s*=\s*_0x[a-f0-9]+\s*-\s*(0x[a-f0-9]+)"
        index_matches = re.findall(index_pattern, self.js_content, re.DOTALL)

        if index_matches:
            index_func, offset_hex = index_matches[0]
            offset = int(offset_hex, 16)

            call_pattern = rf"{re.escape(index_func)}\((0x[a-f0-9]+)\)"
            calls = re.findall(call_pattern, self.js_content)

            if self.string_arrays:
                array_name = list(self.string_arrays.keys())[0]
                strings = self.string_arrays[array_name]

                for call_hex in calls:
                    call_index = int(call_hex, 16)
                    array_index = call_index - offset

                    if 0 <= array_index < len(strings):
                        call_str = f"{index_func}({call_hex})"
                        mappings[call_str] = strings[array_index]

        self.string_mappings = mappings
        return mappings
    
    def decode_base64_strings(self) -> Dict[str, str]:
        """Decode Base64 encoded strings"""
        print("🔓 Decoding Base64 strings...")
        
        decoded = {}
        for call, string_val in self.string_mappings.items():
            try:
                # Check if it looks like Base64
                if re.match(r'^[A-Za-z0-9+/]*={0,2}$', string_val) and len(string_val) % 4 == 0:
                    decoded_val = base64.b64decode(string_val).decode('utf-8')
                    decoded[call] = decoded_val
                    print(f"   '{string_val}' -> '{decoded_val}'")
                else:
                    decoded[call] = string_val
            except Exception:
                decoded[call] = string_val
        
        self.decoded_strings = decoded
        return decoded
    
    def extract_credentials(self) -> List[Dict[str, str]]:
        """Extract potential credentials from decoded strings"""
        print("🔑 Extracting credentials...")
        
        credentials = []
        usernames = []
        passwords = []
        
        # Common username patterns
        username_patterns = ['admin', 'user', 'root', 'administrator', 'secure_user']
        
        # Look for decoded strings that match credential patterns
        for call, value in self.decoded_strings.items():
            if value.lower() in username_patterns:
                usernames.append(value)
            elif len(value) >= 6 and any(c.isalpha() for c in value) and any(c.isdigit() for c in value):
                passwords.append(value)
        
        # Also check for ROT13 patterns in the code
        rot13_pattern = r"_0x[a-f0-9]+\('([^']+)'\)"
        rot13_matches = re.findall(rot13_pattern, self.js_content)
        
        for encoded in rot13_matches:
            decoded_rot13 = self.rot13_decode(encoded)
            if len(decoded_rot13) >= 6:
                passwords.append(decoded_rot13)
                print(f"   ROT13: '{encoded}' -> '{decoded_rot13}'")
        
        # Create credential combinations
        for username in set(usernames):
            for password in set(passwords):
                credentials.append({
                    'username': username,
                    'password': password,
                    'method': 'extracted'
                })
        
        # Add hash-based credentials
        hash_pattern = r"'([a-f0-9]{64})'"
        hash_matches = re.findall(hash_pattern, self.js_content)
        
        for hash_val in hash_matches:
            # Try common passwords
            common_passwords = ['hello123', 'password', 'admin', '123456', 'secret', 'test']
            for pwd in common_passwords:
                import hashlib
                if hashlib.sha256(pwd.encode()).hexdigest() == hash_val:
                    credentials.append({
                        'username': 'secure_user',
                        'password': pwd,
                        'method': 'hash_cracked'
                    })
                    print(f"   Hash cracked: {hash_val[:16]}... -> '{pwd}'")
                    break
        
        return credentials
    
    def rot13_decode(self, text: str) -> str:
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
    
    def analyze_functions(self) -> Dict[str, Dict]:
        """Analyze function patterns and purposes"""
        print("🔧 Analyzing functions...")
        
        functions = {}
        
        # Find all function definitions
        func_pattern = r"function\s+(_0x[a-f0-9]+)\s*\([^)]*\)\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}"
        func_matches = re.findall(func_pattern, self.js_content, re.DOTALL)
        
        for func_name, func_body in func_matches:
            analysis = {
                'name': func_name,
                'length': len(func_body),
                'complexity': func_body.count('if') + func_body.count('switch') + func_body.count('for'),
                'purpose': self.guess_function_purpose(func_body),
                'calls_crypto': 'CryptoJS' in func_body or 'SHA256' in func_body,
                'has_control_flow': 'switch' in func_body and 'case' in func_body
            }
            functions[func_name] = analysis
            print(f"   {func_name}: {analysis['purpose']}")
        
        return functions
    
    def guess_function_purpose(self, func_body: str) -> str:
        """Guess the purpose of a function based on its content"""
        if 'atob' in func_body or 'btoa' in func_body:
            return 'base64_decoder'
        elif 'replace' in func_body and 'fromCharCode' in func_body:
            return 'string_decoder'
        elif 'switch' in func_body and 'case' in func_body:
            return 'control_flow_flattened'
        elif 'SHA256' in func_body or 'hash' in func_body.lower():
            return 'hash_function'
        elif 'sessionStorage' in func_body or 'localStorage' in func_body:
            return 'session_manager'
        elif 'addEventListener' in func_body:
            return 'event_handler'
        elif 'setTimeout' in func_body or 'Promise' in func_body:
            return 'async_function'
        elif len(func_body) < 50:
            return 'utility_function'
        else:
            return 'unknown'
    
    def analyze_control_flow(self) -> Dict:
        """Analyze control flow obfuscation"""
        print("🌊 Analyzing control flow...")
        
        # Count switch statements
        switch_count = len(re.findall(r'switch\s*\([^)]+\)', self.js_content))
        
        # Count while loops with switches (control flow flattening)
        flattened_pattern = r'while\s*\([^)]+\)\s*\{[^}]*switch'
        flattened_count = len(re.findall(flattened_pattern, self.js_content, re.DOTALL))
        
        # Count case statements
        case_count = len(re.findall(r'case\s+0x[a-f0-9]+:', self.js_content))
        
        return {
            'switch_statements': switch_count,
            'flattened_loops': flattened_count,
            'case_statements': case_count,
            'is_flattened': flattened_count > 0 and case_count > 3
        }
    
    def detect_anti_debug(self) -> Dict:
        """Detect anti-debugging techniques"""
        print("🛡️  Detecting anti-debugging measures...")
        
        techniques = {
            'console_detection': 'console' in self.js_content and 'firebug' in self.js_content,
            'debugger_statements': 'debugger' in self.js_content,
            'timing_checks': 'Date.now()' in self.js_content or 'performance.now()' in self.js_content,
            'setInterval_checks': 'setInterval' in self.js_content and 'console' in self.js_content,
            'alert_on_debug': 'alert' in self.js_content and ('debug' in self.js_content or 'tools' in self.js_content)
        }
        
        detected_count = sum(techniques.values())
        print(f"   Detected {detected_count} anti-debugging techniques")
        
        return techniques
    
    def calculate_obfuscation_score(self) -> float:
        """Calculate an obfuscation complexity score (0-100)"""
        score = 0
        
        # String array obfuscation
        if self.string_arrays:
            score += 20
        
        # Variable name obfuscation
        hex_vars = len(re.findall(r'_0x[a-f0-9]+', self.js_content))
        score += min(hex_vars / 10, 20)
        
        # Control flow flattening
        control_flow = self.analyze_control_flow()
        if control_flow['is_flattened']:
            score += 25
        
        # Anti-debugging
        anti_debug = self.detect_anti_debug()
        score += sum(anti_debug.values()) * 5
        
        # Dead code (fake functions)
        fake_functions = len(re.findall(r'function\s+_0x[a-f0-9]+.*?fake', self.js_content, re.DOTALL))
        score += fake_functions * 5
        
        return min(score, 100)
    
    def generate_report(self, results: Dict) -> str:
        """Generate a comprehensive analysis report"""
        report = []
        report.append("=" * 60)
        report.append("JAVASCRIPT DEOBFUSCATION ANALYSIS REPORT")
        report.append("=" * 60)
        
        # Summary
        report.append(f"\n📊 OBFUSCATION SCORE: {results['obfuscation_score']:.1f}/100")
        
        # String Arrays
        report.append(f"\n📋 STRING ARRAYS FOUND: {len(results['string_arrays'])}")
        for array_name, strings in results['string_arrays'].items():
            report.append(f"   {array_name}: {len(strings)} strings")
        
        # Credentials
        report.append(f"\n🔑 CREDENTIALS EXTRACTED: {len(results['credentials'])}")
        for cred in results['credentials']:
            report.append(f"   {cred['username']} / {cred['password']} ({cred['method']})")
        
        # Functions
        report.append(f"\n🔧 FUNCTIONS ANALYZED: {len(results['functions'])}")
        for func_name, analysis in results['functions'].items():
            report.append(f"   {func_name}: {analysis['purpose']}")
        
        # Control Flow
        cf = results['control_flow']
        report.append(f"\n🌊 CONTROL FLOW ANALYSIS:")
        report.append(f"   Switch statements: {cf['switch_statements']}")
        report.append(f"   Flattened loops: {cf['flattened_loops']}")
        report.append(f"   Case statements: {cf['case_statements']}")
        report.append(f"   Is flattened: {cf['is_flattened']}")
        
        # Anti-Debug
        ad = results['anti_debug']
        report.append(f"\n🛡️  ANTI-DEBUGGING TECHNIQUES:")
        for technique, detected in ad.items():
            status = "✅ DETECTED" if detected else "❌ Not found"
            report.append(f"   {technique.replace('_', ' ').title()}: {status}")
        
        report.append("\n" + "=" * 60)
        
        return "\n".join(report)


def main():
    parser = argparse.ArgumentParser(description='JavaScript Deobfuscation Tool')
    parser.add_argument('file', help='JavaScript file to analyze')
    parser.add_argument('--output', '-o', help='Output file for results (JSON)')
    parser.add_argument('--report', '-r', help='Output file for text report')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Read JavaScript file
    js_file = Path(args.file)
    if not js_file.exists():
        print(f"❌ Error: File {args.file} not found")
        return
    
    js_content = js_file.read_text(encoding='utf-8')
    
    # Analyze
    deobfuscator = JavaScriptDeobfuscator(js_content)
    results = deobfuscator.analyze()
    
    # Generate report
    report = deobfuscator.generate_report(results)
    print(report)
    
    # Save results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n💾 Results saved to {args.output}")
    
    if args.report:
        with open(args.report, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"📄 Report saved to {args.report}")


if __name__ == "__main__":
    main()
