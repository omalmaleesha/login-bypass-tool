#!/usr/bin/env python3
"""
Advanced Multi-Phase Security Analyzer
Comprehensive tool for analyzing all phases of the SecureBank Security Lab

This tool can handle:
- Phase 1: Advanced JavaScript obfuscation
- Phase 2: Cryptographic hash validation
- Phase 3: Dynamic security mechanisms
- Phase 4: WebAssembly analysis
- Phase 5: Custom encoding schemes
- Phase 6: Client-side encryption
- Phase 7: Deception and anti-analysis
- Phase 8: Anti-debugging and evasion
- Phase 9: Token generation and validation
- Phase 10: Full-stack integration
"""

import requests
import re
import base64
import hashlib
import json
import time
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


class AdvancedSecurityAnalyzer:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.analysis_results = {}
        self.discovered_credentials = []
        self.phase_capabilities = {
            0: self.analyze_basic_phase,
            1: self.analyze_obfuscation_phase,
            2: self.analyze_crypto_phase,
            3: self.analyze_dynamic_phase,
            4: self.analyze_wasm_phase,
            5: self.analyze_encoding_phase,
            6: self.analyze_encryption_phase,
            7: self.analyze_deception_phase,
            8: self.analyze_evasion_phase,
            9: self.analyze_tokens_phase,
            10: self.analyze_fullstack_phase
        }
    
    def analyze_phase(self, phase_number: int) -> Dict:
        """Analyze a specific phase"""
        print(f"🔍 Starting analysis of Phase {phase_number}")
        print("=" * 60)
        
        if phase_number not in self.phase_capabilities:
            return {"error": f"Phase {phase_number} not supported"}
        
        # Fetch phase content
        phase_url = self.get_phase_url(phase_number)
        html_content = self.fetch_page(phase_url)
        if not html_content:
            return {"error": f"Could not fetch Phase {phase_number} content"}
        
        # Extract JavaScript files
        js_files = self.extract_js_files(html_content, phase_url)
        
        # Run phase-specific analysis
        analyzer_func = self.phase_capabilities[phase_number]
        results = analyzer_func(html_content, js_files)
        
        # Store results
        self.analysis_results[phase_number] = results
        
        return results
    
    def get_phase_url(self, phase_number: int) -> str:
        """Get URL for specific phase"""
        if phase_number == 0:
            return self.base_url + "/index.html"
        else:
            return self.base_url + f"/phases/phase{phase_number}-*/index.html"
    
    def fetch_page(self, url: str) -> Optional[str]:
        """Fetch webpage content"""
        try:
            # Handle wildcard URLs
            if '*' in url:
                base_path = url.split('*')[0]
                # Try common phase directory names
                phase_dirs = {
                    1: 'obfuscation',
                    2: 'crypto',
                    3: 'dynamic',
                    4: 'wasm',
                    5: 'encoding',
                    6: 'encryption',
                    7: 'deception',
                    8: 'evasion',
                    9: 'tokens',
                    10: 'fullstack'
                }
                
                for phase_num, dir_name in phase_dirs.items():
                    if f"phase{phase_num}" in base_path:
                        url = base_path.replace('*', dir_name)
                        break
            
            response = self.session.get(url)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            print(f"❌ Error fetching {url}: {e}")
            return None
    
    def extract_js_files(self, html_content: str, base_url: str) -> List[str]:
        """Extract JavaScript file contents"""
        soup = BeautifulSoup(html_content, 'html.parser')
        js_contents = []
        
        # Find script tags with src attributes
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src and not src.startswith('http'):
                js_url = urljoin(base_url, src)
                js_content = self.fetch_page(js_url)
                if js_content:
                    js_contents.append(js_content)
        
        # Find inline scripts
        for script in soup.find_all('script'):
            if script.string:
                js_contents.append(script.string)
        
        return js_contents
    
    def analyze_basic_phase(self, html_content: str, js_files: List[str]) -> Dict:
        """Analyze basic authentication phase"""
        print("📋 Analyzing Basic Phase...")
        
        results = {
            "phase": 0,
            "type": "basic_authentication",
            "vulnerabilities": [],
            "credentials": [],
            "obfuscation_level": "low"
        }
        
        for js_content in js_files:
            # Look for Base64 encoded credentials
            base64_pattern = r"'([A-Za-z0-9+/=]{8,})'"
            base64_matches = re.findall(base64_pattern, js_content)
            
            for match in base64_matches:
                try:
                    decoded = base64.b64decode(match).decode('utf-8')
                    if len(decoded) > 2 and decoded.isalnum():
                        results["credentials"].append({
                            "encoded": match,
                            "decoded": decoded,
                            "method": "base64"
                        })
                except:
                    continue
            
            # Look for ROT13 patterns
            if "_0x2e4f" in js_content:
                results["vulnerabilities"].append("ROT13 encoding detected")
            
            # Look for hash validation
            hash_pattern = r"'([a-f0-9]{64})'"
            if re.search(hash_pattern, js_content):
                results["vulnerabilities"].append("SHA256 hash validation")
        
        return results
    
    def analyze_obfuscation_phase(self, html_content: str, js_files: List[str]) -> Dict:
        """Analyze advanced obfuscation phase"""
        print("🔒 Analyzing Obfuscation Phase...")
        
        results = {
            "phase": 1,
            "type": "advanced_obfuscation",
            "obfuscation_techniques": [],
            "string_arrays": {},
            "control_flow": {},
            "credentials": [],
            "obfuscation_level": "high"
        }
        
        for js_content in js_files:
            # Detect string array functions
            string_array_pattern = r"function\s+(_0x[a-f0-9]+)\(\)\s*\{\s*const\s+(_0x[a-f0-9]+)\s*=\s*\[(.*?)\];"
            string_matches = re.findall(string_array_pattern, js_content, re.DOTALL)
            
            if string_matches:
                results["obfuscation_techniques"].append("string_array_rotation")
                for func_name, var_name, array_content in string_matches:
                    strings = re.findall(r"'([^']*)'", array_content)
                    results["string_arrays"][func_name] = strings
            
            # Detect control flow flattening
            if re.search(r"switch\s*\([^)]+\).*case\s+0x[a-f0-9]+:", js_content, re.DOTALL):
                results["obfuscation_techniques"].append("control_flow_flattening")
                results["control_flow"]["flattened"] = True
            
            # Detect variable name obfuscation
            hex_vars = len(re.findall(r'_0x[a-f0-9]+', js_content))
            if hex_vars > 10:
                results["obfuscation_techniques"].append("variable_name_obfuscation")
                results["control_flow"]["hex_variables"] = hex_vars
            
            # Extract credentials from string arrays
            for array_name, strings in results["string_arrays"].items():
                for string_val in strings:
                    try:
                        if re.match(r'^[A-Za-z0-9+/]*={0,2}$', string_val):
                            decoded = base64.b64decode(string_val).decode('utf-8')
                            if len(decoded) > 2:
                                results["credentials"].append({
                                    "encoded": string_val,
                                    "decoded": decoded,
                                    "method": "base64_from_array",
                                    "array": array_name
                                })
                    except:
                        continue
        
        return results
    
    def analyze_crypto_phase(self, html_content: str, js_files: List[str]) -> Dict:
        """Analyze cryptographic hash validation phase"""
        print("🔐 Analyzing Crypto Phase...")
        
        results = {
            "phase": 2,
            "type": "cryptographic_validation",
            "hash_types": [],
            "hash_database": {},
            "rainbow_attacks": [],
            "timing_vulnerabilities": [],
            "credentials": []
        }
        
        for js_content in js_files:
            # Detect hash databases
            if "HASH_DATABASE" in js_content:
                results["hash_types"].extend(["md5", "sha1", "sha256", "bcrypt"])
            
            # Extract hash values
            hash_patterns = {
                "md5": r"'([a-f0-9]{32})'",
                "sha1": r"'([a-f0-9]{40})'",
                "sha256": r"'([a-f0-9]{64})'",
                "sha512": r"'([a-f0-9]{128})'"
            }
            
            for hash_type, pattern in hash_patterns.items():
                hashes = re.findall(pattern, js_content)
                if hashes:
                    results["hash_database"][hash_type] = hashes
            
            # Detect timing attack vulnerabilities
            if "Date.now()" in js_content and "timing" in js_content:
                results["timing_vulnerabilities"].append("timing_attack_vulnerable")
            
            # Attempt rainbow table attacks
            common_passwords = ['password', 'admin', 'user', 'secret', 'hello123']
            for hash_type, hashes in results["hash_database"].items():
                for hash_val in hashes:
                    for pwd in common_passwords:
                        if self.verify_hash(pwd, hash_val, hash_type):
                            results["credentials"].append({
                                "hash": hash_val,
                                "password": pwd,
                                "hash_type": hash_type,
                                "method": "rainbow_table"
                            })
        
        return results
    
    def analyze_dynamic_phase(self, html_content: str, js_files: List[str]) -> Dict:
        """Analyze dynamic security mechanisms phase"""
        print("⚡ Analyzing Dynamic Phase...")
        
        results = {
            "phase": 3,
            "type": "dynamic_security",
            "mechanisms": [],
            "token_systems": {},
            "challenges": [],
            "two_factor": {},
            "bypass_methods": []
        }
        
        for js_content in js_files:
            # Detect time-based tokens
            if "TimeBasedTokenSystem" in js_content:
                results["mechanisms"].append("time_based_tokens")
                results["token_systems"]["totp_like"] = True
            
            # Detect challenge systems
            if "ChallengeSystem" in js_content:
                results["mechanisms"].append("captcha_challenges")
                challenge_types = re.findall(r"type:\s*'([^']+)'", js_content)
                results["challenges"] = challenge_types
            
            # Detect 2FA
            if "TwoFactorAuth" in js_content:
                results["mechanisms"].append("two_factor_auth")
                results["two_factor"]["enabled"] = True
            
            # Detect bypass opportunities
            if "getCurrentToken" in js_content:
                results["bypass_methods"].append("token_extraction")
            
            if "getBackupCodes" in js_content:
                results["bypass_methods"].append("backup_code_extraction")
        
        return results
    
    def analyze_wasm_phase(self, html_content: str, js_files: List[str]) -> Dict:
        """Analyze WebAssembly phase"""
        print("🔧 Analyzing WASM Phase...")
        
        results = {
            "phase": 4,
            "type": "webassembly_analysis",
            "wasm_modules": [],
            "binary_analysis": {},
            "reverse_engineering": []
        }
        
        # Look for WASM loading patterns
        for js_content in js_files:
            if "WebAssembly" in js_content or ".wasm" in js_content:
                results["wasm_modules"].append("validation_module")
                results["binary_analysis"]["detected"] = True
        
        return results
    
    def analyze_encoding_phase(self, html_content: str, js_files: List[str]) -> Dict:
        """Analyze custom encoding schemes phase"""
        print("🔀 Analyzing Encoding Phase...")
        
        results = {
            "phase": 5,
            "type": "custom_encoding",
            "encoding_schemes": [],
            "xor_patterns": [],
            "key_locations": []
        }
        
        for js_content in js_files:
            # Detect XOR operations
            if "^" in js_content and "charCodeAt" in js_content:
                results["encoding_schemes"].append("xor_encoding")
            
            # Detect multi-layer encoding
            if "atob" in js_content and "fromCharCode" in js_content:
                results["encoding_schemes"].append("multi_layer_encoding")
        
        return results
    
    def analyze_encryption_phase(self, html_content: str, js_files: List[str]) -> Dict:
        """Analyze client-side encryption phase"""
        print("🔐 Analyzing Encryption Phase...")
        
        results = {
            "phase": 6,
            "type": "client_side_encryption",
            "encryption_algorithms": [],
            "key_storage": [],
            "vulnerabilities": []
        }
        
        for js_content in js_files:
            # Detect AES usage
            if "AES" in js_content:
                results["encryption_algorithms"].append("AES")
            
            # Detect key storage in DOM/CSS
            if "getAttribute" in js_content or "getComputedStyle" in js_content:
                results["key_storage"].append("dom_attributes")
        
        return results
    
    def analyze_deception_phase(self, html_content: str, js_files: List[str]) -> Dict:
        """Analyze deception and anti-analysis phase"""
        print("🎭 Analyzing Deception Phase...")
        
        results = {
            "phase": 7,
            "type": "deception_anti_analysis",
            "fake_functions": [],
            "hidden_logic": [],
            "decoy_credentials": []
        }
        
        for js_content in js_files:
            # Detect fake validation functions
            fake_patterns = re.findall(r"function\s+\w+.*fake", js_content, re.IGNORECASE)
            results["fake_functions"] = len(fake_patterns)
        
        return results
    
    def analyze_evasion_phase(self, html_content: str, js_files: List[str]) -> Dict:
        """Analyze anti-debugging and evasion phase"""
        print("🛡️ Analyzing Evasion Phase...")
        
        results = {
            "phase": 8,
            "type": "anti_debugging_evasion",
            "detection_methods": [],
            "evasion_techniques": [],
            "bypass_methods": []
        }
        
        for js_content in js_files:
            # Detect developer tools detection
            if "console" in js_content and "firebug" in js_content:
                results["detection_methods"].append("devtools_detection")
            
            # Detect debugger statements
            if "debugger" in js_content:
                results["detection_methods"].append("debugger_statements")
        
        return results
    
    def analyze_tokens_phase(self, html_content: str, js_files: List[str]) -> Dict:
        """Analyze token generation and validation phase"""
        print("🎫 Analyzing Tokens Phase...")
        
        results = {
            "phase": 9,
            "type": "token_generation",
            "token_algorithms": [],
            "jwt_patterns": [],
            "fingerprinting": []
        }
        
        for js_content in js_files:
            # Detect JWT patterns
            if "jwt" in js_content.lower() or "header.payload.signature" in js_content:
                results["jwt_patterns"].append("custom_jwt")
            
            # Detect browser fingerprinting
            if "navigator" in js_content and "screen" in js_content:
                results["fingerprinting"].append("browser_fingerprinting")
        
        return results
    
    def analyze_fullstack_phase(self, html_content: str, js_files: List[str]) -> Dict:
        """Analyze full-stack integration phase"""
        print("🌐 Analyzing Full-Stack Phase...")
        
        results = {
            "phase": 10,
            "type": "fullstack_integration",
            "api_endpoints": [],
            "authentication_flows": [],
            "network_security": []
        }
        
        for js_content in js_files:
            # Detect API calls
            api_patterns = re.findall(r"fetch\(['\"]([^'\"]+)['\"]", js_content)
            results["api_endpoints"] = api_patterns
            
            # Detect custom headers
            if "setRequestHeader" in js_content:
                results["network_security"].append("custom_headers")
        
        return results
    
    def verify_hash(self, password: str, hash_value: str, hash_type: str) -> bool:
        """Verify if password matches hash"""
        try:
            if hash_type == "md5":
                computed = hashlib.md5(password.encode()).hexdigest()
            elif hash_type == "sha1":
                computed = hashlib.sha1(password.encode()).hexdigest()
            elif hash_type == "sha256":
                computed = hashlib.sha256(password.encode()).hexdigest()
            elif hash_type == "sha512":
                computed = hashlib.sha512(password.encode()).hexdigest()
            else:
                return False
            
            return computed.lower() == hash_value.lower()
        except:
            return False
    
    def generate_comprehensive_report(self) -> str:
        """Generate comprehensive analysis report"""
        report = []
        report.append("=" * 80)
        report.append("SECUREBANK SECURITY LAB - COMPREHENSIVE ANALYSIS REPORT")
        report.append("=" * 80)
        
        total_phases = len(self.analysis_results)
        report.append(f"\n📊 ANALYSIS SUMMARY")
        report.append(f"Phases Analyzed: {total_phases}")
        report.append(f"Total Credentials Found: {len(self.discovered_credentials)}")
        
        for phase_num, results in self.analysis_results.items():
            report.append(f"\n{'='*60}")
            report.append(f"PHASE {phase_num}: {results.get('type', 'Unknown').upper()}")
            report.append(f"{'='*60}")
            
            # Phase-specific reporting
            if "obfuscation_techniques" in results:
                report.append(f"Obfuscation Techniques: {', '.join(results['obfuscation_techniques'])}")
            
            if "credentials" in results:
                report.append(f"Credentials Found: {len(results['credentials'])}")
                for cred in results['credentials']:
                    if 'decoded' in cred:
                        report.append(f"  - {cred['decoded']} ({cred['method']})")
            
            if "vulnerabilities" in results:
                report.append(f"Vulnerabilities: {', '.join(results['vulnerabilities'])}")
        
        report.append(f"\n{'='*80}")
        
        return "\n".join(report)


def main():
    parser = argparse.ArgumentParser(description='Advanced Multi-Phase Security Analyzer')
    parser.add_argument('--phase', '-p', type=int, help='Specific phase to analyze (0-10)')
    parser.add_argument('--all', '-a', action='store_true', help='Analyze all phases')
    parser.add_argument('--url', '-u', default='http://localhost:8000', help='Base URL')
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    analyzer = AdvancedSecurityAnalyzer(args.url)
    
    if args.all:
        # Analyze all phases
        for phase_num in range(11):  # 0-10
            try:
                results = analyzer.analyze_phase(phase_num)
                print(f"✅ Phase {phase_num} analysis complete")
            except Exception as e:
                print(f"❌ Phase {phase_num} analysis failed: {e}")
    elif args.phase is not None:
        # Analyze specific phase
        results = analyzer.analyze_phase(args.phase)
        print(json.dumps(results, indent=2))
    else:
        print("Please specify --phase or --all")
        return
    
    # Generate comprehensive report
    if analyzer.analysis_results:
        report = analyzer.generate_comprehensive_report()
        print(report)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"\n📄 Report saved to {args.output}")


if __name__ == "__main__":
    main()
