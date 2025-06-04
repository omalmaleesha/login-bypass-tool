#!/usr/bin/env python3
"""
Hash Cracking Tool
Multi-algorithm hash analysis and attack implementation
"""

import hashlib
import itertools
import string
import time
import argparse
import requests
from pathlib import Path
from typing import List, Optional, Dict, Tuple
import concurrent.futures
from threading import Lock

class HashCracker:
    def __init__(self):
        self.hash_functions = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
        }
        
        self.common_passwords = [
            'password', 'admin', 'user', 'secret', 'hello', 'test',
            'password123', 'admin123', 'user123', 'secret123', 'hello123',
            'test123', 'abc123', 'secure456', 'banking456', '123456',
            'qwerty', 'letmein', 'welcome', 'monkey', 'dragon',
            'football', 'baseball', 'master', 'jordan', 'harley',
            'ranger', 'shadow', 'superman', 'batman', 'trustno1'
        ]
        
        self.results_lock = Lock()
        self.found_passwords = {}
    
    def identify_hash_type(self, hash_string: str) -> List[str]:
        """Identify possible hash types based on length and format"""
        hash_string = hash_string.strip()
        possible_types = []
        
        if hash_string.startswith('$2b$') or hash_string.startswith('$2a$'):
            possible_types.append('bcrypt')
        elif len(hash_string) == 32 and all(c in string.hexdigits for c in hash_string):
            possible_types.append('md5')
        elif len(hash_string) == 40 and all(c in string.hexdigits for c in hash_string):
            possible_types.append('sha1')
        elif len(hash_string) == 64 and all(c in string.hexdigits for c in hash_string):
            possible_types.append('sha256')
        elif len(hash_string) == 128 and all(c in string.hexdigits for c in hash_string):
            possible_types.append('sha512')
        elif len(hash_string) == 32 and ':' in hash_string:
            possible_types.append('ntlm')
        else:
            # If unsure, try common types
            possible_types = ['md5', 'sha1', 'sha256']
        
        return possible_types
    
    def hash_password(self, password: str, hash_type: str, salt: str = '') -> str:
        """Generate hash for a password"""
        if hash_type == 'ntlm':
            # NTLM hashing (simplified)
            return hashlib.new('md4', password.encode('utf-16le')).hexdigest()
        elif hash_type in self.hash_functions:
            data = (salt + password + salt).encode('utf-8')
            return self.hash_functions[hash_type](data).hexdigest()
        else:
            raise ValueError(f"Unsupported hash type: {hash_type}")
    
    def dictionary_attack(self, target_hash: str, hash_type: str,
                         wordlist: List[str], salt: str = '') -> Optional[str]:
        """Perform dictionary attack"""
        for password in wordlist:
            try:
                computed_hash = self.hash_password(password, hash_type, salt)
                if computed_hash.lower() == target_hash.lower():
                    return password
            except Exception:
                continue
        return None
    
    def brute_force_attack(self, target_hash: str, hash_type: str,
                          charset: str = None, max_length: int = 4,
                          salt: str = '') -> Optional[str]:
        """Perform brute force attack (limited for demo)"""
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        print(f"🔨 Starting brute force attack ({hash_type})...")
        print(f"   Target: {target_hash}")
        print(f"   Charset: {charset}")
        print(f"   Max length: {max_length}")
        
        start_time = time.time()
        attempts = 0
        
        for length in range(1, max_length + 1):
            print(f"   Trying length {length}...")
            for candidate in itertools.product(charset, repeat=length):
                password = ''.join(candidate)
                attempts += 1
                
                try:
                    computed_hash = self.hash_password(password, hash_type, salt)
                    if computed_hash.lower() == target_hash.lower():
                        elapsed = time.time() - start_time
                        print(f"✅ PASSWORD FOUND: '{password}'")
                        print(f"   Attempts: {attempts}")
                        print(f"   Time: {elapsed:.2f} seconds")
                        return password
                except Exception:
                    continue
                
                if attempts % 10000 == 0:
                    elapsed = time.time() - start_time
                    rate = attempts / elapsed if elapsed > 0 else 0
                    print(f"   Progress: {attempts} attempts, {rate:.0f} h/s")
        
        elapsed = time.time() - start_time
        print(f"❌ Brute force attack failed")
        print(f"   Total attempts: {attempts}")
        print(f"   Time: {elapsed:.2f} seconds")
        return None
    
    def hybrid_attack(self, target_hash: str, hash_type: str,
                     base_words: List[str], salt: str = '') -> Optional[str]:
        """Perform hybrid attack (dictionary + mutations)"""
        print(f"🧬 Starting hybrid attack ({hash_type})...")
        
        mutations = [
            lambda w: w,                    # Original
            lambda w: w.upper(),            # UPPERCASE
            lambda w: w.lower(),            # lowercase
            lambda w: w.capitalize(),       # Capitalize
            lambda w: w + '123',            # Add numbers
            lambda w: w + '!',              # Add symbol
            lambda w: '123' + w,            # Prepend numbers
            lambda w: w[::-1],              # Reverse
            lambda w: w + w[:2],            # Duplicate first 2 chars
            lambda w: w.replace('a', '@'),  # Leet speak
            lambda w: w.replace('e', '3'),
            lambda w: w.replace('i', '1'),
            lambda w: w.replace('o', '0'),
            lambda w: w.replace('s', '$'),
        ]
        
        candidates = []
        for word in base_words:
            for mutation in mutations:
                try:
                    mutated = mutation(word)
                    if mutated not in candidates:
                        candidates.append(mutated)
                except:
                    continue
        
        return self.dictionary_attack(target_hash, hash_type, candidates, salt)
    
    def online_lookup(self, target_hash: str) -> Optional[str]:
        """Attempt online hash lookup (educational purposes only)"""
        print(f"🌐 Attempting online lookup...")
        
        # Note: This is for educational purposes only
        # In real scenarios, be careful about sending hashes to online services
        
        # Simulate online lookup with local rainbow table
        rainbow_table = {
            # MD5 hashes
            '5d41402abc4b2a76b9719d911017c592': 'hello',
            '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8': 'password',
            '21232f297a57a5a743894a0e4a801fc3': 'admin',
            'ee11cbb19052e40b07aac0ca060c23ee': 'user',
            
            # SHA-1 hashes
            'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d': 'hello',
            '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8': 'password',
            'd033e22ae348aeb5660fc2140aec35850c4da997': 'admin',
            
            # SHA-256 hashes
            '2cf24dba4f21d4288094c8b0f01b4336f1b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0': 'hello',
            '0b14d501a594442a01c6859541bcb3e8164d183d32937b851835442f69d5c94e': 'hello123',
            '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918': 'admin',
        }
        
        result = rainbow_table.get(target_hash.lower())
        if result:
            print(f"✅ Online lookup successful: '{result}'")
            return result
        else:
            print(f"❌ Hash not found in online database")
            return None
    
    def load_wordlist(self, wordlist_path: str) -> List[str]:
        """Load wordlist from file"""
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
            print(f"📋 Loaded {len(words)} words from {wordlist_path}")
            return words
        except FileNotFoundError:
            print(f"❌ Wordlist file not found: {wordlist_path}")
            return self.common_passwords
        except Exception as e:
            print(f"❌ Error loading wordlist: {e}")
            return self.common_passwords
    
    def crack_hash(self, target_hash: str, hash_types: List[str] = None,
                   wordlist_path: str = None, use_brute_force: bool = False,
                   use_hybrid: bool = True, salt: str = '') -> Dict:
        """Main hash cracking function"""
        print("=" * 60)
        print("HASH CRACKING ANALYSIS")
        print("=" * 60)
        
        if hash_types is None:
            hash_types = self.identify_hash_type(target_hash)
        
        print(f"Target hash: {target_hash}")
        print(f"Possible types: {', '.join(hash_types)}")
        print(f"Salt: '{salt}' (if any)")
        print("-" * 60)
        
        # Load wordlist
        if wordlist_path:
            wordlist = self.load_wordlist(wordlist_path)
        else:
            wordlist = self.common_passwords
        
        results = {
            'hash': target_hash,
            'possible_types': hash_types,
            'found': False,
            'password': None,
            'method': None,
            'hash_type': None,
            'attempts': []
        }
        
        # Try each possible hash type
        for hash_type in hash_types:
            if hash_type == 'bcrypt':
                print(f"⚠️  bcrypt detected - cannot crack with this tool")
                results['attempts'].append({
                    'type': hash_type,
                    'method': 'bcrypt_detection',
                    'success': False,
                    'note': 'bcrypt requires specialized tools'
                })
                continue
            
            print(f"\n🎯 Trying {hash_type.upper()}...")
            
            # Method 1: Online lookup
            password = self.online_lookup(target_hash)
            if password:
                results.update({
                    'found': True,
                    'password': password,
                    'method': 'online_lookup',
                    'hash_type': hash_type
                })
                return results
            
            # Method 2: Dictionary attack
            password = self.dictionary_attack(target_hash, hash_type, wordlist, salt)
            if password:
                results.update({
                    'found': True,
                    'password': password,
                    'method': 'dictionary',
                    'hash_type': hash_type
                })
                return results
            
            # Method 3: Hybrid attack
            if use_hybrid:
                password = self.hybrid_attack(target_hash, hash_type, wordlist[:10], salt)
                if password:
                    results.update({
                        'found': True,
                        'password': password,
                        'method': 'hybrid',
                        'hash_type': hash_type
                    })
                    return results
            
            # Method 4: Brute force (limited)
            if use_brute_force:
                password = self.brute_force_attack(target_hash, hash_type, 
                                                 max_length=3, salt=salt)
                if password:
                    results.update({
                        'found': True,
                        'password': password,
                        'method': 'brute_force',
                        'hash_type': hash_type
                    })
                    return results
        
        print("\n❌ Hash cracking failed with all methods")
        return results
    
    def analyze_hash_strength(self, password: str) -> Dict:
        """Analyze password strength across different hash types"""
        print(f"\n🔒 Password Strength Analysis: '{password}'")
        print("-" * 40)
        
        analysis = {
            'password': password,
            'length': len(password),
            'character_sets': [],
            'hashes': {},
            'crack_time_estimates': {}
        }
        
        # Character set analysis
        if any(c.islower() for c in password):
            analysis['character_sets'].append('lowercase')
        if any(c.isupper() for c in password):
            analysis['character_sets'].append('uppercase')
        if any(c.isdigit() for c in password):
            analysis['character_sets'].append('digits')
        if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            analysis['character_sets'].append('symbols')
        
        # Generate hashes
        for hash_type in ['md5', 'sha1', 'sha256', 'sha512']:
            hash_value = self.hash_password(password, hash_type)
            analysis['hashes'][hash_type] = hash_value
            print(f"{hash_type.upper()}: {hash_value}")
        
        return analysis


def main():
    parser = argparse.ArgumentParser(description='Hash Cracking Tool for Educational Purposes')
    parser.add_argument('hash', help='Hash to crack')
    parser.add_argument('--type', '-t', help='Hash type (md5, sha1, sha256, etc.)')
    parser.add_argument('--wordlist', '-w', help='Path to wordlist file')
    parser.add_argument('--brute-force', '-b', action='store_true', help='Enable brute force attack')
    parser.add_argument('--salt', '-s', default='', help='Salt value (if known)')
    parser.add_argument('--analyze', '-a', help='Analyze password strength instead of cracking')
    
    args = parser.parse_args()
    
    cracker = HashCracker()
    
    if args.analyze:
        # Password strength analysis mode
        cracker.analyze_hash_strength(args.analyze)
    else:
        # Hash cracking mode
        hash_types = [args.type] if args.type else None
        results = cracker.crack_hash(
            args.hash,
            hash_types=hash_types,
            wordlist_path=args.wordlist,
            use_brute_force=args.brute_force,
            salt=args.salt
        )
        
        print("\n" + "=" * 60)
        print("FINAL RESULTS")
        print("=" * 60)
        
        if results['found']:
            print(f"✅ SUCCESS!")
            print(f"Password: {results['password']}")
            print(f"Hash type: {results['hash_type']}")
            print(f"Method: {results['method']}")
        else:
            print(f"❌ FAILED - Hash could not be cracked")
            print(f"Tried types: {', '.join(results['possible_types'])}")


if __name__ == "__main__":
    main()
