#!/usr/bin/env python3
"""Test current share using the comprehensive hash discovery tool"""

import sys
sys.path.append('.')

from hash_discovery import HashMethodTester
import hashlib

def test_current_share():
    """Test current share data with the discovery tool"""
    
    # Current share data from your logs
    job = {
        "coinb1": "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2203676940",
        "coinb2": "4d696e656420427920546f6d61732056616e61676173ffffffff02902f500900000000160014462bf26c29e00ee732f4d475a7ddb0dfb29bc7390000000000000000286a246a24aa21a9edc99be73af85f048166f41505ca0e10e47a02533dce8b88f050a91f5a6092344700000000",
        "prevhash": "b5943ea561328af1fdfc81bd0f7bcb2bcab2ffe46fcbe261e228b8960bc1b93e",
        "merkle_branch": ["2683352d34d2bcd5390f3d3366cfb0ba0d8c962e5b5bd2f2de86869202883a7e"],
        "version": "00000020",
        "nbits": "c53f011c",
    }
    
    # Submitted parameters
    extra_nonce1 = "00000000"
    extra_nonce2 = "00000000"  
    ntime = "f8cbaa68"
    nonce = "83290900"
    
    # Expected hash from miner
    expected_hash = "000000f562794800434d5deeebef1d4ecf7e121894282ec9f67e163568a7a634"
    
    print("🔍 TESTING CURRENT SHARE WITH DISCOVERY TOOL")
    print(f"Expected hash: {expected_hash}")
    print(f"Job data: {job}")
    print(f"Submitted: en1={extra_nonce1}, en2={extra_nonce2}, ntime={ntime}, nonce={nonce}")
    print()
    
    # First, let's verify if any of our test cases produces the expected hash
    test_cases = HashMethodTester._generate_test_cases(job, extra_nonce1, extra_nonce2, ntime, nonce)
    
    print(f"Generated {len(test_cases)} test cases")
    print("Searching for matching hash...")
    
    matches_found = 0
    for i, (method_name, header_bytes) in enumerate(test_cases):
        try:
            result_hash = hashlib.scrypt(header_bytes, salt=header_bytes, n=1024, r=1, p=1, dklen=32)[::-1].hex()
            
            if i % 1000 == 0:
                print(f"  Progress: {i}/{len(test_cases)} ({i/len(test_cases)*100:.1f}%)")
            
            if result_hash == expected_hash:
                print(f"🎯 *** EXACT MATCH FOUND! ***")
                print(f"Method: {method_name}")
                print(f"Header: {header_bytes.hex()}")
                print(f"Hash: {result_hash}")
                matches_found += 1
                
                # Continue searching to see if there are multiple matches
                
        except Exception as e:
            continue
    
    print(f"\nSearch complete! Found {matches_found} exact matches.")
    
    if matches_found == 0:
        print("❌ No exact matches found")
        print("🔍 Searching for any valid hashes (starting with 0000)...")
        
        # Use the discovery tool to find any valid method
        discovered_method = HashMethodTester.discover_method_from_share(job, extra_nonce1, extra_nonce2, ntime, nonce)
        
        if discovered_method:
            print(f"✅ Found a valid method: {discovered_method}")
        else:
            print("❌ No valid methods found")

if __name__ == "__main__":
    test_current_share()
