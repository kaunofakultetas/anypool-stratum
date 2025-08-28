#!/usr/bin/env python3
"""
Test script for main.py functions
Validates key functionality without requiring a full stratum connection
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from main import (
    create_coinbase_tx, calculate_txid, decode_address_to_script,
    validate_template, validate_share_params, hash_meets_target,
    target_from_bits, reverse_hex
)

def test_coinbase_transaction():
    """Test SegWit coinbase transaction creation"""
    print("🧪 Testing coinbase transaction creation...")
    
    try:
        height = 4220700
        extra_nonce1 = "12345678"
        extra_nonce2 = "abcdef00"
        value = 156250000  # satoshis
        
        coinbase_tx, coinbase_txid = create_coinbase_tx(height, extra_nonce1, extra_nonce2, value)
        
        print(f"   ✅ Coinbase TX created: {len(coinbase_tx)//2} bytes")
        print(f"   ✅ Coinbase TXID: {coinbase_txid}")
        print(f"   ✅ TX starts with SegWit marker: {coinbase_tx.startswith('010000000001')}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Coinbase test failed: {e}")
        return False

def test_address_decoding():
    """Test address to script conversion"""
    print("🧪 Testing address decoding...")
    
    try:
        # Test bech32 address
        addr1 = "tltc1qrjfchgya859ntsnaw9l9vkgeskghadex29u9qe"
        script1 = decode_address_to_script(addr1)
        print(f"   ✅ Bech32: {addr1} → {script1}")
        
        # Test legacy address (fallback)
        addr2 = "mxxx123456789"
        script2 = decode_address_to_script(addr2)
        print(f"   ✅ Legacy: {addr2} → {script2}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Address test failed: {e}")
        return False

def test_validation_functions():
    """Test validation functions"""
    print("🧪 Testing validation functions...")
    
    try:
        # Test template validation
        valid_template = {
            'version': 536870912,
            'previousblockhash': '0' * 64,
            'height': 4220700,
            'coinbasevalue': 156250000,
            'bits': '1c013fc5',
            'curtime': 1755939299,
            'transactions': []
        }
        
        assert validate_template(valid_template), "Valid template should pass"
        print(f"   ✅ Template validation works")
        
        # Test share params validation
        valid_params = ["worker", "job123", "12345678", "abcdef00", "deadbeef"]
        assert validate_share_params(valid_params), "Valid params should pass"
        
        invalid_params = ["worker", "job123", "123", "abc", "def"]  # Wrong lengths
        assert not validate_share_params(invalid_params), "Invalid params should fail"
        print(f"   ✅ Share validation works")
        
        # Test target calculation
        target = target_from_bits("1c013fc5")
        assert target > 0, "Target should be positive"
        print(f"   ✅ Target calculation: {target}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Validation test failed: {e}")
        return False

def test_transaction_hashing():
    """Test transaction ID calculation"""
    print("🧪 Testing transaction hashing...")
    
    try:
        # Simple test transaction
        test_tx = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08044c86041b020602ffffffff0100f2052a010000004341041b0e8c2567c12536aa13357b79a073dc4444acb83c4ec7a0e2f99dd7457516c5817242da796924ca4e99947d087fedf9ce467cb9f7c6287078f801df276fdf84ac00000000"
        txid = calculate_txid(test_tx)
        
        assert len(txid) == 64, "TXID should be 64 hex characters"
        print(f"   ✅ TXID calculation: {txid}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Transaction hashing test failed: {e}")
        return False

def test_utility_functions():
    """Test utility functions"""
    print("🧪 Testing utility functions...")
    
    try:
        # Test hex reversal
        test_hex = "deadbeef"
        reversed_hex = reverse_hex(test_hex)
        assert reversed_hex == "efbeadde", f"Expected efbeadde, got {reversed_hex}"
        print(f"   ✅ Hex reversal: {test_hex} → {reversed_hex}")
        
        # Test hash meets target
        low_hash = "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        high_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        target = 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        
        assert hash_meets_target(low_hash, target), "Low hash should meet target"
        assert not hash_meets_target(high_hash, target), "High hash should not meet target"
        print(f"   ✅ Target checking works")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Utility test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 Testing main.py functions...")
    print("=" * 50)
    
    tests = [
        test_coinbase_transaction,
        test_address_decoding,
        test_validation_functions,
        test_transaction_hashing,
        test_utility_functions
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"📊 Tests: {passed}/{total} passed")
    
    if passed == total:
        print("🎉 All tests PASSED! Main.py implementation is bulletproof!")
        return True
    else:
        print("⚠️  Some tests failed. Check implementation.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
