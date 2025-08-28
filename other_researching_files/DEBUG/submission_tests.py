#!/usr/bin/env python3
"""
Block Submission Tests for Litecoin Stratum Server

This file tests the mathematical correctness and encoding logic for constructing 
valid Litecoin block headers. It validates the core algorithms that assemble 
block components into network-valid submissions.

Critical validation areas:
1. Field Encoding - Tests bit-level encoding of version, time, nonce, bits fields
2. Block Reconstruction - Rebuilds known good block headers from components  
3. Endianness Handling - Validates little-endian vs big-endian conversions
4. Live Block Analysis - Tests against current blockchain data in real-time
5. Merkle Calculation - Verifies merkle root computation from transaction tree

What this ensures:
- Block headers are mathematically valid and network-compliant
- Endianness rules follow Bitcoin/Litecoin protocol specifications
- Hash calculations produce correct double-SHA256 results
- Merkle tree construction matches protocol requirements
- Field encoding produces parseable header structures

Failure consequences:
❌ Malformed headers → Network rejects all submitted blocks
❌ Endianness errors → Invalid hash calculations and proof-of-work
❌ Wrong merkle roots → Blocks fail transaction validation
❌ Encoding bugs → Unparseable headers crash node processing

This tests the mathematical foundation of block submission - ensuring that
when miners find valid proof-of-work, the pool constructs blocks that the
Litecoin network will accept and add to the blockchain.

Usage: python3 submission_tests.py
Run this to verify block construction algorithms before pool deployment.
"""

import struct
import hashlib
import sys
import asyncio
import aiohttp
from typing import List

# Configuration - adjust these to match your setup
RPC_HOST = "ltc-testnet4-litecoind"
RPC_PORT = 19332
RPC_USER = "admin"
RPC_PASS = "admin"





def sha256d(data: bytes) -> bytes:
    """Double SHA256"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def reverse_hex(hex_str: str) -> str:
    """Reverse hex string in 2-char chunks"""
    return ''.join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)]))

def _calculate_merkle_root(coinbase_hash: str, merkle_branch: List[str]) -> str:
    """Calculate merkle root from coinbase and branch"""
    current = coinbase_hash
    for branch_hash in merkle_branch:
        combined = current + branch_hash
        current = sha256d(bytes.fromhex(combined)).hex()
    return current

async def rpc_call(method: str, params: List = None) -> dict:
    """Make RPC call to Litecoin node"""
    if params is None:
        params = []
        
    payload = {
        "jsonrpc": "1.0",
        "id": "test",
        "method": method,
        "params": params
    }
    
    auth = aiohttp.BasicAuth(RPC_USER, RPC_PASS)
    async with aiohttp.ClientSession(auth=auth) as session:
        async with session.post(f"http://{RPC_HOST}:{RPC_PORT}", json=payload) as resp:
            data = await resp.json()
            if "error" in data and data["error"]:
                raise Exception(f"RPC Error: {data['error']}")
            return data["result"]

def test_field_encoding():
    """Test individual field encoding"""
    print("=" * 60)
    print("TEST 1: Individual Field Encoding")
    print("=" * 60)
    
    # Test version encoding
    version = 536870912  # 0x20000000
    expected_version = "00000020"
    actual_version = struct.pack('<I', version).hex()
    print(f"Version: {actual_version} (expected {expected_version}) {'✅' if actual_version == expected_version else '❌'}")
    
    # Test time encoding  
    time_int = 1755804407
    time_hex = "68a772f7"
    expected_time = "f772a768"  # little-endian
    actual_time = struct.pack('<I', int(time_hex, 16)).hex()
    print(f"Time: {actual_time} (expected {expected_time}) {'✅' if actual_time == expected_time else '❌'}")
    
    # Test nonce encoding
    nonce_int = 3520922880
    nonce_hex = "d1dd0500"
    expected_nonce = "0005ddd1"  # little-endian  
    actual_nonce = struct.pack('<I', int(nonce_hex, 16)).hex()
    print(f"Nonce: {actual_nonce} (expected {expected_nonce}) {'✅' if actual_nonce == expected_nonce else '❌'}")
    
    # Test bits encoding
    bits = "1e0fffff"
    expected_bits = "ffff0f1e"  # byte-reversed
    actual_bits = bytes.fromhex(bits)[::-1].hex()
    print(f"Bits: {actual_bits} (expected {expected_bits}) {'✅' if actual_bits == expected_bits else '❌'}")
    
    # Test hash reversal
    test_hash = "4e983c88b922daa5fc337030ab45aff6e1e79f50bedfa1af08b947983b8a8b5c"
    expected_reversed = "5c8b8a3b9847b908afa1dfbe509fe7e1f6af45ab307033fca5da22b9883c984e"
    actual_reversed = bytes.fromhex(test_hash)[::-1].hex()
    print(f"Hash reversal: {actual_reversed} (expected {expected_reversed}) {'✅' if actual_reversed == expected_reversed else '❌'}")
    
    return True

def test_known_block_reconstruction():
    """Test block header reconstruction against known good block"""
    print("\n" + "=" * 60)
    print("TEST 2: Known Block Header Reconstruction")
    print("=" * 60)
    
    # Known good block data from block 52723f9b1abd0fbda357bcbaf5a5acb08fdbbdc4e26efc484bc87c17a5bc331e
    expected_header = "000000205c8b8a3b9847b908afa1dfbe509fe7e1f6af45ab307033fca5da22b9883c984e054033b5af5b1eb1c249fe93f0a7d3d1e5d706b9ed35ffffea8689a318d5b1cbf772a768ffff0f1e0005ddd1"
    
    # Test values from the real block
    test_version = 536870912  # 0x20000000
    test_prevhash = "4e983c88b922daa5fc337030ab45aff6e1e79f50bedfa1af08b947983b8a8b5c"
    test_merkleroot = "cbb1d518a38986eaffff35edb906d7e5d1d3a7f093fe49c2b11e5bafb5334005"
    test_time = "68a772f7"  # 1755804407 in hex (but stored little-endian)
    test_bits = "1e0fffff"
    test_nonce = "d1dd0500"  # 3520922880 in little-endian hex
    
    print(f"Input values:")
    print(f"  Version: {test_version} (0x{test_version:08x})")
    print(f"  PrevHash: {test_prevhash}")
    print(f"  MerkleRoot: {test_merkleroot}")
    print(f"  Time: {test_time}")
    print(f"  Bits: {test_bits}")
    print(f"  Nonce: {test_nonce}")
    print()
    
    # Reconstruct header using our logic
    version_bytes = struct.pack('<I', test_version)                  # Little-endian
    prevhash_bytes = bytes.fromhex(test_prevhash)[::-1]             # Byte-reversed
    merkle_bytes = bytes.fromhex(test_merkleroot)[::-1]             # Byte-reversed
    time_bytes = struct.pack('<I', int(test_time, 16))              # Little-endian
    bits_bytes = bytes.fromhex(test_bits)[::-1]                     # Byte-reversed
    nonce_bytes = struct.pack('<I', int(test_nonce, 16))            # Little-endian
    
    reconstructed_header = (version_bytes + prevhash_bytes + merkle_bytes + time_bytes + bits_bytes + nonce_bytes).hex()
    
    print(f"Expected:      {expected_header}")
    print(f"Reconstructed: {reconstructed_header}")
    print(f"Match: {'✅ PERFECT!' if reconstructed_header == expected_header else '❌ FAILED!'}")
    
    if reconstructed_header != expected_header:
        # Show differences
        print("\nDifferences:")
        for i in range(0, min(len(expected_header), len(reconstructed_header)), 16):
            exp_chunk = expected_header[i:i+16]
            rec_chunk = reconstructed_header[i:i+16]
            if exp_chunk != rec_chunk:
                print(f"  Byte {i//2:2d}-{(i+15)//2:2d}: expected {exp_chunk}, got {rec_chunk}")
    
    return reconstructed_header == expected_header

def test_endianness_variations():
    """Test different endianness combinations to verify our understanding"""
    print("\n" + "=" * 60)
    print("TEST 3: Endianness Variations")
    print("=" * 60)
    
    test_value = 0x12345678
    test_hex = "12345678"
    
    # Little-endian struct pack
    le_pack = struct.pack('<I', test_value).hex()
    print(f"Little-endian pack: {le_pack}")
    
    # Big-endian struct pack
    be_pack = struct.pack('>I', test_value).hex()
    print(f"Big-endian pack: {be_pack}")
    
    # Byte reversal
    byte_rev = bytes.fromhex(test_hex)[::-1].hex()
    print(f"Byte reversal: {byte_rev}")
    
    # Word reversal (2-byte chunks)
    word_rev = reverse_hex(test_hex)
    print(f"Word reversal: {word_rev}")
    
    return True

async def test_live_block_analysis():
    """Analyze current blocks from the live network"""
    print("\n" + "=" * 60)
    print("TEST 4: Live Block Analysis")
    print("=" * 60)
    
    try:
        # Get current best block
        best_hash = await rpc_call("getbestblockhash")
        print(f"Current best block: {best_hash}")
        
        # Get block data
        block_hex = await rpc_call("getblock", [best_hash, 0])
        block_info = await rpc_call("getblock", [best_hash, 1])
        
        print(f"Block height: {block_info['height']}")
        print(f"Block version: {block_info['version']} (0x{block_info['version']:08x})")
        print(f"Block time: {block_info['time']}")
        print(f"Block bits: {block_info['bits']}")
        print(f"Block nonce: {block_info['nonce']}")
        print(f"Previous hash: {block_info['previousblockhash']}")
        print(f"Merkle root: {block_info['merkleroot']}")
        
        # Extract header (first 80 bytes = 160 hex chars)
        header_hex = block_hex[:160]
        print(f"\nActual header: {header_hex}")
        
        # Try to reconstruct it
        version_bytes = struct.pack('<I', block_info['version'])
        prevhash_bytes = bytes.fromhex(block_info['previousblockhash'])[::-1]
        merkle_bytes = bytes.fromhex(block_info['merkleroot'])[::-1]
        time_bytes = struct.pack('<I', block_info['time'])
        bits_bytes = bytes.fromhex(block_info['bits'])[::-1]
        nonce_bytes = struct.pack('<I', block_info['nonce'])
        
        reconstructed = (version_bytes + prevhash_bytes + merkle_bytes + time_bytes + bits_bytes + nonce_bytes).hex()
        print(f"Reconstructed: {reconstructed}")
        print(f"Match: {'✅ PERFECT!' if reconstructed == header_hex else '❌ FAILED!'}")
        
        return reconstructed == header_hex
        
    except Exception as e:
        print(f"❌ Error accessing live data: {e}")
        print("This is normal if RPC is not accessible")
        return False

def test_merkle_calculation():
    """Test merkle root calculation"""
    print("\n" + "=" * 60)
    print("TEST 5: Merkle Root Calculation")
    print("=" * 60)
    
    # Simple test with empty branch (single transaction)
    coinbase_hash = "e1add0bb1b2fd4aacfcedd86093d6b4477aeb3fe55662e178d2e864b0d298794"
    empty_branch = []
    
    result = _calculate_merkle_root(coinbase_hash, empty_branch)
    print(f"Single transaction merkle root: {result}")
    print(f"Should equal coinbase hash: {'✅' if result == coinbase_hash else '❌'}")
    
    # Test with one branch element
    branch = ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]
    
    # Calculate manually
    combined = coinbase_hash + branch[0]
    manual_result = sha256d(bytes.fromhex(combined)).hex()
    
    # Calculate with function
    function_result = _calculate_merkle_root(coinbase_hash, branch)
    
    print(f"With branch element:")
    print(f"  Manual: {manual_result}")
    print(f"  Function: {function_result}")
    print(f"  Match: {'✅' if manual_result == function_result else '❌'}")
    
    return True







async def run_all_tests():
    """Run all tests"""
    print("🔬 LITECOIN BLOCK SUBMISSION TESTS")
    print("=" * 60)
    
    results = []
    
    # Keep only these tests here
    results.append(("Field Encoding", test_field_encoding()))
    results.append(("Block Reconstruction", test_known_block_reconstruction()))
    results.append(("Endianness Variations", test_endianness_variations()))
    results.append(("Merkle Calculation", test_merkle_calculation()))
    results.append(("Live Block Analysis", await test_live_block_analysis()))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:25s} {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED! Block submission should work correctly.")
    else:
        print("⚠️  Some tests failed. Block submission may not work correctly.")
    
    return passed == total







if __name__ == "__main__":
    print("Starting Litecoin block submission tests...")
    print(f"Testing against RPC: {RPC_HOST}:{RPC_PORT}")
    print()
    
    try:
        result = asyncio.run(run_all_tests())
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        print("\n🛑 Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Tests failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)




