#!/usr/bin/env python3
"""
Submit a constructed block using REAL hardcoded values from an old block.

Uses actual header values and coinbase transaction from block:
6fe25d5a48d892cc12f81c33893ef58ae9433b404ed77cdf10ecf1fa3a927155

This creates a block with valid structure and real proof-of-work values,
but in wrong context (current template's previous hash) to test realistic
rejection scenarios.
"""

import struct
import asyncio
import aiohttp
import os
from typing import List, Dict
import hashlib
import scrypt



# RPC config (env-overridable)
RPC_HOST = os.getenv("RPC_HOST", "ltc-testnet4-litecoind")
RPC_PORT = int(os.getenv("RPC_PORT", "19332"))
RPC_USER = os.getenv("RPC_USER", "admin")
RPC_PASS = os.getenv("RPC_PASS", "admin")
RPC_URL  = f"http://{RPC_HOST}:{RPC_PORT}"





################################################################################
##################################### UTILS ####################################
################################################################################

class StratumUtils:
    @staticmethod
    def sha256d(data: bytes) -> bytes:
        """Double SHA256"""
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()



async def rpc_call(method: str, params: List = None) -> Dict:
    if params is None:
        params = []
    payload = {"jsonrpc": "1.0", "id": "submit", "method": method, "params": params}
    auth = aiohttp.BasicAuth(RPC_USER, RPC_PASS)
    async with aiohttp.ClientSession(auth=auth) as session:
        async with session.post(RPC_URL, json=payload) as resp:
            data = await resp.json()
            if "error" in data and data["error"]:
                raise Exception(f"RPC Error: {data['error']}")
            return data["result"]



################################################################################
################################################################################
################################################################################




class MerkleTree:

    @staticmethod
    def calculate_merkle_branch(tx_hashes_be: List[str], index_to_prove: int) -> List[str]:
        """
        Calculates the merkle branch for a transaction at a given index.
        Uses proven algorithm with proper endianness handling.
        """
        if not tx_hashes_be:
            return []

        # Start with all txids as raw bytes (NO endianness conversion for hashing)
        level = [bytes.fromhex(txid) for txid in tx_hashes_be]
        branch = []
        idx = index_to_prove

        while len(level) > 1:
            # Pad to even count
            if len(level) % 2 == 1:
                level.append(level[-1])

            # Find sibling using XOR operation
            sibling_idx = idx ^ 1
            if sibling_idx < len(level):
                # Store sibling as hex for branch
                sibling_hex = level[sibling_idx].hex()
                branch.append(sibling_hex)

            # Build next level
            next_level = []
            for i in range(0, len(level), 2):
                combined = level[i] + level[i + 1]
                next_level.append(StratumUtils.sha256d(combined))

            level = next_level
            idx //= 2

        return branch



    @staticmethod
    def calculate_merkle_root_from_branch(leaf_hex: str, branch: List[str], index: int) -> str:
        """
        Correctly calculates a merkle root from a leaf, its branch, and its index.
        Uses proven algorithm with proper endianness handling.
        """
        # Start with leaf as raw bytes (NO endianness conversion for hashing)
        current = bytes.fromhex(leaf_hex)
        
        for sibling_hex in branch:
            sibling = bytes.fromhex(sibling_hex)  # Raw bytes, no conversion
            if index % 2 == 1:
                combined = sibling + current
            else:
                combined = current + sibling
            current = StratumUtils.sha256d(combined)
            index //= 2
        
        # Return as little-endian hex (header format)
        return current.hex()









##### BLOCK HEADER (HEIGHT 4220700) #####
# 00000020 c97db626cccc4ced08132471875db3d1673e4bf4f451b8182f64e63ee2339b02 
#          09ad4abb1edc2346276cecccf28b190c9be102d6f500ad2c1bfc5d82c508ca1e 
# e381a968 c53f011c d07c2be8 
# 02 

# COINBASE:
# 01000000 00 01 01 0000000000000000000000000000000000000000000000000000000000000000
# ffffffff 5b 
# 031c674029303043796265724c65617020496e6330300000000070e4452e4d415054000002b965140000000000002cfabe6d6d16ea38fd0f7afd6b6e1b2876b28e91a54cf18bfb215dd099ed617eba7aab918d040000008d685c75 
# ffffffff 02 902f500900000000 16 00141c938ba09d3d0b35c27d717e56591985917eb726 
# 0000000000000000 26 6a24aa21a9edeed80146b83c2bba1755065136024c5aa2e313f7455a8e785eb200338eda5680
# 01 20 000000000000000000000000000000000000000000000000000000000000000000000000





# MWEB:
# 02000000 00 08 01 c7467fbe765e591e9f6908c39bb352d8c1544271d895bbbcd89d65030fcff572
# 00000000 00 ffffffff 01 88fd9e3012a30000 22 
# 582093aa3b00ccbad8ba1addb6a585b6dc9f78729ff4b1a5c440b66acd287e4bb671
# 00000000 00 01 81 80cd1c03fe60d1ffdb723253250e50b72b8d1e14be1967cd2b7b77140aac029263
# 10 440000000000000000000000000000000000000000000000000000000000000000 
# a17418f325b569109db7819c9b47b407cd5cf0540b396245d1cebb56ebf3fcd5b3
# 789d499122b19789ad675850c089fee9bdc75a0655203e2b0d165033eafa7b
# 0000000000000000000000000000000000000000000000000000000000000000
# b30700000000


# Useful links:
# https://www.blockchain.com/explorer/assets/btc/decode-transaction


# HARDCODED VALUES FROM REAL BLOCK (HEIGHT 4220700)
REAL_BLOCK_RAW = "00000020c97db626cccc4ced08132471875db3d1673e4bf4f451b8182f64e63ee2339b0209ad4abb1edc2346276cecccf28b190c9be102d6f500ad2c1bfc5d82c508ca1ee381a968c53f011cd07c2be802010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff5b031c674029303043796265724c65617020496e6330300000000070e4452e4d415054000002b965140000000000002cfabe6d6d16ea38fd0f7afd6b6e1b2876b28e91a54cf18bfb215dd099ed617eba7aab918d040000008d685c75ffffffff02902f5009000000001600141c938ba09d3d0b35c27d717e56591985917eb7260000000000000000266a24aa21a9edeed80146b83c2bba1755065136024c5aa2e313f7455a8e785eb200338eda5680012000000000000000000000000000000000000000000000000000000000000000000000000002000000000801c7467fbe765e591e9f6908c39bb352d8c1544271d895bbbcd89d65030fcff5720000000000ffffffff0188fd9e3012a3000022582093aa3b00ccbad8ba1addb6a585b6dc9f78729ff4b1a5c440b66acd287e4bb6710000000000018180cd1c03fe60d1ffdb723253250e50b72b8d1e14be1967cd2b7b77140aac02926310440000000000000000000000000000000000000000000000000000000000000000a17418f325b569109db7819c9b47b407cd5cf0540b396245d1cebb56ebf3fcd5b3789d499122b19789ad675850c089fee9bdc75a0655203e2b0d165033eafa7b0000000000000000000000000000000000000000000000000000000000000000b30700000000"
REAL_BLOCK_HASH = "6fe25d5a48d892cc12f81c33893ef58ae9433b404ed77cdf10ecf1fa3a927155"
REAL_BLOCK_VALUES = {
    "version": "00000020",
    "prev_hash": "c97db626cccc4ced08132471875db3d1673e4bf4f451b8182f64e63ee2339b02", # Explorer: 029b33e23ee6642f18b851f4f44b3e67d1b35d8771241308ed4ccccc26b67dc9
    "merkle_root": "09ad4abb1edc2346276cecccf28b190c9be102d6f500ad2c1bfc5d82c508ca1e", 
    "timestamp": "e381a968",
    "bits": "c53f011c",
    "nonce": "d07c2be8",
    "transaction_count": "02",
    "coinbase_tx": {
        "version": "01000000",  # Version 1
        "segwit_marker": "00",  # SegWit marker
        "segwit_flag": "01",    # SegWit flag
        "input_count": "01",    # 1 input
        "input": {
            "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",  # Null hash (coinbase)
            "prev_index": "ffffffff",  # Coinbase marker
            "script_length": "5b",      # 91 bytes
            "script": "031c674029303043796265724c65617020496e6330300000000070e4452e4d415054000002b965140000000000002cfabe6d6d16ea38fd0f7afd6b6e1b2876b28e91a54cf18bfb215dd099ed617eba7aab918d040000008d685c75",  # Coinbase script
            "sequence": "ffffffff"     # Sequence
        },
        "output_count": "02",   # 2 outputs
        "outputs": [
            {
                "value": "902f500900000000",  # Block reward (little-endian)
                "script_length": "16",        # 22 bytes
                "script": "00141c938ba09d3d0b35c27d717e56591985917eb726"  # P2WPKH script
            },
            {
                "value": "0000000000000000",  # 0 value (OP_RETURN)
                "script_length": "26",        # 38 bytes  
                "script": "6a24aa21a9edeed80146b83c2bba1755065136024c5aa2e313f7455a8e785eb200338eda5680"  # Witness commitment
            }
        ],
        "witness_stack_count": "01",  # 1 witness stack (for 1 input)
        "witness_item_length": "20",  # 32 bytes (0x20)
        "witness_item": "0000000000000000000000000000000000000000000000000000000000000000",  # 32 zero bytes
        "locktime": "00000000"        # Locktime 0
    },
    "mweb": {
        "version": "02000000",
        "witness_marker": "00",
        "witness_flag": "08",
        "input_count": "01",                # 1 input
        "input": {
            "prev_txid": "c7467fbe765e591e9f6908c39bb352d8c1544271d895bbbcd89d65030fcff572",  # Reversed txid
            "prev_vout": "00000000",        # vout 0 (little-endian)
            "script_length": "00",          # Empty scriptSig
            "script": "",                   # Empty
            "sequence": "ffffffff"          # Sequence
        },
        "output_count": "01",  # 1 output
        "output": {
            "value": "88fd9e3012a30000",  # Input value (8 bytes, little-endian)
            "script_length": "22",  # 34 bytes
            "script": "582093aa3b00ccbad8ba1addb6a585b6dc9f78729ff4b1a5c440b66acd287e4bb671"  # MWEB input script
        },
        "locktime": "00000000",
        "witness_stack_count_for_txid": "00",
        "mweb_extension": {
            "extension_count": "01",  # 1 extension
            "extension_type": "81",   # Extension type 
            "output_root": "80cd1c03fe60d1ffdb723253250e50b72b8d1e14be1967cd2b7b77140aac029263",
            "kernel_size": "10",      # 16 bytes
            "kernel_root": "440000000000000000000000000000000000000000000000000000000000000000",
            "leaf_root": "a17418f325b569109db7819c9b47b407cd5cf0540b396245d1cebb56ebf3fcd5b3", 
            "kernel_offset": "789d499122b19789ad675850c089fee9bdc75a0655203e2b0d165033eafa7b",
            "stealth_offset": "0000000000000000000000000000000000000000000000000000000000000000",
            "final_field": "b30700000000"  # Final 6-byte field
        }
    }
}









def hash_real_block_header():
    """Hash the real block header and verify against known hash"""
    
    print("\n\n🚀 [*] RECONSTRUCTING BLOCK HEADER...")
    print("=" * 60)
    
    ###################################################################
    ############ Reconstruct header from our parsed values ############
    ###################################################################
    header_hex = (
        REAL_BLOCK_VALUES["version"] +           # 00000020
        REAL_BLOCK_VALUES["prev_hash"] +         # c97db626cccc4ced08132471875db3d1673e4bf4f451b8182f64e63ee2339b02  
        REAL_BLOCK_VALUES["merkle_root"] +       # 09ad4abb1edc2346276cecccf28b190c9be102d6f500ad2c1bfc5d82c508ca1e
        REAL_BLOCK_VALUES["timestamp"] +         # e381a968
        REAL_BLOCK_VALUES["bits"] +              # c53f011c  
        REAL_BLOCK_VALUES["nonce"]               # d07c2be8
    )
    header_bytes = bytes.fromhex(header_hex)
    ###################################################################
    ###################################################################
    ###################################################################
    


    ##########################################
    ######### Block SHA256 Hash Test #########
    ##########################################

    # Double SHA256 (Bitcoin/Litecoin standard)
    hash1 = hashlib.sha256(header_bytes).digest()
    hash2 = hashlib.sha256(hash1).digest()
    
    # Reverse bytes for display (Bitcoin/Litecoin convention)
    block_hash = hash2[::-1].hex()
    
    # Expected hash
    expected_hash = REAL_BLOCK_HASH
    
    print(f"    SHA256 Hash Results:")
    print(f"      Calculated hash: {block_hash}")
    print(f"      Expected hash:   {expected_hash}  {'✅' if block_hash == expected_hash else '❌'}")
    ##########################################
    ##########################################
    ##########################################


    ##########################################
    ############# SCRYPT Hash Test ###########
    ##########################################
    scrypt_hash = scrypt.hash(header_bytes, header_bytes, 1024, 1, 1, 32)
    
    # Show both formats
    raw_hash = scrypt_hash.hex()                    # Raw hash (shows leading zeros!)
    display_hash = scrypt_hash[::-1].hex()          # Reversed for display (standard format)
        
    print(f"    SCRYPT Hash Results:")
    print(f"      Calculated hash: {display_hash}")
    ##########################################
    ##########################################
    ##########################################






def reconstruct_whole_block():
    """Reconstruct the whole block from our parsed values"""
    
    print("\n\n🚀 [*] RECONSTRUCTING BLOCK WHOLE BLOCK...")
    print("=" * 60)
    
    # 1. RECONSTRUCT HEADER (80 bytes)
    header = (
        REAL_BLOCK_VALUES["version"] +
        REAL_BLOCK_VALUES["prev_hash"] +
        REAL_BLOCK_VALUES["merkle_root"] +
        REAL_BLOCK_VALUES["timestamp"] +
        REAL_BLOCK_VALUES["bits"] +
        REAL_BLOCK_VALUES["nonce"]
    )
    
    # 2. TRANSACTION COUNT (1 byte) - this block has 2 transactions
    tx_count = REAL_BLOCK_VALUES["transaction_count"]
    
    # 3. RECONSTRUCT COINBASE TRANSACTION
    cb = REAL_BLOCK_VALUES["coinbase_tx"]
    coinbase_tx = (
        cb["version"] +
        cb["segwit_marker"] +
        cb["segwit_flag"] +
        cb["input_count"] +
        cb["input"]["prev_hash"] +
        cb["input"]["prev_index"] +
        cb["input"]["script_length"] +
        cb["input"]["script"] +
        cb["input"]["sequence"] +
        cb["output_count"] +
        cb["outputs"][0]["value"] +
        cb["outputs"][0]["script_length"] +
        cb["outputs"][0]["script"] +
        cb["outputs"][1]["value"] +
        cb["outputs"][1]["script_length"] +
        cb["outputs"][1]["script"] +
        cb["witness_stack_count"] +
        cb["witness_item_length"] +
        cb["witness_item"] +
        cb["locktime"]
    )
    
    # 4. RECONSTRUCT MWEB TRANSACTION (full with extension - for block, not just TXID)
    mweb = REAL_BLOCK_VALUES["mweb"]
    mweb_full_tx = (
        mweb["version"] +                        # 02000000
        mweb["witness_marker"] +                 # 00
        mweb["witness_flag"] +                   # 08
        mweb["input_count"] +                    # 01
        mweb["input"]["prev_txid"] +             # c7467fbe...
        mweb["input"]["prev_vout"] +             # 00000000
        mweb["input"]["script_length"] +        # 00
        mweb["input"]["script"] +                # (empty)
        mweb["input"]["sequence"] +              # ffffffff
        mweb["output_count"] +                   # 01
        mweb["output"]["value"] +                # 88fd9e3012a30000
        mweb["output"]["script_length"] +       # 22
        mweb["output"]["script"] +               # 582093aa...
        mweb["locktime"] +                       # 00000000
        mweb["witness_stack_count_for_txid"] +   # 00
        # MWEB Extension Block Data (this goes in the block, not transaction)
        mweb["mweb_extension"]["extension_count"] +
        mweb["mweb_extension"]["extension_type"] +
        mweb["mweb_extension"]["output_root"] +
        mweb["mweb_extension"]["kernel_size"] +
        mweb["mweb_extension"]["kernel_root"] +
        mweb["mweb_extension"]["leaf_root"] +
        mweb["mweb_extension"]["kernel_offset"] +
        mweb["mweb_extension"]["stealth_offset"] +
        mweb["mweb_extension"]["final_field"]
    )
    
    # 5. COMBINE EVERYTHING
    reconstructed_block = header + tx_count + coinbase_tx + mweb_full_tx
    
    print(f"    Header: {header}")
    print(f"    Transaction count: {tx_count}")
    print(f"    Partial block (header + tx_count + coinbase): {len(header + tx_count + coinbase_tx)//2} bytes")
    if header + tx_count + coinbase_tx == REAL_BLOCK_RAW[:len(header + tx_count + coinbase_tx)]:
        print(f"      MATCH: ✅")
    else:
        print(f"      MISMATCH: ❌")
    
    print(f"\n    📊 Block Reconstruction Results:")
    print(f"     Reconstructed: {reconstructed_block[:100]}...")
    print(f"     Original:      {REAL_BLOCK_RAW[:100]}...")
    print(f"     Reconstructed length: {len(reconstructed_block)//2} bytes")
    print(f"     Original length:      {len(REAL_BLOCK_RAW)//2} bytes")
    print(f"     Match: {'✅ PERFECT!' if reconstructed_block == REAL_BLOCK_RAW else '❌ MISMATCH!'}")
    
    return reconstructed_block == REAL_BLOCK_RAW












def reconstruct_merkle_root():
    """Reconstruct the merkle root from the coinbase and mweb transactions"""
    
    print("\n\n🚀 [*] RECONSTRUCTING MERKLE ROOT...")
    print("=" * 60)
    
    # 1. RECONSTRUCT COINBASE TRANSACTION
    cb = REAL_BLOCK_VALUES["coinbase_tx"]
    coinbase_tx = (
        cb["version"] +
        cb["segwit_marker"] +
        cb["segwit_flag"] +
        cb["input_count"] +
        cb["input"]["prev_hash"] +
        cb["input"]["prev_index"] +
        cb["input"]["script_length"] +
        cb["input"]["script"] +
        cb["input"]["sequence"] +
        cb["output_count"] +
        cb["outputs"][0]["value"] +
        cb["outputs"][0]["script_length"] +
        cb["outputs"][0]["script"] +
        cb["outputs"][1]["value"] +
        cb["outputs"][1]["script_length"] +
        cb["outputs"][1]["script"] +
        cb["witness_stack_count"] +
        cb["witness_item_length"] +
        cb["witness_item"] +
        cb["locktime"]
    )
    coinbase_no_witness = (
        cb["version"] +                          # 01000000
        cb["input_count"] +                      # 01 (skip segwit marker/flag)
        cb["input"]["prev_hash"] +
        cb["input"]["prev_index"] +
        cb["input"]["script_length"] +
        cb["input"]["script"] +
        cb["input"]["sequence"] +
        cb["output_count"] +
        cb["outputs"][0]["value"] +
        cb["outputs"][0]["script_length"] +
        cb["outputs"][0]["script"] +
        cb["outputs"][1]["value"] +
        cb["outputs"][1]["script_length"] +
        cb["outputs"][1]["script"] +
        cb["locktime"]                           # 00000000
    )
    print(f"    Coinbase TX length: {len(coinbase_tx)} chars")
    print(f"    Coinbase TX: {coinbase_tx}")

    # Hash coinbase transaction (double SHA256)
    coinbase_bytes = bytes.fromhex(coinbase_tx)
    coinbase_hash = hashlib.sha256(hashlib.sha256(coinbase_bytes).digest()).digest()
    coinbase_hash_hex_viewable = coinbase_hash[::-1].hex() # Reverse for readable format
    print(f"    Coinbase hash: {coinbase_hash_hex_viewable}")

    coinbase_txid_bytes = hashlib.sha256(hashlib.sha256(bytes.fromhex(coinbase_no_witness)).digest()).digest()
    coinbase_txid_hex_viewable = coinbase_txid_bytes[::-1].hex()  # Reverse for readable format
    print(f"    Coinbase TXID: {coinbase_txid_hex_viewable}")
    print("\n\n")
    
    



    
    # 2. RECONSTRUCT MWEB TRANSACTION  
    mweb = REAL_BLOCK_VALUES["mweb"]
    # For MWEB TXID calculation, exclude witness marker/flag/data (like standard SegWit)
    mweb_tx = (
        mweb["version"] +                        # 02000000
        # Skip witness_marker and witness_flag for TXID
        mweb["input_count"] +                    # 01
        mweb["input"]["prev_txid"] +             # c7467fbe...
        mweb["input"]["prev_vout"] +             # 00000000
        mweb["input"]["script_length"] +        # 00
        mweb["input"]["script"] +                # (empty)
        mweb["input"]["sequence"] +              # ffffffff
        mweb["output_count"] +                   # 01
        mweb["output"]["value"] +                # 88fd9e3012a30000
        mweb["output"]["script_length"] +       # 22
        mweb["output"]["script"] +               # 582093aa...
        mweb["locktime"]                         # 00000000
    )
    mweb_full = (
        mweb["version"] +
        mweb["witness_marker"] +                 # 00
        mweb["witness_flag"] +                   # 08
        mweb["input_count"] +
        mweb["input"]["prev_txid"] +
        mweb["input"]["prev_vout"] +
        mweb["input"]["script_length"] +
        mweb["input"]["script"] +
        mweb["input"]["sequence"] +
        mweb["output_count"] +
        mweb["output"]["value"] +
        mweb["output"]["script_length"] +
        mweb["output"]["script"] +
        mweb["locktime"]
    )

    print(f"    MWEB TX length: {len(mweb_full)} chars")
    print(f"    MWEB TX: {mweb_full}")

    # Calculate TXID (without witness)
    mweb_tx_bytes = bytes.fromhex(mweb_tx)
    mweb_txid_bytes = hashlib.sha256(hashlib.sha256(mweb_tx_bytes).digest()).digest()
    mweb_txid_hex_viewable = mweb_txid_bytes[::-1].hex()
    print(f"    MWEB TXID and hash: {mweb_txid_hex_viewable}")

    

    
    # 4. BUILD MERKLE TREE OLD METHOD
    print(f"\n    🌳 Building merkle tree OLD METHOD:")
    
    # Start with transaction hashes
    tx_hashes = [coinbase_txid_bytes, mweb_txid_bytes]
    print(f"    Level 0 (transactions): {len(tx_hashes)} hashes")
    print(f"      TX 0: {tx_hashes[0].hex()}")
    print(f"      TX 1: {tx_hashes[1].hex()}")
    
    level = 0
    while len(tx_hashes) > 1:
        level += 1
        next_level = []
        
        # Process pairs
        for i in range(0, len(tx_hashes), 2):
            left = tx_hashes[i]
            
            if i + 1 < len(tx_hashes):
                right = tx_hashes[i + 1]
            else:
                right = left  # Duplicate if odd number
                print(f"      (Duplicating last hash for odd count)")
            
            # Combine and hash
            combined = left + right
            parent_hash = hashlib.sha256(hashlib.sha256(combined).digest()).digest()
            next_level.append(parent_hash)
            
            print(f"    Level {level}: Combining {left.hex()[:16]}... + {right.hex()[:16]}...")
            print(f"             → {parent_hash.hex()}")
        
        tx_hashes = next_level
        print(f"    Level {level}: {len(tx_hashes)} hashes")
    
    # 5. COMPARE WITH EXPECTED MERKLE ROOT
    calculated_merkle_root = tx_hashes[0].hex()
    expected_merkle_root = REAL_BLOCK_VALUES["merkle_root"]
    
    # Note: The expected merkle root in our block is in storage format (little-endian)
    
    print(f"\n    📊 Merkle Root Results:")
    print(f"     Calculated:     {calculated_merkle_root}")
    print(f"     Expected (raw): {expected_merkle_root}")
    print(f"     Match: {'✅ PERFECT!' if calculated_merkle_root == expected_merkle_root else '❌ MISMATCH!'}")
    print("\n\n")



    # 6. BUILD MERKLE TREE NEW METHOD
    print(f"\n    🌳 Building merkle tree NEW METHOD:")

    # Start with transaction hashes
    tx_hashes = [coinbase_txid_bytes.hex(), mweb_txid_bytes.hex()]
    print(f"    Level 0 (transactions): {len(tx_hashes)} hashes")
    print(f"      TX 0: {tx_hashes[0]}")
    print(f"      TX 1: {tx_hashes[1]}")

    merkle_branch = MerkleTree.calculate_merkle_branch(tx_hashes, 0)
    merkle_root_le = MerkleTree.calculate_merkle_root_from_branch(
        coinbase_txid_bytes.hex(), merkle_branch, 0
    )

    print(f"    Merkle Branch: {str(merkle_branch)}")

    print(f"\n    📊 Merkle Root Results (NEW METHOD):")
    print(f"     Calculated:     {merkle_root_le}")
    print(f"     Expected (raw): {expected_merkle_root}")
    print(f"     Match: {'✅ PERFECT!' if merkle_root_le == expected_merkle_root else '❌ MISMATCH!'}")
    print("\n\n")









async def submit_block():
    """Submit the reconstructed block to the network"""
    
    print("\n\n🚀 [*] SUBMITTING RECONSTRUCTED BLOCK...")
    print("=" * 60)
    
    # 1. RECONSTRUCT THE COMPLETE BLOCK
    print("🔨 Reconstructing complete block...")
    
    # Header
    header = (
        REAL_BLOCK_VALUES["version"] +
        REAL_BLOCK_VALUES["prev_hash"] +
        REAL_BLOCK_VALUES["merkle_root"] +
        REAL_BLOCK_VALUES["timestamp"] +
        REAL_BLOCK_VALUES["bits"] +
        REAL_BLOCK_VALUES["nonce"]
    )
    
    # Transaction count
    tx_count = "02"
    
    # Coinbase transaction
    cb = REAL_BLOCK_VALUES["coinbase_tx"]
    coinbase_tx = (
        cb["version"] +
        cb["segwit_marker"] +
        cb["segwit_flag"] +
        cb["input_count"] +
        cb["input"]["prev_hash"] +
        cb["input"]["prev_index"] +
        cb["input"]["script_length"] +
        cb["input"]["script"] +
        cb["input"]["sequence"] +
        cb["output_count"] +
        cb["outputs"][0]["value"] +
        cb["outputs"][0]["script_length"] +
        cb["outputs"][0]["script"] +
        cb["outputs"][1]["value"] +
        cb["outputs"][1]["script_length"] +
        cb["outputs"][1]["script"] +
        cb["witness_stack_count"] +          # Fixed: use correct field names
        cb["witness_item_length"] +          # Fixed: use correct field names
        cb["witness_item"] +                 # Fixed: use correct field names
        cb["locktime"]
    )
    
    # MWEB transaction
    mweb = REAL_BLOCK_VALUES["mweb"]
    mweb_full_tx = (
        mweb["version"] +                        # Fixed: use correct field names
        mweb["witness_marker"] +
        mweb["witness_flag"] +
        mweb["input_count"] +
        mweb["input"]["prev_txid"] +             # Fixed: use correct field names
        mweb["input"]["prev_vout"] +
        mweb["input"]["script_length"] +
        mweb["input"]["script"] +
        mweb["input"]["sequence"] +
        mweb["output_count"] +
        mweb["output"]["value"] +                # Fixed: use correct field names
        mweb["output"]["script_length"] +
        mweb["output"]["script"] +
        mweb["locktime"] +
        mweb["witness_stack_count_for_txid"] +   # Fixed: use correct field names
        # MWEB Extension Block Data
        mweb["mweb_extension"]["extension_count"] +
        mweb["mweb_extension"]["extension_type"] +
        mweb["mweb_extension"]["output_root"] +
        mweb["mweb_extension"]["kernel_size"] +
        mweb["mweb_extension"]["kernel_root"] +
        mweb["mweb_extension"]["leaf_root"] +
        mweb["mweb_extension"]["kernel_offset"] +
        mweb["mweb_extension"]["stealth_offset"] +
        mweb["mweb_extension"]["final_field"]
    )
    
    # Complete block
    complete_block = header + tx_count + coinbase_tx + mweb_full_tx
    
    print(f"✅ Block reconstructed:")
    print(f"   Size: {len(complete_block)//2} bytes")
    print(f"   Hash: {REAL_BLOCK_HASH}")
    print(f"   Height: 4220700")
    
    # 2. SUBMIT TO NETWORK
    print(f"\n🌐 Submitting to {RPC_URL}...")
    
    result = await rpc_call("submitblock", [complete_block])
        
    print(f"   Result: {result}")



hash_real_block_header()
reconstruct_whole_block()
reconstruct_merkle_root()


async def async_tests():
    await submit_block()
    print("\n\n")

if __name__ == "__main__":
    raise SystemExit(asyncio.run(async_tests()))
