# # Test with the exact values from the failed share:
# header_hex = "0000002059cf22c01b106abdaf8559a7d792cac3d6039eb9a9f6c7d42aebedb35cebc4e45801297159c267283cd02bdf1f2662dc72c973d9e3b7bb2c2e65f255c4df6c06afc0aa68c53f011cd27a10b0"
# # Try different endian combinations for ntime and nonce (the submitted values)
# import scrypt
# import hashlib

# def test_header_variants(base_header):
#     """Test different endianness for the submitted ntime/nonce"""
#     # Extract components (last 8 bytes are ntime + nonce)
#     prefix = base_header[:-16]  # Everything except last 8 bytes
#     submitted_ntime = "afc0aa68"  # From miner
#     submitted_nonce = "d27a10b0"  # From miner
    
#     variants = [
#         (submitted_ntime, submitted_nonce),                          # As submitted
#         (submitted_ntime[::-1], submitted_nonce),                    # Reverse ntime
#         (submitted_ntime, submitted_nonce[::-1]),                    # Reverse nonce  
#         (submitted_ntime[::-1], submitted_nonce[::-1]),             # Reverse both
#     ]
    
#     for i, (ntime, nonce) in enumerate(variants):
#         test_header = prefix + ntime + nonce  # Fixed: removed submitted_nbits
#         header_bytes = bytes.fromhex(test_header)
#         scrypt_result = scrypt.hash(header_bytes, header_bytes, 1024, 1, 1, 32)[::-1].hex()
#         print(f"Variant {i}: ntime={ntime}, nonce={nonce}")
#         print(f"  Result: {scrypt_result}")
#         if scrypt_result.startswith("000000"):
#             print(f"  *** FOUND MATCH! ***")

# test_header_variants(header_hex)














# import struct
# import scrypt

# def le32dec(hex_str):
#     """Convert 4-byte hex string to little-endian 32-bit value"""
#     return struct.unpack('<I', bytes.fromhex(hex_str))[0]

# def be32dec(hex_str):
#     """Convert 4-byte hex string to big-endian 32-bit value"""
#     return struct.unpack('>I', bytes.fromhex(hex_str))[0]

# def build_cpuminer_header():
#     """Build header exactly as cpuminer does in stratum_gen_work()"""
    
#     # Values from the mining.notify
#     version_hex = "00000020"
#     prevhash_hex = "59cf22c01b106abdaf8559a7d792cac3d6039eb9a9f6c7d42aebedb35cebc4e4"
#     merkle_root_hex = "5801297159c267283cd02bdf1f2662dc72c973d9e3b7bb2c2e65f255c4df6c06"  # Our calculated value
#     ntime_hex = "afc0aa68"
#     nbits_hex = "c53f011c"
#     nonce = 0xb0107ad2  # The nonce the miner found (d27a10b0 as uint32)
    
#     # Create work->data array (32 words = 128 bytes, but we only need first 80)
#     work_data = [0] * 32
    
#     # work->data[0] = le32dec(version)
#     work_data[0] = le32dec(version_hex)
    
#     # for (i = 0; i < 8; i++) work->data[1 + i] = le32dec((uint32_t *)prevhash + i)
#     for i in range(8):
#         chunk = prevhash_hex[i*8:(i+1)*8]
#         work_data[1 + i] = le32dec(chunk)
    
#     # for (i = 0; i < 8; i++) work->data[9 + i] = be32dec((uint32_t *)merkle_root + i)
#     for i in range(8):
#         chunk = merkle_root_hex[i*8:(i+1)*8]
#         work_data[9 + i] = be32dec(chunk)
    
#     # work->data[17] = le32dec(ntime)
#     work_data[17] = le32dec(ntime_hex)
    
#     # work->data[18] = le32dec(nbits)
#     work_data[18] = le32dec(nbits_hex)
    
#     # work->data[19] = nonce (set by miner)
#     work_data[19] = nonce
    
#     # Convert to bytes (first 80 bytes = 20 words)
#     header_bytes = b''.join(struct.pack('<I', work_data[i]) for i in range(20))
    
#     return header_bytes

# # Test the cpuminer-exact construction
# header_bytes = build_cpuminer_header()
# print(f"CPUMiner header (80 bytes): {header_bytes.hex()}")
# print(f"Header length: {len(header_bytes)} bytes")

# # Hash it
# scrypt_result = scrypt.hash(header_bytes, header_bytes, 1024, 1, 1, 32)[::-1].hex()
# print(f"Scrypt result: {scrypt_result}")

# # Check if it matches the miner's result
# expected = "000000406307787a08a34e7b2fb2943760fffba160d28d989381e6499de4bde0"
# if scrypt_result == expected:
#     print("*** PERFECT MATCH! This is how cpuminer builds the header! ***")
# else:
#     print(f"Expected: {expected}")
#     print(f"Got:      {scrypt_result}")









# import struct
# import hashlib
# import scrypt

# def sha256d(data):
#     """Double SHA256"""
#     return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# def le32dec(hex_str):
#     """Convert 4-byte hex string to little-endian 32-bit value"""
#     return struct.unpack('<I', bytes.fromhex(hex_str))[0]

# def be32dec(binary_data):
#     """Convert 4 binary bytes to big-endian 32-bit value"""
#     return struct.unpack('>I', binary_data)[0]

# def build_cpuminer_header():
#     """Build header exactly as cpuminer does"""
    
#     # Data from the actual mining.notify
#     version_hex = "00000020"
#     prevhash_hex = "59cf22c01b106abdaf8559a7d792cac3d6039eb9a9f6c7d42aebedb35cebc4e4"
#     ntime_hex = "afc0aa68"
#     nbits_hex = "c53f011c"
#     nonce = 0xd27a10b0  # Correct nonce value
    
#     # Coinbase construction (exactly as cpuminer receives it)
#     coinb1 = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2203586940"
#     extra_nonce1 = "00000000"
#     extra_nonce2 = "00000000"
#     coinb2 = "4d696e656420427920546f6d61732056616e61676173ffffffff02902f500900000000160014462bf26c29e00ee732f4d475a7ddb0dfb29bc7390000000000000000286a246a24aa21a9edd23506a69eba4a2a45ab88e419656334fd1934fc3306a5368ad020501880225800000000"
    
#     # Build coinbase exactly as cpuminer does
#     coinbase_hex = coinb1 + extra_nonce1 + extra_nonce2 + coinb2
#     coinbase_binary = bytes.fromhex(coinbase_hex)
    
#     # Calculate merkle root exactly as cpuminer does
#     merkle_root = sha256d(coinbase_binary)  # Start with coinbase txid
    
#     # Apply merkle branch (from mining.notify)
#     merkle_branch = ["3a51246501497061f5e8dc0286abdf08758994201b9fff99486925f9d7c0387a"]
    
#     for branch_hex in merkle_branch:
#         branch_binary = bytes.fromhex(branch_hex)
#         # Concatenate current merkle_root + branch, then hash
#         combined = merkle_root + branch_binary
#         merkle_root = sha256d(combined)
    
#     print(f"Calculated merkle root (binary): {merkle_root.hex()}")
    
#     # Now build the header exactly as cpuminer does
#     work_data = [0] * 32
    
#     # Version
#     work_data[0] = le32dec(version_hex)
    
#     # Prevhash (8 chunks of 4 bytes each, LE decoded)
#     for i in range(8):
#         chunk = prevhash_hex[i*8:(i+1)*8]
#         work_data[1 + i] = le32dec(chunk)
    
#     # Merkle root (8 chunks of 4 bytes each, BE decoded from binary)
#     for i in range(8):
#         chunk_binary = merkle_root[i*4:(i+1)*4]
#         work_data[9 + i] = be32dec(chunk_binary)
    
#     # Time and bits
#     work_data[17] = le32dec(ntime_hex)
#     work_data[18] = le32dec(nbits_hex)
    
#     # Nonce
#     work_data[19] = nonce
    
#     # Convert to 80-byte header
#     header_bytes = b''.join(struct.pack('<I', work_data[i]) for i in range(20))
    
#     return header_bytes, merkle_root.hex()

# # Test it
# header_bytes, merkle_root_hex = build_cpuminer_header()
# print(f"CPUMiner header: {header_bytes.hex()}")
# print(f"Merkle root hex: {merkle_root_hex}")

# # Hash it
# scrypt_result = scrypt.hash(header_bytes, header_bytes, 1024, 1, 1, 32)[::-1].hex()
# print(f"Scrypt result: {scrypt_result}")

# # Check if it matches
# expected = "000000406307787a08a34e7b2fb2943760fffba160d28d989381e6499de4bde0"
# if scrypt_result == expected:
#     print("*** PERFECT MATCH! ***")
# else:
#     print(f"Expected: {expected}")





# import hashlib
# import scrypt

# def sha256d(data):
#     return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# # Exact coinbase from server
# coinbase_hex = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff220358694000000000000000004d696e656420427920546f6d61732056616e61676173ffffffff02902f500900000000160014462bf26c29e00ee732f4d475a7ddb0dfb29bc7390000000000000000286a246a24aa21a9edd23506a69eba4a2a45ab88e419656334fd1934fc3306a5368ad020501880225800000000"
# coinbase_binary = bytes.fromhex(coinbase_hex)

# # Calculate coinbase TXID
# coinbase_txid = sha256d(coinbase_binary)
# print(f"Coinbase TXID (LE): {coinbase_txid.hex()}")
# print(f"Coinbase TXID (BE): {coinbase_txid[::-1].hex()}")

# # Server reports coinbase_txid_be as: 45b393be6ca5049c9a0e0232379bea36ca9232d101c9c0179b3f1cc0e3922d5e
# expected_be = "45b393be6ca5049c9a0e0232379bea36ca9232d101c9c0179b3f1cc0e3922d5e"
# if coinbase_txid[::-1].hex() == expected_be:
#     print("✅ Coinbase TXID matches server calculation")
# else:
#     print("❌ Coinbase TXID mismatch!")

# # Now test merkle branch combinations
# merkle_branch_hex = "3a51246501497061f5e8dc0286abdf08758994201b9fff99486925f9d7c0387a"

# # Test both orientations
# branch_be = bytes.fromhex(merkle_branch_hex)
# branch_le = bytes.fromhex(merkle_branch_hex)[::-1]

# print(f"\nTesting merkle combinations:")
# print(f"Branch BE: {branch_be.hex()}")
# print(f"Branch LE: {branch_le.hex()}")

# # Test 1: coinbase_txid (LE) + branch (as-is)
# test1 = sha256d(coinbase_txid + branch_be)
# print(f"Test 1 (LE + BE): {test1.hex()}")

# # Test 2: coinbase_txid (LE) + branch (reversed)  
# test2 = sha256d(coinbase_txid + branch_le)
# print(f"Test 2 (LE + LE): {test2.hex()}")

# # Test 3: coinbase_txid (BE) + branch (as-is)
# test3 = sha256d(coinbase_txid[::-1] + branch_be)
# print(f"Test 3 (BE + BE): {test3.hex()}")

# # Test 4: coinbase_txid (BE) + branch (reversed)
# test4 = sha256d(coinbase_txid[::-1] + branch_le)
# print(f"Test 4 (BE + LE): {test4.hex()}")

# # Server calculated: f51aa13099b1157b830268a5d256641f2a66fc151056e4d636b71761cc053619
# expected_merkle = "f51aa13099b1157b830268a5d256641f2a66fc151056e4d636b71761cc053619"
# print(f"\nServer calculated: {expected_merkle}")

# tests = [test1.hex(), test2.hex(), test3.hex(), test4.hex()]
# for i, test in enumerate(tests, 1):
#     if test == expected_merkle:
#         print(f"✅ Test {i} matches server!")






# import hashlib

# def sha256d(data):
#     return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# # Server's method (WRONG)
# coinbase_full = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff220358694000000000000000004d696e656420427920546f6d61732056616e61676173ffffffff02902f500900000000160014462bf26c29e00ee732f4d475a7ddb0dfb29bc7390000000000000000286a246a24aa21a9edd23506a69eba4a2a45ab88e419656334fd1934fc3306a5368ad020501880225800000000"
# merkle_branch = "3a51246501497061f5e8dc0286abdf08758994201b9fff99486925f9d7c0387a"

# server_wrong = sha256d(bytes.fromhex(coinbase_full) + bytes.fromhex(merkle_branch))
# print(f"Server's wrong method: {server_wrong.hex()}")

# # Correct method (what cpuminer does)
# coinbase_txid = sha256d(bytes.fromhex(coinbase_full))  # First get TXID
# correct_merkle = sha256d(coinbase_txid + bytes.fromhex(merkle_branch))
# print(f"Correct method: {correct_merkle.hex()}")

# # Expected from server debug
# expected = "f51aa13099b1157b830268a5d256641f2a66fc151056e4d636b71761cc053619"
# print(f"Server calculated: {expected}")

# if server_wrong.hex() == expected:
#     print("✅ Server is using wrong method - hashing full coinbase!")





# import hashlib

# def sha256d(data):
#     return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# # Test the server's calculate_merkle_root_from_branch function
# def calculate_merkle_root_from_branch(leaf_hex: str, branch: list[str], index: int) -> str:
#     """Server's version"""
#     current = bytes.fromhex(leaf_hex)[::-1]  # Convert BE to LE
    
#     for sibling_hex in branch:
#         sibling = bytes.fromhex(sibling_hex)[::-1]  # Convert to LE bytes
#         if index % 2 == 1:
#             combined = sibling + current
#         else:
#             combined = current + sibling
#         current = sha256d(combined)
#         index //= 2
    
#     return current.hex()  # Returns LE hex

# # Test it
# coinbase_txid_be = "45b393be6ca5049c9a0e0232379bea36ca9232d101c9c0179b3f1cc0e3922d5e"
# merkle_branch = ["3a51246501497061f5e8dc0286abdf08758994201b9fff99486925f9d7c0387a"]

# server_result = calculate_merkle_root_from_branch(coinbase_txid_be, merkle_branch, 0)
# print(f"Server function result (LE): {server_result}")
# print(f"Server function result (BE): {bytes.fromhex(server_result)[::-1].hex()}")

# # Expected correct result (from our earlier test)
# expected = "460eaff21241df866def8b605daaea86abc8175c3f911b165157ef93c8adacd0"
# print(f"Expected (LE): {expected}")
# print(f"Expected (BE): {bytes.fromhex(expected)[::-1].hex()}")

# # Check what the server displays
# displayed = "5801297159c267283cd02bdf1f2662dc72c973d9e3b7bb2c2e65f255c4df6c06"
# print(f"Server displays: {displayed}")

# if bytes.fromhex(server_result)[::-1].hex() == displayed:
#     print("✅ Server converts LE result to BE for display")
# elif server_result == displayed:
#     print("❌ Server function returns BE directly")





# import hashlib

# def sha256d(data):
#     return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# def calculate_merkle_root_FIXED(leaf_hex: str, branch, index: int) -> str:
#     """FIXED version - don't convert branch to LE"""
#     current = bytes.fromhex(leaf_hex)[::-1]  # Convert BE leaf to LE
#     print(f"  Starting with leaf_hex: {leaf_hex}")
#     print(f"  Converted to LE bytes: {current.hex()}")
    
#     for sibling_hex in branch:
#         sibling = bytes.fromhex(sibling_hex)  # Keep branch in BE format!
#         print(f"  Sibling hex: {sibling_hex}")
#         print(f"  Sibling BE bytes: {sibling.hex()}")
        
#         if index % 2 == 1:
#             combined = sibling + current
#             print(f"  Combined (sibling + current): {combined.hex()}")
#         else:
#             combined = current + sibling  
#             print(f"  Combined (current + sibling): {combined.hex()}")
            
#         current = sha256d(combined)
#         print(f"  SHA256d result: {current.hex()}")
#         index //= 2
    
#     return current.hex()  # Returns LE hex

# # Test the FIXED version
# print("=== TESTING FIXED FUNCTION ===")
# coinbase_txid_be = "45b393be6ca5049c9a0e0232379bea36ca9232d101c9c0179b3f1cc0e3922d5e"
# merkle_branch = ["3a51246501497061f5e8dc0286abdf08758994201b9fff99486925f9d7c0387a"]

# fixed_result_le = calculate_merkle_root_FIXED(coinbase_txid_be, merkle_branch, 0)
# fixed_result_be = bytes.fromhex(fixed_result_le)[::-1].hex()

# print(f"\nFixed result (LE): {fixed_result_le}")
# print(f"Fixed result (BE): {fixed_result_be}")

# # Expected correct result
# expected_le = "460eaff21241df866def8b605daaea86abc8175c3f911b165157ef93c8adacd0"
# print(f"Expected (LE): {expected_le}")

# if fixed_result_le == expected_le:
#     print("🎯 *** PERFECT! FIXED VERSION MATCHES EXPECTED RESULT! ***")
# else:
#     print("❌ Still doesn't match")









# import struct
# import hashlib
# import scrypt

# def sha256d(data):
#     return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# def le32dec(hex_str):
#     """Convert 4-byte hex string to little-endian 32-bit value"""
#     return struct.unpack('<I', bytes.fromhex(hex_str))[0]

# def be32dec(binary_data):
#     """Convert 4 binary bytes to big-endian 32-bit value"""
#     return struct.unpack('>I', binary_data)[0]

# def build_cpuminer_header():
#     """Build header exactly as cpuminer does with current share data"""
    
#     # Current share data
#     version_hex = "00000020"
#     prevhash_hex = "3e8a18cc67da1ac9a452b86a2813ff68a3103619f7513306c71fd7acf919083d"
#     ntime_hex = "3ac7aa68"
#     nbits_hex = "c53f011c"
#     nonce = 0x301812f1  # Current nonce (f1121830 as big-endian uint32)
    
#     # Coinbase from current share
#     coinb1 = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2203606940"
#     extra_nonce1 = "00000000"
#     extra_nonce2 = "02000000"
#     coinb2 = "4d696e656420427920546f6d61732056616e61676173ffffffff02902f500900000000160014462bf26c29e00ee732f4d475a7ddb0dfb29bc7390000000000000000286a246a24aa21a9ed46ff479f411fb01dd2615db120091ef24e70b5bd1bd2f93ad8ddbe214d5d737200000000"
    
#     # Build coinbase exactly as cpuminer does
#     coinbase_hex = coinb1 + extra_nonce1 + extra_nonce2 + coinb2
#     coinbase_binary = bytes.fromhex(coinbase_hex)
    
#     print(f"Coinbase hex: {coinbase_hex}")
#     print(f"Coinbase length: {len(coinbase_binary)} bytes")
    
#     # Calculate merkle root exactly as cpuminer does
#     merkle_root = sha256d(coinbase_binary)  # Coinbase TXID
#     print(f"Coinbase TXID: {merkle_root.hex()}")
    
#     # Apply merkle branch (from current share)
#     merkle_branch = ["24cf5fdfeb2e7802f82606a35fd7fd59c04431d8d802ff1b3be9926edeef3801"]
    
#     for branch_hex in merkle_branch:
#         branch_binary = bytes.fromhex(branch_hex)
#         # cpuminer: concatenate current + branch, then hash
#         combined = merkle_root + branch_binary
#         merkle_root = sha256d(combined)
#         print(f"After branch: {merkle_root.hex()}")
    
#     print(f"Final merkle root (binary): {merkle_root.hex()}")
    
#     # Now build the header exactly as cpuminer does
#     work_data = [0] * 32
    
#     # Version: le32dec
#     work_data[0] = le32dec(version_hex)
    
#     # Prevhash: 8 chunks of 4 bytes each, le32dec
#     for i in range(8):
#         chunk = prevhash_hex[i*8:(i+1)*8]
#         work_data[1 + i] = le32dec(chunk)
    
#     # Merkle root: 8 chunks of 4 bytes each, be32dec from binary
#     for i in range(8):
#         chunk_binary = merkle_root[i*4:(i+1)*4]
#         work_data[9 + i] = be32dec(chunk_binary)
    
#     # Time and bits: le32dec
#     work_data[17] = le32dec(ntime_hex)
#     work_data[18] = le32dec(nbits_hex)
    
#     # Nonce: raw value
#     work_data[19] = nonce
    
#     # Convert to 80-byte header (little-endian words)
#     header_bytes = b''.join(struct.pack('<I', work_data[i]) for i in range(20))
    
#     return header_bytes, merkle_root.hex()

# def build_server_header():
#     """Build header exactly as server does"""
#     version_le = "00000020"
#     prevhash_le = "3e8a18cc67da1ac9a452b86a2813ff68a3103619f7513306c71fd7acf919083d"
#     merkle_root_be = "8375b9b8f96a53e7ab87985a713843f5fb9cc1479ddfdd294cbe6aa08b88c8c1"  # From server output
#     ntime_le = "3ac7aa68"
#     nbits_le = "c53f011c"
#     nonce_le = "f1121830"
    
#     header_hex = version_le + prevhash_le + merkle_root_be + ntime_le + nbits_le + nonce_le
#     return bytes.fromhex(header_hex)

# # Test both approaches
# print("=== CPUMINER HEADER CONSTRUCTION ===")
# cpuminer_header, cpuminer_merkle = build_cpuminer_header()
# print(f"CPUMiner header: {cpuminer_header.hex()}")

# print(f"\n=== SERVER HEADER CONSTRUCTION ===") 
# server_header = build_server_header()
# print(f"Server header: {server_header.hex()}")

# print(f"\n=== COMPARISON ===")
# if cpuminer_header.hex() == server_header.hex():
#     print("✅ Headers match!")
# else:
#     print("❌ Headers differ")
#     print(f"Difference at byte:")
#     for i, (c, s) in enumerate(zip(cpuminer_header, server_header)):
#         if c != s:
#             print(f"  Byte {i}: CPUMiner={c:02x}, Server={s:02x}")
#             break

# print(f"\n=== SCRYPT RESULTS ===")
# cpuminer_scrypt = scrypt.hash(cpuminer_header, cpuminer_header, 1024, 1, 1, 32)[::-1].hex()
# server_scrypt = scrypt.hash(server_header, server_header, 1024, 1, 1, 32)[::-1].hex()

# print(f"CPUMiner scrypt: {cpuminer_scrypt}")
# print(f"Server scrypt:   {server_scrypt}")

# # Expected from miner
# expected_hash = "00000038b50e3fc147acf69ca5ec4a3c8e2eed78303f32cd803b62815164d8e0"
# print(f"Miner found:     {expected_hash}")

# if cpuminer_scrypt == expected_hash:
#     print("🎯 *** CPUMINER CONSTRUCTION MATCHES MINER! ***")
# elif server_scrypt == expected_hash:
#     print("🎯 *** SERVER CONSTRUCTION MATCHES MINER! ***")









# import struct
# import hashlib
# import scrypt

# def sha256d(data):
#     return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# def le32dec(hex_str):
#     """Convert 4-byte hex string to little-endian 32-bit value"""
#     return struct.unpack('<I', bytes.fromhex(hex_str))[0]

# def be32dec(binary_data):
#     """Convert 4 binary bytes to big-endian 32-bit value"""
#     return struct.unpack('>I', binary_data)[0]

# def build_cpuminer_header():
#     """Build header exactly as cpuminer does with LATEST share data"""
    
#     # Latest share data from the log
#     version_hex = "00000020"
#     prevhash_hex = "e0bceb6a0a3e0238d57156367830945eb9d8194041748f636c4774dfaa260282"
#     ntime_hex = "9bc8aa68"
#     nbits_hex = "c53f011c"
#     nonce = 0xe012cde4  # Latest nonce (e4cd12e0 as big-endian uint32)
    
#     # Coinbase from latest share
#     coinb1 = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2203626940"
#     extra_nonce1 = "00000000"
#     extra_nonce2 = "04000000"
#     coinb2 = "4d696e656420427920546f6d61732056616e61676173ffffffff02902f500900000000160014462bf26c29e00ee732f4d475a7ddb0dfb29bc7390000000000000000286a246a24aa21a9ed5164ed7675e9148802e6ac60c6539385a21e8180b7e57790f6102a99144ab10200000000"
    
#     # Build coinbase exactly as cpuminer does
#     coinbase_hex = coinb1 + extra_nonce1 + extra_nonce2 + coinb2
#     coinbase_binary = bytes.fromhex(coinbase_hex)
    
#     print(f"Coinbase hex: {coinbase_hex}")
#     print(f"Coinbase length: {len(coinbase_binary)} bytes")
    
#     # Calculate merkle root exactly as cpuminer does
#     merkle_root = sha256d(coinbase_binary)  # Coinbase TXID
#     print(f"Coinbase TXID: {merkle_root.hex()}")
#     print(f"Server calculated TXID: fbf7446e14f388926ab27fccf08805c178a1a5e380e1c64dcd1640c8bbfffd7b")
    
#     # Apply merkle branch (from latest share)
#     merkle_branch = ["4d71b41a0803c62f63320c74bc6cf001bb40074115a5f7975f384c1aa0d5deaf"]
    
#     for branch_hex in merkle_branch:
#         branch_binary = bytes.fromhex(branch_hex)
#         # cpuminer: concatenate current + branch, then hash
#         combined = merkle_root + branch_binary
#         merkle_root = sha256d(combined)
#         print(f"After branch: {merkle_root.hex()}")
    
#     print(f"Final merkle root (binary): {merkle_root.hex()}")
    
#     # Now build the header exactly as cpuminer does
#     work_data = [0] * 32
    
#     # Version: le32dec
#     work_data[0] = le32dec(version_hex)
    
#     # Prevhash: 8 chunks of 4 bytes each, le32dec
#     for i in range(8):
#         chunk = prevhash_hex[i*8:(i+1)*8]
#         work_data[1 + i] = le32dec(chunk)
    
#     # Merkle root: 8 chunks of 4 bytes each, be32dec from binary
#     for i in range(8):
#         chunk_binary = merkle_root[i*4:(i+1)*4]
#         work_data[9 + i] = be32dec(chunk_binary)
    
#     # Time and bits: le32dec
#     work_data[17] = le32dec(ntime_hex)
#     work_data[18] = le32dec(nbits_hex)
    
#     # Nonce: raw value
#     work_data[19] = nonce
    
#     # Convert to 80-byte header (little-endian words)
#     header_bytes = b''.join(struct.pack('<I', work_data[i]) for i in range(20))
    
#     return header_bytes, merkle_root.hex()

# def build_server_header():
#     """Build header exactly as server does with latest data"""
#     version_le = "00000020"
#     prevhash_le = "e0bceb6a0a3e0238d57156367830945eb9d8194041748f636c4774dfaa260282"
#     merkle_root_be = "389696db0e5e19177e2ebd9b2e809c3e23bc149fbb42006ff8a0b3219a0af0f6"  # From server output
#     ntime_le = "9bc8aa68"
#     nbits_le = "c53f011c"
#     nonce_le = "e4cd12e0"
    
#     header_hex = version_le + prevhash_le + merkle_root_be + ntime_le + nbits_le + nonce_le
#     return bytes.fromhex(header_hex)

# # Test both approaches
# print("=== CPUMINER HEADER CONSTRUCTION ===")
# cpuminer_header, cpuminer_merkle = build_cpuminer_header()
# print(f"CPUMiner header: {cpuminer_header.hex()}")

# print(f"\n=== SERVER HEADER CONSTRUCTION ===") 
# server_header = build_server_header()
# print(f"Server header: {server_header.hex()}")

# print(f"\n=== COMPARISON ===")
# if cpuminer_header.hex() == server_header.hex():
#     print("✅ Headers match!")
# else:
#     print("❌ Headers differ")
#     print(f"CPUMiner: {cpuminer_header.hex()}")
#     print(f"Server:   {server_header.hex()}")
    
#     # Find first difference
#     for i, (c, s) in enumerate(zip(cpuminer_header.hex(), server_header.hex())):
#         if c != s:
#             byte_pos = i // 2
#             print(f"First difference at byte {byte_pos}, position {i}")
#             print(f"  CPUMiner: ...{cpuminer_header.hex()[max(0,i-8):i+8]}...")
#             print(f"  Server:   ...{server_header.hex()[max(0,i-8):i+8]}...")
#             break

# print(f"\n=== SCRYPT RESULTS ===")
# cpuminer_scrypt = scrypt.hash(cpuminer_header, cpuminer_header, 1024, 1, 1, 32)[::-1].hex()
# server_scrypt = scrypt.hash(server_header, server_header, 1024, 1, 1, 32)[::-1].hex()

# print(f"CPUMiner scrypt: {cpuminer_scrypt}")
# print(f"Server scrypt:   {server_scrypt}")

# # Expected from miner
# expected_hash = "00000093dcb99f66c11491775657d4685e4c5967521bc6edd63f8140fc1ee18e"
# print(f"Miner found:     {expected_hash}")

# if cpuminer_scrypt == expected_hash:
#     print("🎯 *** CPUMINER CONSTRUCTION MATCHES MINER! ***")
# elif server_scrypt == expected_hash:
#     print("🎯 *** SERVER CONSTRUCTION MATCHES MINER! ***")
# else:
#     print("❌ Neither matches - there's still an issue")








# import struct
# import hashlib
# import scrypt

# def sha256d(data):
#     return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# def le32dec(hex_str):
#     return struct.unpack('<I', bytes.fromhex(hex_str))[0]

# def be32dec(binary_data):
#     return struct.unpack('>I', binary_data)[0]

# def test_different_extranonce2_interpretations():
#     """Test different ways cpuminer might interpret extranonce2"""
    
#     # Static components
#     coinb1 = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2203626940"
#     extra_nonce1 = "00000000"
#     coinb2 = "4d696e656420427920546f6d61732056616e61676173ffffffff02902f500900000000160014462bf26c29e00ee732f4d475a7ddb0dfb29bc7390000000000000000286a246a24aa21a9ed5164ed7675e9148802e6ac60c6539385a21e8180b7e57790f6102a99144ab10200000000"
#     merkle_branch = "4d71b41a0803c62f63320c74bc6cf001bb40074115a5f7975f384c1aa0d5deaf"
    
#     # Submitted extranonce2 from miner
#     submitted_extranonce2 = "04000000"
    
#     # Test different interpretations
#     interpretations = [
#         ("As hex string", submitted_extranonce2),
#         ("As LE bytes [4,0,0,0]", "04000000"),  # Same as above
#         ("As BE bytes [0,0,0,4]", "00000004"), 
#         ("Iteration 4 LE", bytes([4, 0, 0, 0]).hex()),  # cpuminer 4th iteration
#         ("Iteration 4 BE", bytes([0, 0, 0, 4]).hex()),
#     ]
    
#     expected_hash = "00000093dcb99f66c11491775657d4685e4c5967521bc6edd63f8140fc1ee18e"
    
#     print("Testing different extranonce2 interpretations:")
#     print(f"Target hash: {expected_hash}")
#     print()
    
#     for desc, extra_nonce2 in interpretations:
#         # Build coinbase
#         coinbase_hex = coinb1 + extra_nonce1 + extra_nonce2 + coinb2
#         coinbase_binary = bytes.fromhex(coinbase_hex)
        
#         # Calculate merkle root
#         merkle_root = sha256d(coinbase_binary)
#         branch_binary = bytes.fromhex(merkle_branch)
#         combined = merkle_root + branch_binary
#         final_merkle = sha256d(combined)
        
#         # Build header (cpuminer style)
#         work_data = [0] * 32
        
#         # Static header components
#         work_data[0] = le32dec("00000020")  # version
        
#         # Prevhash (8 chunks, le32dec each)
#         prevhash = "e0bceb6a0a3e0238d57156367830945eb9d8194041748f636c4774dfaa260282"
#         for i in range(8):
#             chunk = prevhash[i*8:(i+1)*8]
#             work_data[1 + i] = le32dec(chunk)
        
#         # Merkle root (8 chunks, be32dec each)
#         for i in range(8):
#             chunk_binary = final_merkle[i*4:(i+1)*4]
#             work_data[9 + i] = be32dec(chunk_binary)
            
#         work_data[17] = le32dec("9bc8aa68")  # ntime
#         work_data[18] = le32dec("c53f011c")  # nbits
#         work_data[19] = 0xe012cde4           # nonce
        
#         # Convert to header bytes
#         header_bytes = b''.join(struct.pack('<I', work_data[i]) for i in range(20))
        
#         # Calculate scrypt
#         scrypt_result = scrypt.hash(header_bytes, header_bytes, 1024, 1, 1, 32)[::-1].hex()
        
#         print(f"{desc:20} | extranonce2: {extra_nonce2} | hash: {scrypt_result[:16]}...")
        
#         if scrypt_result == expected_hash:
#             print(f"🎯 *** MATCH FOUND: {desc} ***")
#             print(f"   Coinbase: {coinbase_hex}")
#             print(f"   Header: {header_bytes.hex()}")
#             return True
    
#     print("❌ No interpretation matched the miner's hash")
#     return False

# # Run the test
# test_different_extranonce2_interpretations()

# # Additional test: try different nonce values too
# print("\n" + "="*80)
# print("Testing if the nonce submission might have endianness issues:")

# def test_nonce_interpretations():
#     # Use the server's exact coinbase construction
#     coinbase_hex = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff220362694000000000040000004d696e656420427920546f6d61732056616e61676173ffffffff02902f500900000000160014462bf26c29e00ee732f4d475a7ddb0dfb29bc7390000000000000000286a246a24aa21a9ed5164ed7675e9148802e6ac60c6539385a21e8180b7e57790f6102a99144ab10200000000"
    
#     # Server's merkle root calculation  
#     coinbase_binary = bytes.fromhex(coinbase_hex)
#     merkle_root = sha256d(coinbase_binary)
#     branch_binary = bytes.fromhex("4d71b41a0803c62f63320c74bc6cf001bb40074115a5f7975f384c1aa0d5deaf")
#     combined = merkle_root + branch_binary
#     final_merkle = sha256d(combined)
    
#     # Try different nonce interpretations
#     submitted_nonce = "e4cd12e0"
#     nonce_interpretations = [
#         ("As submitted LE", int(submitted_nonce, 16)),
#         ("Byte-reversed BE", int(submitted_nonce[::-1], 16)), 
#         ("As BE interpreted", struct.unpack('>I', bytes.fromhex(submitted_nonce))[0]),
#         ("As LE interpreted", struct.unpack('<I', bytes.fromhex(submitted_nonce))[0]),
#     ]
    
#     for desc, nonce_val in nonce_interpretations:
#         work_data = [0] * 32
#         work_data[0] = le32dec("00000020")
        
#         prevhash = "e0bceb6a0a3e0238d57156367830945eb9d8194041748f636c4774dfaa260282"
#         for i in range(8):
#             chunk = prevhash[i*8:(i+1)*8]
#             work_data[1 + i] = le32dec(chunk)
        
#         for i in range(8):
#             chunk_binary = final_merkle[i*4:(i+1)*4]
#             work_data[9 + i] = be32dec(chunk_binary)
            
#         work_data[17] = le32dec("9bc8aa68")
#         work_data[18] = le32dec("c53f011c")
#         work_data[19] = nonce_val
        
#         header_bytes = b''.join(struct.pack('<I', work_data[i]) for i in range(20))
#         scrypt_result = scrypt.hash(header_bytes, header_bytes, 1024, 1, 1, 32)[::-1].hex()
        
#         print(f"{desc:20} | nonce: 0x{nonce_val:08x} | hash: {scrypt_result[:16]}...")
        
#         if scrypt_result == "00000093dcb99f66c11491775657d4685e4c5967521bc6edd63f8140fc1ee18e":
#             print(f"🎯 *** MATCH FOUND: {desc} ***")
#             return True
    
#     return False

# test_nonce_interpretations()






# import struct
# import hashlib
# import scrypt

# def sha256d(data):
#     return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# def le32dec(hex_str):
#     return struct.unpack('<I', bytes.fromhex(hex_str))[0]

# def be32dec(binary_data):
#     return struct.unpack('>I', binary_data)[0]

# def test_extranonce2_iterations():
#     """Test if miner used a different extranonce2 iteration than submitted"""
    
#     # Base components
#     coinb1 = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2203626940"
#     extra_nonce1 = "00000000"
#     coinb2 = "4d696e656420427920546f6d61732056616e61676173ffffffff02902f500900000000160014462bf26c29e00ee732f4d475a7ddb0dfb29bc7390000000000000000286a246a24aa21a9ed5164ed7675e9148802e6ac60c6539385a21e8180b7e57790f6102a99144ab10200000000"
#     merkle_branch = "4d71b41a0803c62f63320c74bc6cf001bb40074115a5f7975f384c1aa0d5deaf"
    
#     # Header static components
#     prevhash = "e0bceb6a0a3e0238d57156367830945eb9d8194041748f636c4774dfaa260282"
#     nonce = 0xe012cde4  # LE interpretation of submitted nonce
    
#     expected_hash = "00000093dcb99f66c11491775657d4685e4c5967521bc6edd63f8140fc1ee18e"
    
#     print("Testing extranonce2 iterations (cpuminer increments for each work unit):")
#     print(f"Target: {expected_hash}")
#     print()
    
#     # Test extranonce2 values from 0 to 100 (cpuminer iterations)
#     for iteration in range(101):
#         # Convert iteration to 4-byte little-endian 
#         extranonce2_bytes = struct.pack('<I', iteration)
#         extranonce2_hex = extranonce2_bytes.hex()
        
#         # Build coinbase with this extranonce2
#         coinbase_hex = coinb1 + extra_nonce1 + extranonce2_hex + coinb2
#         coinbase_binary = bytes.fromhex(coinbase_hex)
        
#         # Calculate merkle root
#         merkle_root = sha256d(coinbase_binary)
#         branch_binary = bytes.fromhex(merkle_branch)
#         final_merkle = sha256d(merkle_root + branch_binary)
        
#         # Build header exactly as cpuminer
#         work_data = [0] * 32
#         work_data[0] = le32dec("00000020")
        
#         # Prevhash (8 chunks, le32dec)
#         for i in range(8):
#             chunk = prevhash[i*8:(i+1)*8]
#             work_data[1 + i] = le32dec(chunk)
        
#         # Merkle root (8 chunks, be32dec)
#         for i in range(8):
#             chunk_binary = final_merkle[i*4:(i+1)*4]
#             work_data[9 + i] = be32dec(chunk_binary)
            
#         work_data[17] = le32dec("9bc8aa68")  # ntime
#         work_data[18] = le32dec("c53f011c")  # nbits
#         work_data[19] = nonce
        
#         header_bytes = b''.join(struct.pack('<I', work_data[i]) for i in range(20))
#         scrypt_result = scrypt.hash(header_bytes, header_bytes, 1024, 1, 1, 32)[::-1].hex()
        
#         if iteration % 10 == 0 or iteration < 10:
#             print(f"Iteration {iteration:3d} | extranonce2: {extranonce2_hex} | hash: {scrypt_result[:16]}...")
        
#         if scrypt_result == expected_hash:
#             print(f"🎯 *** FOUND IT! Iteration {iteration} ***")
#             print(f"   Extranonce2: {extranonce2_hex}")
#             print(f"   Submitted:   04000000 (iteration 4)")
#             print(f"   Actual used: {extranonce2_hex} (iteration {iteration})")
#             print(f"   Coinbase: {coinbase_hex}")
#             print(f"   Header: {header_bytes.hex()}")
            
#             # Explain the discrepancy
#             if iteration != 4:
#                 print(f"\n💡 EXPLANATION: The miner found the hash using iteration {iteration},")
#                 print(f"   but submitted the job's original extranonce2 (iteration 4) instead!")
#                 print(f"   This is why the server validation failed.")
            
#             return True
    
#     print("❌ No iteration from 0-100 matched")
#     return False

# # Run the comprehensive test
# test_extranonce2_iterations()












# import struct
# import hashlib
# import scrypt

# def sha256d(data):
#     return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# def le32dec(hex_str):
#     return struct.unpack('<I', bytes.fromhex(hex_str))[0]

# def be32dec(binary_data):
#     return struct.unpack('>I', binary_data)[0]

# def test_ntime_variations():
#     """Test if miner used a different ntime than submitted"""
    
#     # Use exact data from the failed share
#     coinb1 = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2203626940"
#     extra_nonce1 = "00000000"
#     extra_nonce2 = "04000000"  # As submitted
#     coinb2 = "4d696e656420427920546f6d61732056616e61676173ffffffff02902f500900000000160014462bf26c29e00ee732f4d475a7ddb0dfb29bc7390000000000000000286a246a24aa21a9ed5164ed7675e9148802e6ac60c6539385a21e8180b7e57790f6102a99144ab10200000000"
#     merkle_branch = "4d71b41a0803c62f63320c74bc6cf001bb40074115a5f7975f384c1aa0d5deaf"
    
#     # Static components
#     prevhash = "e0bceb6a0a3e0238d57156367830945eb9d8194041748f636c4774dfaa260282"
#     nonce = 0xe012cde4  # LE interpretation
#     submitted_ntime = "9bc8aa68"
    
#     expected_hash = "00000093dcb99f66c11491775657d4685e4c5967521bc6edd63f8140fc1ee18e"
    
#     print("Testing ntime variations (miners can adjust ntime within range):")
#     print(f"Target: {expected_hash}")
#     print(f"Submitted ntime: {submitted_ntime}")
#     print()
    
#     # Build coinbase once
#     coinbase_hex = coinb1 + extra_nonce1 + extra_nonce2 + coinb2
#     coinbase_binary = bytes.fromhex(coinbase_hex)
    
#     # Calculate merkle root once
#     merkle_root = sha256d(coinbase_binary)
#     branch_binary = bytes.fromhex(merkle_branch)
#     final_merkle = sha256d(merkle_root + branch_binary)
    
#     # Convert submitted ntime to integer
#     submitted_ntime_int = struct.unpack('<I', bytes.fromhex(submitted_ntime))[0]
    
#     # Test ntime values in a range around the submitted value (±300 seconds)
#     for ntime_offset in range(-300, 301, 1):
#         test_ntime_int = submitted_ntime_int + ntime_offset
#         test_ntime_hex = struct.pack('<I', test_ntime_int).hex()
        
#         # Build header with this ntime
#         work_data = [0] * 32
#         work_data[0] = le32dec("00000020")
        
#         # Prevhash (8 chunks, le32dec)
#         for i in range(8):
#             chunk = prevhash[i*8:(i+1)*8]
#             work_data[1 + i] = le32dec(chunk)
        
#         # Merkle root (8 chunks, be32dec)
#         for i in range(8):
#             chunk_binary = final_merkle[i*4:(i+1)*4]
#             work_data[9 + i] = be32dec(chunk_binary)
            
#         work_data[17] = test_ntime_int  # Direct integer, not le32dec
#         work_data[18] = le32dec("c53f011c")
#         work_data[19] = nonce
        
#         header_bytes = b''.join(struct.pack('<I', work_data[i]) for i in range(20))
#         scrypt_result = scrypt.hash(header_bytes, header_bytes, 1024, 1, 1, 32)[::-1].hex()
        
#         if ntime_offset % 50 == 0 or abs(ntime_offset) < 5:
#             print(f"Offset {ntime_offset:4d} | ntime: {test_ntime_hex} | hash: {scrypt_result[:16]}...")
        
#         if scrypt_result == expected_hash:
#             print(f"🎯 *** FOUND IT! Ntime offset: {ntime_offset} seconds ***")
#             print(f"   Submitted ntime: {submitted_ntime}")
#             print(f"   Actual ntime:    {test_ntime_hex}")
#             print(f"   Difference:      {ntime_offset} seconds")
#             print(f"   Header: {header_bytes.hex()}")
            
#             if ntime_offset != 0:
#                 print(f"\n💡 EXPLANATION: The miner used a different ntime than submitted!")
#                 print(f"   This is allowed in Stratum but causes validation to fail.")
            
#             return True
    
#     print("❌ No ntime variation from -300 to +300 seconds matched")
#     return False

# # Also test if there's an issue with work->data[19] nonce storage
# def test_direct_header_construction():
#     """Test building header exactly like the server does vs cpuminer"""
    
#     print("\n" + "="*80)
#     print("DIRECT HEADER COMPARISON:")
    
#     # Server's exact header from debug output
#     server_header = "00000020e0bceb6a0a3e0238d57156367830945eb9d8194041748f636c4774dfaa260282389696db0e5e19177e2ebd9b2e809c3e23bc149fbb42006ff8a0b3219a0af0f69bc8aa68c53f011ce4cd12e0"
    
#     print(f"Server header: {server_header}")
    
#     # Test all possible nonce positions/interpretations
#     nonce_tests = [
#         ("e4cd12e0", "As submitted hex"),
#         ("e012cde4", "LE interpreted"), 
#         ("0e21dc4e", "Byte-reversed"),
#         ("4edc210e", "Full reverse"),
#     ]
    
#     for nonce_hex, desc in nonce_tests:
#         # Replace last 8 characters (nonce) in server header
#         test_header = server_header[:-8] + nonce_hex
#         header_bytes = bytes.fromhex(test_header)
#         scrypt_result = scrypt.hash(header_bytes, header_bytes, 1024, 1, 1, 32)[::-1].hex()
        
#         print(f"{desc:20} | nonce: {nonce_hex} | hash: {scrypt_result[:16]}...")
        
#         if scrypt_result == "00000093dcb99f66c11491775657d4685e4c5967521bc6edd63f8140fc1ee18e":
#             print(f"🎯 *** MATCH! {desc} ***")
#             return True
    
#     return False

# # Run both tests
# test_ntime_variations()
# test_direct_header_construction()

















# import struct
# import hashlib
# import scrypt

# def sha256d(data):
#     return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# def test_all_endianness_combinations():
#     """Test different endianness combinations for all header fields"""
    
#     # Raw data from the mining.notify and submit
#     version_raw = "00000020"
#     prevhash_raw = "e0bceb6a0a3e0238d57156367830945eb9d8194041748f636c4774dfaa260282"
#     nbits_raw = "c53f011c"
#     ntime_raw = "9bc8aa68"
#     nonce_raw = "e4cd12e0"
    
#     # Build coinbase and merkle root
#     coinb1 = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2203626940"
#     extra_nonce1 = "00000000"
#     extra_nonce2 = "04000000"
#     coinb2 = "4d696e656420427920546f6d61732056616e61676173ffffffff02902f500900000000160014462bf26c29e00ee732f4d475a7ddb0dfb29bc7390000000000000000286a246a24aa21a9ed5164ed7675e9148802e6ac60c6539385a21e8180b7e57790f6102a99144ab10200000000"
#     merkle_branch_raw = "4d71b41a0803c62f63320c74bc6cf001bb40074115a5f7975f384c1aa0d5deaf"
    
#     coinbase_hex = coinb1 + extra_nonce1 + extra_nonce2 + coinb2
#     coinbase_binary = bytes.fromhex(coinbase_hex)
#     merkle_root = sha256d(coinbase_binary)
#     branch_binary = bytes.fromhex(merkle_branch_raw)
#     final_merkle = sha256d(merkle_root + branch_binary)
    
#     expected_hash = "00000093dcb99f66c11491775657d4685e4c5967521bc6edd63f8140fc1ee18e"
    
#     print("Testing all endianness combinations:")
#     print(f"Target: {expected_hash}")
#     print()
    
#     # Function to reverse hex string
#     def reverse_hex(hex_str):
#         return bytes.fromhex(hex_str)[::-1].hex()
    
#     # Test different combinations
#     combinations = [
#         # (version, prevhash, merkle, ntime, nbits, nonce, description)
#         (version_raw, prevhash_raw, final_merkle.hex(), ntime_raw, nbits_raw, nonce_raw, "All as-is"),
#         (reverse_hex(version_raw), prevhash_raw, final_merkle.hex(), ntime_raw, nbits_raw, nonce_raw, "Version reversed"),
#         (version_raw, reverse_hex(prevhash_raw), final_merkle.hex(), ntime_raw, nbits_raw, nonce_raw, "Prevhash reversed"),
#         (version_raw, prevhash_raw, final_merkle[::-1].hex(), ntime_raw, nbits_raw, nonce_raw, "Merkle reversed"),
#         (version_raw, prevhash_raw, final_merkle.hex(), reverse_hex(ntime_raw), nbits_raw, nonce_raw, "Ntime reversed"),
#         (version_raw, prevhash_raw, final_merkle.hex(), ntime_raw, reverse_hex(nbits_raw), nonce_raw, "Nbits reversed"),
#         (version_raw, prevhash_raw, final_merkle.hex(), ntime_raw, nbits_raw, reverse_hex(nonce_raw), "Nonce reversed"),
        
#         # Try with server's cpuminer-style merkle processing
#         ("20000000", prevhash_raw, final_merkle.hex(), ntime_raw, nbits_raw, nonce_raw, "Version LE->BE"),
#         (version_raw, prevhash_raw, final_merkle.hex(), "68aac89b", nbits_raw, nonce_raw, "Ntime LE->BE"),
#         (version_raw, prevhash_raw, final_merkle.hex(), ntime_raw, "1c013fc5", nonce_raw, "Nbits LE->BE"),
#         (version_raw, prevhash_raw, final_merkle.hex(), ntime_raw, nbits_raw, "e012cde4", "Nonce LE->BE"),
#     ]
    
#     for i, (version, prevhash, merkle, ntime, nbits, nonce, desc) in enumerate(combinations):
#         # Build header
#         header_hex = version + prevhash + merkle + ntime + nbits + nonce
        
#         # Ensure exactly 80 bytes
#         if len(header_hex) != 160:  # 80 bytes = 160 hex chars
#             print(f"❌ {desc}: Invalid length {len(header_hex)//2} bytes")
#             continue
            
#         header_bytes = bytes.fromhex(header_hex)
#         scrypt_result = scrypt.hash(header_bytes, header_bytes, 1024, 1, 1, 32)[::-1].hex()
        
#         print(f"{i:2d}. {desc:20} | hash: {scrypt_result[:16]}...")
        
#         if scrypt_result == expected_hash:
#             print(f"🎯 *** FOUND IT! {desc} ***")
#             print(f"    Header: {header_hex}")
#             print(f"    Length: {len(header_bytes)} bytes")
#             return True
    
#     print("\n❌ None of the basic endianness combinations matched")
#     return False

# def test_cpuminer_work_data_array():
#     """Test building header exactly as cpuminer work->data array"""
    
#     print("\n" + "="*60)
#     print("TESTING CPUMINER WORK->DATA ARRAY CONSTRUCTION:")
    
#     # Build exactly as cpuminer stratum_gen_work does
#     coinb1 = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2203626940"
#     extra_nonce1 = "00000000"
#     extra_nonce2 = "04000000"
#     coinb2 = "4d696e656420427920546f6d61732056616e61676173ffffffff02902f500900000000160014462bf26c29e00ee732f4d475a7ddb0dfb29bc7390000000000000000286a246a24aa21a9ed5164ed7675e9148802e6ac60c6539385a21e8180b7e57790f6102a99144ab10200000000"
    
#     coinbase_hex = coinb1 + extra_nonce1 + extra_nonce2 + coinb2
#     coinbase_binary = bytes.fromhex(coinbase_hex)
    
#     # Build merkle root as cpuminer does
#     merkle_root = sha256d(coinbase_binary)
#     branch_binary = bytes.fromhex("4d71b41a0803c62f63320c74bc6cf001bb40074115a5f7975f384c1aa0d5deaf")
#     combined = merkle_root + branch_binary
#     final_merkle = sha256d(combined)
    
#     print(f"Coinbase TXID: {merkle_root.hex()}")
#     print(f"Final merkle:  {final_merkle.hex()}")
    
#     # Now test if cpuminer processes the submitted values differently
#     # Maybe the submitted nonce is actually used differently?
    
#     expected = "00000093dcb99f66c11491775657d4685e4c5967521bc6edd63f8140fc1ee18e"
    
#     # The miner debug shows it found the hash, so let me try building the header
#     # with the EXACT values that would be in cpuminer's work->data array
    
#     # What if the miner incremented extranonce2 locally but submitted the original?
#     # Let me try with the actual nonce value from mining iterations
    
#     test_cases = [
#         # Different nonce interpretations
#         (0xe4cd12e0, "Submitted as-is"),
#         (0xe012cde4, "LE interpreted"),
#         (0x0e21dc4e, "Byte-reversed"),
#         (0x1830f112, "Endian-swapped"),  # e4cd12e0 -> 1830f112
#     ]
    
#     for nonce_val, desc in test_cases:
#         work_data = [0] * 32
        
#         # work->data[0] = le32dec(version)  
#         work_data[0] = struct.unpack('<I', bytes.fromhex("00000020"))[0]
        
#         # Prevhash: 8 words, each le32dec of 4-byte chunks
#         prevhash = "e0bceb6a0a3e0238d57156367830945eb9d8194041748f636c4774dfaa260282"
#         for i in range(8):
#             chunk_hex = prevhash[i*8:(i+1)*8]
#             chunk_bytes = bytes.fromhex(chunk_hex)
#             work_data[1 + i] = struct.unpack('<I', chunk_bytes)[0]
        
#         # Merkle: 8 words, each be32dec of 4-byte chunks
#         for i in range(8):
#             chunk_bytes = final_merkle[i*4:(i+1)*4]
#             work_data[9 + i] = struct.unpack('>I', chunk_bytes)[0]
        
#         # Time and bits
#         work_data[17] = struct.unpack('<I', bytes.fromhex("9bc8aa68"))[0]
#         work_data[18] = struct.unpack('<I', bytes.fromhex("c53f011c"))[0]
        
#         # Nonce
#         work_data[19] = nonce_val
        
#         # Convert work_data to 80-byte header (first 20 words as little-endian)
#         header_bytes = b''.join(struct.pack('<I', work_data[i]) for i in range(20))
        
#         scrypt_result = scrypt.hash(header_bytes, header_bytes, 1024, 1, 1, 32)[::-1].hex()
        
#         print(f"{desc:20} | nonce: 0x{nonce_val:08x} | hash: {scrypt_result[:16]}...")
        
#         if scrypt_result == expected:
#             print(f"🎯 *** FOUND IT! {desc} ***")
#             print(f"    Header: {header_bytes.hex()}")
#             return True
    
#     return False

# # Run both comprehensive tests
# success1 = test_all_endianness_combinations()
# success2 = test_cpuminer_work_data_array()

# if not (success1 or success2):
#     print("\n❌ CONCLUSION: None of the standard interpretations work.")
#     print("   This suggests there might be a bug in the miner, or")
#     print("   the miner is using non-standard header construction.")









# import struct
# import hashlib
# import scrypt

# def sha256d(data):
#     return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# def final_comprehensive_test():
#     """Final comprehensive test with all possible variations"""
    
#     expected_hash = "00000093dcb99f66c11491775657d4685e4c5967521bc6edd63f8140fc1ee18e"
    
#     # Base components
#     coinb1 = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2203626940"
#     extra_nonce1 = "00000000"
#     coinb2 = "4d696e656420427920546f6d61732056616e61676173ffffffff02902f500900000000160014462bf26c29e00ee732f4d475a7ddb0dfb29bc7390000000000000000286a246a24aa21a9ed5164ed7675e9148802e6ac60c6539385a21e8180b7e57790f6102a99144ab10200000000"
#     merkle_branch = "4d71b41a0803c62f63320c74bc6cf001bb40074115a5f7975f384c1aa0d5deaf"
    
#     prevhash = "e0bceb6a0a3e0238d57156367830945eb9d8194041748f636c4774dfaa260282"
#     ntime = "9bc8aa68"
#     nbits = "c53f011c"
#     nonce = "e4cd12e0"
    
#     print("🔍 FINAL COMPREHENSIVE TEST")
#     print(f"Target: {expected_hash}")
#     print()
    
#     # Test 1: Big-endian extranonce2 incrementation
#     print("1. Testing BIG-ENDIAN extranonce2 incrementation:")
#     for iteration in range(20):  # Test first 20 iterations
#         # Big-endian: 4 becomes 00000004 instead of 04000000
#         extranonce2_bytes = struct.pack('>I', 4 + iteration)  # Start from submitted value + offset
#         extranonce2_hex = extranonce2_bytes.hex()
        
#         coinbase_hex = coinb1 + extra_nonce1 + extranonce2_hex + coinb2
#         coinbase_binary = bytes.fromhex(coinbase_hex)
        
#         merkle_root = sha256d(coinbase_binary)
#         branch_binary = bytes.fromhex(merkle_branch)
#         final_merkle = sha256d(merkle_root + branch_binary)
        
#         # Build header with exact cpuminer method
#         work_data = [0] * 32
#         work_data[0] = struct.unpack('<I', bytes.fromhex("00000020"))[0]
        
#         for i in range(8):
#             chunk = prevhash[i*8:(i+1)*8]
#             work_data[1 + i] = struct.unpack('<I', bytes.fromhex(chunk))[0]
        
#         for i in range(8):
#             chunk_bytes = final_merkle[i*4:(i+1)*4]
#             work_data[9 + i] = struct.unpack('>I', chunk_bytes)[0]
            
#         work_data[17] = struct.unpack('<I', bytes.fromhex(ntime))[0]
#         work_data[18] = struct.unpack('<I', bytes.fromhex(nbits))[0]
#         work_data[19] = struct.unpack('<I', bytes.fromhex(nonce))[0]
        
#         header_bytes = b''.join(struct.pack('<I', work_data[i]) for i in range(20))
#         scrypt_result = scrypt.hash(header_bytes, header_bytes, 1024, 1, 1, 32)[::-1].hex()
        
#         if iteration < 10:
#             print(f"  Iter {iteration:2d} | extranonce2: {extranonce2_hex} | hash: {scrypt_result[:16]}...")
        
#         if scrypt_result == expected_hash:
#             print(f"🎯 *** FOUND WITH BIG-ENDIAN EXTRANONCE2! ***")
#             return True
    
#     # Test 2: Different submitted extranonce2 interpretation
#     print(f"\n2. Testing if submitted '04000000' means iteration 0x04000000:")
#     base_iteration = 0x04000000  # Interpret submitted value as actual iteration number
#     for offset in range(-10, 11):
#         iteration = base_iteration + offset
#         extranonce2_bytes = struct.pack('<I', iteration)
#         extranonce2_hex = extranonce2_bytes.hex()
        
#         coinbase_hex = coinb1 + extra_nonce1 + extranonce2_hex + coinb2
#         coinbase_binary = bytes.fromhex(coinbase_hex)
        
#         merkle_root = sha256d(coinbase_binary)
#         branch_binary = bytes.fromhex(merkle_branch)
#         final_merkle = sha256d(merkle_root + branch_binary)
        
#         work_data = [0] * 32
#         work_data[0] = struct.unpack('<I', bytes.fromhex("00000020"))[0]
        
#         for i in range(8):
#             chunk = prevhash[i*8:(i+1)*8]
#             work_data[1 + i] = struct.unpack('<I', bytes.fromhex(chunk))[0]
        
#         for i in range(8):
#             chunk_bytes = final_merkle[i*4:(i+1)*4]
#             work_data[9 + i] = struct.unpack('>I', chunk_bytes)[0]
            
#         work_data[17] = struct.unpack('<I', bytes.fromhex(ntime))[0]
#         work_data[18] = struct.unpack('<I', bytes.fromhex(nbits))[0]
#         work_data[19] = struct.unpack('<I', bytes.fromhex(nonce))[0]
        
#         header_bytes = b''.join(struct.pack('<I', work_data[i]) for i in range(20))
#         scrypt_result = scrypt.hash(header_bytes, header_bytes, 1024, 1, 1, 32)[::-1].hex()
        
#         if abs(offset) <= 5:
#             print(f"  Offset {offset:3d} | iter: 0x{iteration:08x} | hash: {scrypt_result[:16]}...")
        
#         if scrypt_result == expected_hash:
#             print(f"🎯 *** FOUND WITH LARGE ITERATION NUMBER! ***")
#             return True
    
#     # Test 3: Alternative nonce field processing
#     print(f"\n3. Testing alternative nonce processing:")
    
#     # Maybe the work->data[19] nonce field is processed differently
#     nonce_variations = [
#         (struct.unpack('<I', bytes.fromhex(nonce))[0], "LE of submitted"),
#         (struct.unpack('>I', bytes.fromhex(nonce))[0], "BE of submitted"),  
#         (int(nonce, 16), "Direct hex to int"),
#         (int(nonce[::-1], 16), "Reversed hex to int"),
#     ]
    
#     # Use the base extranonce2=04000000 coinbase
#     coinbase_hex = coinb1 + extra_nonce1 + "04000000" + coinb2
#     coinbase_binary = bytes.fromhex(coinbase_hex)
#     merkle_root = sha256d(coinbase_binary)
#     branch_binary = bytes.fromhex(merkle_branch)
#     final_merkle = sha256d(merkle_root + branch_binary)
    
#     for nonce_val, desc in nonce_variations:
#         work_data = [0] * 32
#         work_data[0] = struct.unpack('<I', bytes.fromhex("00000020"))[0]
        
#         for i in range(8):
#             chunk = prevhash[i*8:(i+1)*8]
#             work_data[1 + i] = struct.unpack('<I', bytes.fromhex(chunk))[0]
        
#         for i in range(8):
#             chunk_bytes = final_merkle[i*4:(i+1)*4]
#             work_data[9 + i] = struct.unpack('>I', chunk_bytes)[0]
            
#         work_data[17] = struct.unpack('<I', bytes.fromhex(ntime))[0]
#         work_data[18] = struct.unpack('<I', bytes.fromhex(nbits))[0]
#         work_data[19] = nonce_val & 0xFFFFFFFF  # Ensure 32-bit
        
#         header_bytes = b''.join(struct.pack('<I', work_data[i]) for i in range(20))
#         scrypt_result = scrypt.hash(header_bytes, header_bytes, 1024, 1, 1, 32)[::-1].hex()
        
#         print(f"  {desc:20} | nonce: 0x{nonce_val:08x} | hash: {scrypt_result[:16]}...")
        
#         if scrypt_result == expected_hash:
#             print(f"🎯 *** FOUND WITH ALTERNATIVE NONCE! ***")
#             return True
    
#     print("\n❌ FINAL CONCLUSION: Unable to reproduce miner's hash")
#     print("   This suggests either:")
#     print("   1. The miner has a non-standard implementation") 
#     print("   2. There's some data we're missing")
#     print("   3. The miner's debug output is misleading")
#     print("\n   💡 RECOMMENDATION: Accept that the algorithms are now correct")
#     print("      and focus on testing with real mining to see if shares work.")
    
#     return False

# # Run the final test
# final_comprehensive_test()







# import struct
# import hashlib
# import scrypt

# def sha256d(data):
#     return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# # Current share data
# coinb1 = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2203676940"
# extra_nonce1 = "00000000"
# extra_nonce2 = "00000000"  
# coinb2 = "4d696e656420427920546f6d61732056616e61676173ffffffff02902f500900000000160014462bf26c29e00ee732f4d475a7ddb0dfb29bc7390000000000000000286a246a24aa21a9edc99be73af85f048166f41505ca0e10e47a02533dce8b88f050a91f5a6092344700000000"

# coinbase_hex = coinb1 + extra_nonce1 + extra_nonce2 + coinb2
# coinbase_binary = bytes.fromhex(coinbase_hex)

# # Calculate merkle root
# merkle_root = sha256d(coinbase_binary)
# branch_binary = bytes.fromhex("2683352d34d2bcd5390f3d3366cfb0ba0d8c962e5b5bd2f2de86869202883a7e")
# final_merkle = sha256d(merkle_root + branch_binary)

# print(f"Coinbase TXID: {merkle_root.hex()}")
# print(f"Server calculated: 85e25e7c56d4dd44a73955310d60cd95f294bc2765aa223c2f8984087015dd9b")
# print(f"Final merkle: {final_merkle.hex()}")

# # Test different nonce interpretations with current data
# prevhash = "b5943ea561328af1fdfc81bd0f7bcb2bcab2ffe46fcbe261e228b8960bc1b93e"
# ntime = "f8cbaa68"
# nbits = "c53f011c"
# submitted_nonce = "83290900"  # From current share

# expected = "000000f562794800434d5deeebef1d4ecf7e121894282ec9f67e163568a7a634"

# print(f"\nTesting nonce interpretations:")
# print(f"Target: {expected}")

# nonce_tests = [
#     (struct.unpack('<I', bytes.fromhex(submitted_nonce))[0], "LE interpretation"),
#     (struct.unpack('>I', bytes.fromhex(submitted_nonce))[0], "BE interpretation"),
#     (int(submitted_nonce, 16), "Direct hex->int"),
#     (int(submitted_nonce[::-1], 16), "Byte-reversed"),
# ]

# for nonce_val, desc in nonce_tests:
#     # Build header exactly as cpuminer
#     work_data = [0] * 32
#     work_data[0] = struct.unpack('<I', bytes.fromhex("00000020"))[0]
    
#     # Prevhash (8 chunks, le32dec)
#     for i in range(8):
#         chunk = prevhash[i*8:(i+1)*8]
#         work_data[1 + i] = struct.unpack('<I', bytes.fromhex(chunk))[0]
    
#     # Merkle root (8 chunks, be32dec)
#     for i in range(8):
#         chunk_bytes = final_merkle[i*4:(i+1)*4]
#         work_data[9 + i] = struct.unpack('>I', chunk_bytes)[0]
        
#     work_data[17] = struct.unpack('<I', bytes.fromhex(ntime))[0]
#     work_data[18] = struct.unpack('<I', bytes.fromhex(nbits))[0]
#     work_data[19] = nonce_val
    
#     header_bytes = b''.join(struct.pack('<I', work_data[i]) for i in range(20))
#     scrypt_result = scrypt.hash(header_bytes, header_bytes, 1024, 1, 1, 32)[::-1].hex()
    
#     print(f"{desc:20} | nonce: 0x{nonce_val:08x} | hash: {scrypt_result[:16]}...")
    
#     if scrypt_result == expected:
#         print(f"🎯 *** FOUND IT! {desc} ***")
#         print(f"    Correct nonce interpretation: 0x{nonce_val:08x}")
#         break
# else:
#     print("❌ None matched - checking server's exact header...")
    
#     # Test server's exact header format
#     server_header = "00000020b5943ea561328af1fdfc81bd0f7bcb2bcab2ffe46fcbe261e228b8960bc1b93ee31e6c4b0b7afa0ed017a583a8ef0757fb1f0750966e83134f8bcd6d16d6cfd9f8cbaa68c53f011c83290900"
#     server_bytes = bytes.fromhex(server_header)
#     server_scrypt = scrypt.hash(server_bytes, server_bytes, 1024, 1, 1, 32)[::-1].hex()
#     print(f"Server header result: {server_scrypt}")







# import struct
# import hashlib
# import scrypt

# def sha256d(data):
#     return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# def reverse_hex(hex_str: str) -> str:
#     """Reverse hex string in 2-char chunks (byte reversal)"""
#     return ''.join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)]))

# def test_discovered_method():
#     """Test the exact method discovered by the bruteforce tool"""
    
#     print("🔬 TESTING DISCOVERED METHOD")
#     print("Method: standard_standard_reversed_normal_normal_reversed_reversed_mixed")
#     print()
    
#     # Current share data that produced the match
#     job_data = {
#         "coinb1": "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2203676940",
#         "coinb2": "4d696e656420427920546f6d61732056616e61676173ffffffff02902f500900000000160014462bf26c29e00ee732f4d475a7ddb0dfb29bc7390000000000000000286a246a24aa21a9edc99be73af85f048166f41505ca0e10e47a02533dce8b88f050a91f5a6092344700000000",
#         "prevhash": "b5943ea561328af1fdfc81bd0f7bcb2bcab2ffe46fcbe261e228b8960bc1b93e",
#         "merkle_branch": ["2683352d34d2bcd5390f3d3366cfb0ba0d8c962e5b5bd2f2de86869202883a7e"],
#         "version": "00000020",
#         "nbits": "c53f011c",
#     }
    
#     extra_nonce1 = "00000000"
#     extra_nonce2 = "00000000"
#     ntime = "f8cbaa68"
#     nonce = "83290900"
    
#     expected_hash = "000000f562794800434d5deeebef1d4ecf7e121894282ec9f67e163568a7a634"
#     expected_header = "20000000a53e94b5f18a3261bd81fcfd2bcb7b0fe4ffb2ca61e2cb6f96b828e23eb9c10b4b6c1ee30efa7a0b83a517d05707efa850071ffb13836e966dcd8b4fd9cfd61668aacbf81c013fc500092983"
    
#     print(f"Expected hash: {expected_hash}")
#     print(f"Expected header: {expected_header}")
#     print()
    
#     # Step 1: Build coinbase (standard_standard)
#     print("Step 1: Building coinbase")
#     coinbase_hex = job_data["coinb1"] + extra_nonce1 + extra_nonce2 + job_data["coinb2"]
#     print(f"  Coinbase: {coinbase_hex}")
    
#     # Step 2: Calculate merkle root 
#     print("Step 2: Calculating merkle root")
#     coinbase_binary = bytes.fromhex(coinbase_hex)
#     coinbase_txid = sha256d(coinbase_binary)
#     print(f"  Coinbase TXID: {coinbase_txid.hex()}")
    
#     # Apply merkle branch (using our corrected method)
#     merkle_root = coinbase_txid
#     for branch_hex in job_data["merkle_branch"]:
#         branch_binary = bytes.fromhex(branch_hex)
#         combined = merkle_root + branch_binary
#         merkle_root = sha256d(combined)
#     print(f"  Final merkle root: {merkle_root.hex()}")
    
#     # Step 3: Apply discovered transformations
#     print("Step 3: Applying discovered transformations")
    
#     # Decode the method: standard_standard_reversed_normal_normal_reversed_reversed_mixed
#     # - version: reversed (byte-reverse the version field)
#     # - prevhash: reversed (some transformation)  
#     # - ntime: normal (use as-is)
#     # - nonce: normal (use as-is)
#     # - version: reversed (byte-reverse)
#     # - nbits: reversed (byte-reverse)
#     # - serialization: mixed
    
#     version_transformed = reverse_hex(job_data["version"])
#     prevhash_transformed = job_data["prevhash"]  # The "reversed" here refers to the serialization method
#     ntime_transformed = ntime  # normal = use as-is
#     nonce_transformed = nonce  # normal = use as-is  
#     nbits_transformed = reverse_hex(job_data["nbits"])
    
#     print(f"  Version: {job_data['version']} -> {version_transformed}")
#     print(f"  PrevHash: {prevhash_transformed} (as-is)")
#     print(f"  NTime: {ntime} -> {ntime_transformed}")
#     print(f"  NBits: {job_data['nbits']} -> {nbits_transformed}")
#     print(f"  Nonce: {nonce} -> {nonce_transformed}")
    
#     # Step 4: Build header using mixed endianness method
#     print("Step 4: Building header with mixed endianness")
    
#     def build_mixed_endian_header(version: str, prevhash: str, merkle_root_bytes: bytes, ntime: str, nbits: str, nonce: str) -> bytes:
#         """Build header with mixed endianness as discovered"""
#         work_data = [0] * 20
        
#         # Mixed endianness method from hash_discovery.py
#         work_data[0] = struct.unpack('<I', bytes.fromhex(version))[0]  # LE
        
#         prevhash_bytes = bytes.fromhex(prevhash)
#         for i in range(8):
#             chunk = prevhash_bytes[i*4:(i+1)*4]
#             work_data[1 + i] = struct.unpack('>I', chunk)[0]  # BE
        
#         for i in range(8):
#             chunk = merkle_root_bytes[i*4:(i+1)*4]
#             work_data[9 + i] = struct.unpack('<I', chunk)[0]  # LE
        
#         work_data[17] = struct.unpack('>I', bytes.fromhex(ntime))[0]   # BE
#         work_data[18] = struct.unpack('<I', bytes.fromhex(nbits))[0]   # LE  
#         work_data[19] = struct.unpack('>I', bytes.fromhex(nonce))[0]   # BE
        
#         return struct.pack('<20I', *work_data)
    
#     header_bytes = build_mixed_endian_header(
#         version_transformed,
#         prevhash_transformed, 
#         merkle_root,
#         ntime_transformed,
#         nbits_transformed,
#         nonce_transformed
#     )
    
#     result_header = header_bytes.hex()
#     print(f"  Built header: {result_header}")
    
#     # Step 5: Calculate scrypt hash
#     print("Step 5: Calculating scrypt hash")
#     scrypt_result = hashlib.scrypt(header_bytes, salt=header_bytes, n=1024, r=1, p=1, dklen=32)[::-1].hex()
#     print(f"  Scrypt result: {scrypt_result}")
    
#     # Step 6: Verify results
#     print("\nStep 6: Verification")
#     header_match = result_header == expected_header
#     hash_match = scrypt_result == expected_hash
    
#     print(f"  Header match: {'✅' if header_match else '❌'}")
#     print(f"  Hash match: {'✅' if hash_match else '❌'}")
    
#     if header_match and hash_match:
#         print("\n🎯 *** PERFECT! Method verified! ***")
#         print("✅ The discovered method works correctly")
#         print("✅ Safe to apply to main server code")
#         return True
#     else:
#         print("\n❌ *** VERIFICATION FAILED ***")
#         if not header_match:
#             print(f"  Expected header: {expected_header}")
#             print(f"  Got header:      {result_header}")
#         if not hash_match:
#             print(f"  Expected hash: {expected_hash}")
#             print(f"  Got hash:      {scrypt_result}")
#         return False

# def test_server_implementation():
#     """Test how this would be implemented in the server"""
    
#     print("\n" + "="*80)
#     print("🔧 TESTING SERVER IMPLEMENTATION")
#     print()
    
#     # Simulate server validation with discovered method
#     job = {
#         "version": "00000020",
#         "prevhash": "b5943ea561328af1fdfc81bd0f7bcb2bcab2ffe46fcbe261e228b8960bc1b93e",
#         "nbits": "c53f011c",
#         "coinb1": "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2203676940",
#         "coinb2": "4d696e656420427920546f6d61732056616e61676173ffffffff02902f500900000000160014462bf26c29e00ee732f4d475a7ddb0dfb29bc7390000000000000000286a246a24aa21a9edc99be73af85f048166f41505ca0e10e47a02533dce8b88f050a91f5a6092344700000000",
#         "merkle_branch": ["2683352d34d2bcd5390f3d3366cfb0ba0d8c962e5b5bd2f2de86869202883a7e"]
#     }
    
#     extra_nonce1 = "00000000"
#     extra_nonce2 = "00000000"
#     ntime = "f8cbaa68"
#     nonce = "83290900"
    
#     # Build coinbase
#     coinbase_full = job["coinb1"] + extra_nonce1 + extra_nonce2 + job["coinb2"]
#     coinbase_txid_be = sha256d(bytes.fromhex(coinbase_full))[::-1].hex()  # BE format
    
#     # Calculate merkle root (using our fixed function)
#     def calculate_merkle_root_from_branch_fixed(leaf_hex: str, branch: list, index: int) -> str:
#         current = bytes.fromhex(leaf_hex)[::-1]  # Convert BE to LE
#         for sibling_hex in branch:
#             sibling = bytes.fromhex(sibling_hex)  # Keep branch in BE format (FIXED!)
#             if index % 2 == 1:
#                 combined = sibling + current
#             else:
#                 combined = current + sibling
#             current = sha256d(combined)
#             index //= 2
#         return current.hex()  # Return LE
    
#     merkle_root_le = calculate_merkle_root_from_branch_fixed(coinbase_txid_be, job["merkle_branch"], 0)
    
#     # Apply cpuminer-style merkle root processing
#     merkle_root_le_bytes = bytes.fromhex(merkle_root_le)
#     merkle_chunks = []
#     for i in range(8):
#         chunk = merkle_root_le_bytes[i*4:(i+1)*4]
#         chunk_reversed = chunk[::-1]  # be32dec transformation
#         merkle_chunks.append(chunk_reversed.hex())
#     merkle_root_cpuminer = ''.join(merkle_chunks)
    
#     # Apply discovered method transformations
#     version_le = reverse_hex(job["version"])     # DISCOVERED: reverse version
#     prevhash_le = job["prevhash"]                # Keep as-is
#     ntime_le = reverse_hex(ntime)                # DISCOVERED: reverse ntime  
#     nbits_le = reverse_hex(job["nbits"])         # DISCOVERED: reverse nbits
#     nonce_le = reverse_hex(nonce)                # DISCOVERED: reverse nonce
    
#     print(f"Server transformations:")
#     print(f"  Version: {job['version']} -> {version_le}")
#     print(f"  PrevHash: {prevhash_le} (no change)")
#     print(f"  Merkle: {merkle_root_cpuminer}")
#     print(f"  NTime: {ntime} -> {ntime_le}")
#     print(f"  NBits: {job['nbits']} -> {nbits_le}")
#     print(f"  Nonce: {nonce} -> {nonce_le}")
    
#     # Build header (server style - simple concatenation)
#     header_hex = version_le + prevhash_le + merkle_root_cpuminer + ntime_le + nbits_le + nonce_le
#     header_bytes = bytes.fromhex(header_hex)
    
#     print(f"  Header: {header_hex}")
    
#     # Test scrypt  
#     scrypt_result = hashlib.scrypt(header_bytes, salt=header_bytes, n=1024, r=1, p=1, dklen=32)[::-1].hex()
#     expected = "000000f562794800434d5deeebef1d4ecf7e121894282ec9f67e163568a7a634"
    
#     print(f"  Result: {scrypt_result}")
#     print(f"  Expected: {expected}")
#     print(f"  Match: {'✅' if scrypt_result == expected else '❌'}")
    
#     return scrypt_result == expected

# # Run both tests
# print("Testing discovered method...")
# method_works = test_discovered_method()

# print("\nTesting server implementation...")  
# server_works = test_server_implementation()

# print(f"\n{'='*80}")
# print("FINAL RESULTS:")
# print(f"  Discovered method verified: {'✅' if method_works else '❌'}")
# print(f"  Server implementation works: {'✅' if server_works else '❌'}")

# if method_works and server_works:
#     print("\n🎉 *** ALL TESTS PASSED! Safe to update main server! ***")
# else:
#     print("\n⚠️  *** TESTS FAILED! Do not update main server yet! ***")









import struct
import hashlib
import scrypt

def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def reverse_hex(hex_str: str) -> str:
    """Reverse hex string in 2-char chunks (byte reversal)"""
    return ''.join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)]))



def test_discovered_method():
    """Test the exact method discovered by the bruteforce tool"""
    
    print("🔬 TESTING DISCOVERED METHOD")
    print("Method: standard_standard_reversed_normal_normal_reversed_reversed_mixed")
    print()
    
    # Current share data that produced the match
    job_data = {
        "coinb1": "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2203676940",
        "coinb2": "4d696e656420427920546f6d61732056616e61676173ffffffff02902f500900000000160014462bf26c29e00ee732f4d475a7ddb0dfb29bc7390000000000000000286a246a24aa21a9edc99be73af85f048166f41505ca0e10e47a02533dce8b88f050a91f5a6092344700000000",
        "prevhash": "b5943ea561328af1fdfc81bd0f7bcb2bcab2ffe46fcbe261e228b8960bc1b93e",
        "merkle_branch": ["2683352d34d2bcd5390f3d3366cfb0ba0d8c962e5b5bd2f2de86869202883a7e"],
        "version": "00000020",
        "nbits": "c53f011c",
    }
    
    extra_nonce1 = "00000000"
    extra_nonce2 = "00000000"
    ntime = "f8cbaa68"
    nonce = "83290900"
    
    expected_hash = "000000f562794800434d5deeebef1d4ecf7e121894282ec9f67e163568a7a634"
    expected_header = "20000000a53e94b5f18a3261bd81fcfd2bcb7b0fe4ffb2ca61e2cb6f96b828e23eb9c10b4b6c1ee30efa7a0b83a517d05707efa850071ffb13836e966dcd8b4fd9cfd61668aacbf81c013fc500092983"
    
    print(f"Expected hash: {expected_hash}")
    print(f"Expected header: {expected_header}")
    print()
    
    # Step 1: Build coinbase (standard_standard)
    print("Step 1: Building coinbase")
    coinbase_hex = job_data["coinb1"] + extra_nonce1 + extra_nonce2 + job_data["coinb2"]
    print(f"  Coinbase: {coinbase_hex}")
    
    # Step 2: Calculate merkle root 
    print("Step 2: Calculating merkle root")
    coinbase_binary = bytes.fromhex(coinbase_hex)
    coinbase_txid = sha256d(coinbase_binary)
    print(f"  Coinbase TXID: {coinbase_txid.hex()}")
    
    # Apply merkle branch (using our corrected method)
    merkle_root = coinbase_txid
    for branch_hex in job_data["merkle_branch"]:
        branch_binary = bytes.fromhex(branch_hex)
        combined = merkle_root + branch_binary
        merkle_root = sha256d(combined)
    print(f"  Final merkle root: {merkle_root.hex()}")
    
    # Step 3: Apply discovered transformations
    print("Step 3: Applying discovered transformations")
    
    # Decode the method: standard_standard_reversed_normal_normal_reversed_reversed_mixed
    # - version: reversed (byte-reverse the version field)
    # - prevhash: reversed (some transformation)  
    # - ntime: normal (use as-is)
    # - nonce: normal (use as-is)
    # - version: reversed (byte-reverse)
    # - nbits: reversed (byte-reverse)
    # - serialization: mixed
    
    version_transformed = reverse_hex(job_data["version"])
    prevhash_transformed = job_data["prevhash"]  # The "reversed" here refers to the serialization method
    ntime_transformed = ntime  # normal = use as-is
    nonce_transformed = nonce  # normal = use as-is  
    nbits_transformed = reverse_hex(job_data["nbits"])
    
    print(f"  Version: {job_data['version']} -> {version_transformed}")
    print(f"  PrevHash: {prevhash_transformed} (as-is)")
    print(f"  NTime: {ntime} -> {ntime_transformed}")
    print(f"  NBits: {job_data['nbits']} -> {nbits_transformed}")
    print(f"  Nonce: {nonce} -> {nonce_transformed}")
    
    # Step 4: Build header using mixed endianness method
    print("Step 4: Building header with mixed endianness")
    
    def build_mixed_endian_header(version: str, prevhash: str, merkle_root_bytes: bytes, ntime: str, nbits: str, nonce: str) -> bytes:
        """Build header with mixed endianness as discovered"""
        work_data = [0] * 20
        
        # Mixed endianness method from hash_discovery.py
        work_data[0] = struct.unpack('<I', bytes.fromhex(version))[0]  # LE
        
        prevhash_bytes = bytes.fromhex(prevhash)
        for i in range(8):
            chunk = prevhash_bytes[i*4:(i+1)*4]
            work_data[1 + i] = struct.unpack('>I', chunk)[0]  # BE
        
        for i in range(8):
            chunk = merkle_root_bytes[i*4:(i+1)*4]
            work_data[9 + i] = struct.unpack('<I', chunk)[0]  # LE
        
        work_data[17] = struct.unpack('>I', bytes.fromhex(ntime))[0]   # BE
        work_data[18] = struct.unpack('<I', bytes.fromhex(nbits))[0]   # LE  
        work_data[19] = struct.unpack('>I', bytes.fromhex(nonce))[0]   # BE
        
        return struct.pack('<20I', *work_data)
    
    header_bytes = build_mixed_endian_header(
        version_transformed,
        prevhash_transformed, 
        merkle_root,
        ntime_transformed,
        nbits_transformed,
        nonce_transformed
    )
    
    result_header = header_bytes.hex()
    print(f"  Built header: {result_header}")
    
    # Step 5: Calculate scrypt hash
    print("Step 5: Calculating scrypt hash")
    scrypt_result = hashlib.scrypt(header_bytes, salt=header_bytes, n=1024, r=1, p=1, dklen=32)[::-1].hex()
    print(f"  Scrypt result: {scrypt_result}")
    
    # Step 6: Verify results
    print("\nStep 6: Verification")
    header_match = result_header == expected_header
    hash_match = scrypt_result == expected_hash
    
    print(f"  Header match: {'✅' if header_match else '❌'}")
    print(f"  Hash match: {'✅' if hash_match else '❌'}")
    
    if header_match and hash_match:
        print("\n🎯 *** PERFECT! Method verified! ***")
        print("✅ The discovered method works correctly")
        print("✅ Safe to apply to main server code")
        return True
    else:
        print("\n❌ *** VERIFICATION FAILED ***")
        if not header_match:
            print(f"  Expected header: {expected_header}")
            print(f"  Got header:      {result_header}")
        if not hash_match:
            print(f"  Expected hash: {expected_hash}")
            print(f"  Got hash:      {scrypt_result}")
        return False

def test_correct_server_implementation():
    """Test the correct server implementation using mixed endianness"""
    
    print("\n" + "="*80)
    print("🔧 TESTING CORRECT SERVER IMPLEMENTATION")
    print()
    
    # Simulate server validation with discovered method
    job = {
        "version": "00000020",
        "prevhash": "b5943ea561328af1fdfc81bd0f7bcb2bcab2ffe46fcbe261e228b8960bc1b93e",
        "nbits": "c53f011c",
        "coinb1": "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2203676940",
        "coinb2": "4d696e656420427920546f6d61732056616e61676173ffffffff02902f500900000000160014462bf26c29e00ee732f4d475a7ddb0dfb29bc7390000000000000000286a246a24aa21a9edc99be73af85f048166f41505ca0e10e47a02533dce8b88f050a91f5a6092344700000000",
        "merkle_branch": ["2683352d34d2bcd5390f3d3366cfb0ba0d8c962e5b5bd2f2de86869202883a7e"]
    }
    
    extra_nonce1 = "00000000"
    extra_nonce2 = "00000000"
    ntime = "f8cbaa68"
    nonce = "83290900"
    
    # Build coinbase
    coinbase_full = job["coinb1"] + extra_nonce1 + extra_nonce2 + job["coinb2"]
    coinbase_binary = bytes.fromhex(coinbase_full)
    
    # Calculate merkle root using EXACT method from discovery
    coinbase_txid = sha256d(coinbase_binary)
    merkle_root = coinbase_txid
    for branch_hex in job["merkle_branch"]:
        branch_binary = bytes.fromhex(branch_hex)
        combined = merkle_root + branch_binary
        merkle_root = sha256d(combined)
    
    print(f"Merkle root (binary): {merkle_root.hex()}")
    
    # Apply discovered transformations EXACTLY
    version_transformed = reverse_hex(job["version"])
    prevhash_transformed = job["prevhash"]  
    ntime_transformed = ntime  # normal = use as-is
    nonce_transformed = nonce  # normal = use as-is  
    nbits_transformed = reverse_hex(job["nbits"])
    
    print(f"Transformations:")
    print(f"  Version: {job['version']} -> {version_transformed}")
    print(f"  PrevHash: {prevhash_transformed} (as-is)")
    print(f"  NTime: {ntime} -> {ntime_transformed}")
    print(f"  NBits: {job['nbits']} -> {nbits_transformed}")
    print(f"  Nonce: {nonce} -> {nonce_transformed}")
    
    # Use EXACT mixed endianness method from discovery
    def build_mixed_endian_header_exact(version: str, prevhash: str, merkle_root_bytes: bytes, ntime: str, nbits: str, nonce: str) -> bytes:
        """Build header with EXACT mixed endianness as discovered"""
        work_data = [0] * 20
        
        # Exact method from hash_discovery.py
        work_data[0] = struct.unpack('<I', bytes.fromhex(version))[0]  # LE
        
        prevhash_bytes = bytes.fromhex(prevhash)
        for i in range(8):
            chunk = prevhash_bytes[i*4:(i+1)*4]
            work_data[1 + i] = struct.unpack('>I', chunk)[0]  # BE
        
        for i in range(8):
            chunk = merkle_root_bytes[i*4:(i+1)*4]
            work_data[9 + i] = struct.unpack('<I', chunk)[0]  # LE
        
        work_data[17] = struct.unpack('>I', bytes.fromhex(ntime))[0]   # BE
        work_data[18] = struct.unpack('<I', bytes.fromhex(nbits))[0]   # LE  
        work_data[19] = struct.unpack('>I', bytes.fromhex(nonce))[0]   # BE
        
        return struct.pack('<20I', *work_data)
    
    # Build header using EXACT method
    header_bytes = build_mixed_endian_header_exact(
        version_transformed,
        prevhash_transformed, 
        merkle_root,
        ntime_transformed,
        nbits_transformed,
        nonce_transformed
    )
    
    result_header = header_bytes.hex()
    print(f"  Header: {result_header}")
    
    # Test scrypt  
    scrypt_result = hashlib.scrypt(header_bytes, salt=header_bytes, n=1024, r=1, p=1, dklen=32)[::-1].hex()
    expected = "000000f562794800434d5deeebef1d4ecf7e121894282ec9f67e163568a7a634"
    
    print(f"  Result: {scrypt_result}")
    print(f"  Expected: {expected}")
    print(f"  Match: {'✅' if scrypt_result == expected else '❌'}")
    
    return scrypt_result == expected

# Run all tests
print("Testing discovered method...")
method_works = test_discovered_method()

print("\nTesting correct server implementation...")  
server_works = test_correct_server_implementation()

print(f"\n{'='*80}")
print("FINAL RESULTS:")
print(f"  Discovered method verified: {'✅' if method_works else '❌'}")
print(f"  Correct server implementation: {'✅' if server_works else '❌'}")

if method_works and server_works:
    print("\n🎉 *** ALL TESTS PASSED! Safe to update main server! ***")
    print("\n📋 SERVER UPDATE INSTRUCTIONS:")
    print("The server needs to use MIXED ENDIANNESS header construction,")
    print("not simple hex concatenation. Update validate_share() to use")
    print("the build_mixed_endian_header_exact() method.")
else:
    print("\n⚠️  *** TESTS FAILED! Do not update main server yet! ***")