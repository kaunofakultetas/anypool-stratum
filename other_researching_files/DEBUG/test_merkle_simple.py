import hashlib

# The two transaction hashes (as hex strings)
tx0 = "cd2d968e16b358b87dd9827e83419a52d3e4c40dda3b8faa50d34390feaae1fa"
tx1 = "9d46d46e15b2e5695a8a5964ade9afe9e133268c1570f7c4b64e3b3cf696fb50"

# Convert hex strings to bytes
tx0_bytes = bytes.fromhex(tx0)
tx1_bytes = bytes.fromhex(tx1)

print(f"TX 0 bytes: {tx0_bytes.hex()}")
print(f"TX 1 bytes: {tx1_bytes.hex()}")

# Concatenate the two hashes (raw bytes)
combined = tx0_bytes + tx1_bytes
print(f"Combined: {combined.hex()}")

# Apply double SHA256 (like Bitcoin merkle tree)
hash1 = hashlib.sha256(combined).digest()
hash2 = hashlib.sha256(hash1).digest()

# Result as hex string (little-endian format)
merkle_root = hash2.hex()
print(f"Merkle root (LE): {merkle_root}")

# For display purposes, reverse to big-endian
merkle_root_be = bytes.fromhex(merkle_root)[::-1].hex()
print(f"Merkle root (BE): {merkle_root_be}")