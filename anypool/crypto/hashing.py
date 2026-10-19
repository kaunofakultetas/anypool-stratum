############################################################
#  [*] Hashing & Hex Primitives
#
#  The lowest-level building blocks of the pool: double
#  SHA256, the Scrypt and SHA256d proof-of-work hashes, and
#  the two hex byte-order helpers that the stratum protocol
#  forces on us (miners expect some header fields
#  byte-reversed, and the previous block hash reversed in
#  4-byte words).
#
#  Everything here is a pure function of its inputs — no
#  state, no config — which makes this the easiest module in
#  the codebase to unit test against known mined blocks.
#
#  Used by:
#    - crypto/merkle.py, crypto/base58.py — sha256d
#    - coins/ definitions — their pow_hash functions
#    - families/bitcoin/jobs.py, shares.py, server.py —
#      field conversions, header assembly, coinbase txids
#      and the block hash shown in the share panel
############################################################


import hashlib

# scrypt (a C extension) is imported lazily inside
# scrypt_pow_hash() so CryptoNote-family pools and the parts
# of the test suite that never scrypt-hash do not need the
# module installed.








############################################################
# sha256d
############################################################
#
# Bitcoin's workhorse: SHA256 applied twice. Used for txids,
# merkle tree nodes and the block hash itself.
#
# Used by:
#   - sha256d_pow_hash() (below)
#   - crypto/merkle.py — every tree node
#   - crypto/base58.py — the base58check checksum
#   - families/bitcoin/jobs.py, shares.py — the coinbase txid
#   - families/bitcoin/server.py — process_share(), the block
#     hash in the share panel
############################################################

def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()








############################################################
# scrypt_pow_hash
############################################################
#
# The Scrypt proof-of-work hash used by Litecoin-family
# coins: N of 1024, r and p of 1, the header serving as its
# own salt, 32 bytes out. Takes the exact 80-byte serialized
# block header (ValueError otherwise) and returns the hash
# as big-endian hex, ready to be compared numerically
# against a target.
#
# Used by:
#   - coins/doge.py, knf.py, ltc.py — as their pow_hash,
#     which families/bitcoin/shares.py build_header() calls
#     through coins.active()
############################################################

def scrypt_pow_hash(header_bytes: bytes) -> str:
    import scrypt
    if len(header_bytes) != 80:
        raise ValueError("Header must be 80 bytes for Scrypt hashing.")
    return scrypt.hash(header_bytes, header_bytes, 1024, 1, 1, 32)[::-1].hex()








############################################################
# sha256d_pow_hash
############################################################
#
# The SHA256d proof-of-work hash used by Bitcoin itself. For
# SHA256 coins the PoW hash IS the block hash — double SHA256
# of the 80-byte header (ValueError for any other length),
# rendered big-endian so it can be compared numerically
# against a target.
#
# Used by:
#   - coins/btc.py — as its pow_hash, which
#     families/bitcoin/shares.py build_header() calls through
#     coins.active()
############################################################

def sha256d_pow_hash(header_bytes: bytes) -> str:
    if len(header_bytes) != 80:
        raise ValueError("Header must be 80 bytes for SHA256d hashing.")
    return sha256d(header_bytes)[::-1].hex()








############################################################
# reverse_hex
############################################################
#
# Reverses the byte order of a hex string: the pairs of hex
# characters come back in the opposite order, each pair
# itself untouched. This is how a whole field is flipped
# between the big-endian display form and the little-endian
# form used inside a serialized block header, and flipping
# twice gives the original back.
#
# Used by:
#   - reverse_hex_4b_chunks() (below)
#   - families/bitcoin/jobs.py, shares.py, server.py
############################################################

def reverse_hex(hex_str: str) -> str:
    return ''.join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)]))








############################################################
# reverse_hex_4b_chunks
############################################################
#
# Flips the byte order inside each 4-byte word (8 hex chars)
# of a 32-byte hex string while the eight words keep their
# places. The stratum protocol transmits the previous block
# hash in this odd "word-swapped" form, so both job creation
# and header assembly need this exact transformation.
#
# Used by:
#   - families/bitcoin/jobs.py, shares.py, server.py
############################################################

def reverse_hex_4b_chunks(hex_str: str) -> str:
    hex_str_final = ""
    for i in range(0, 64, 8):
        chunk = hex_str[i:i+8]
        hex_str_final += reverse_hex(chunk)
    return hex_str_final
