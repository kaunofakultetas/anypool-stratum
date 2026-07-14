# -----------------------------------------------------------
#  [*] Hashing & Hex Primitives
#
#  The lowest-level building blocks of the pool: double
#  SHA256, the Scrypt proof-of-work hash and the two hex
#  byte-order helpers that the stratum protocol forces on us
#  (miners expect some header fields byte-reversed, and the
#  previous block hash reversed in 4-byte words).
#
#  Everything here is a pure function of its inputs — no
#  state, no config — which makes this the easiest module in
#  the codebase to unit test against known mined blocks.
#
#  Used by:
#    - crypto/merkle.py  — sha256d for tree hashing
#    - mining/coinbase.py — txid hashing
#    - mining/shares.py   — header assembly + PoW hash
#    - mining/jobs.py     — prevhash conversion for job fields
#    - stratum/server.py  — display of hashes in log panels
# -----------------------------------------------------------

import hashlib

import scrypt




# -----------------------------------------------------------
# sha256d
# -----------------------------------------------------------
#
# Bitcoin's workhorse: SHA256 applied twice. Used for txids,
# merkle tree nodes and the block hash itself.
#
# Used by:
#   - crypto/merkle.py, mining/coinbase.py, mining/shares.py,
#     stratum/server.py
# -----------------------------------------------------------
def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()










# -----------------------------------------------------------
# scrypt_pow_hash
# -----------------------------------------------------------
#
# The Scrypt proof-of-work hash (N=1024, r=1, p=1) used by
# Litecoin-family coins. Takes the exact 80-byte serialized
# block header and returns the hash as big-endian hex, ready
# to be compared numerically against a target.
#
# Used by:
#   - mining/shares.py — build_header()
#   - coins/ definitions — as their pow_hash function
# -----------------------------------------------------------
def scrypt_pow_hash(header_bytes: bytes) -> str:
    if len(header_bytes) != 80:
        raise ValueError("Header must be 80 bytes for Scrypt hashing.")
    return scrypt.hash(header_bytes, header_bytes, 1024, 1, 1, 32)[::-1].hex()










# -----------------------------------------------------------
# reverse_hex
# -----------------------------------------------------------
#
# Reverse a hex string byte-wise (in 2-char chunks). This is
# how a whole field is flipped between big-endian display
# form and the little-endian form used inside a serialized
# block header.
#
# INPUT:
# +---------------------------------------+
# | 01 | 23 | 45 | 67 | 89 | AB | CD | EF |
# +---------------------------------------+
#
# OUTPUT:
# +---------------------------------------+
# | EF | CD | AB | 89 | 67 | 45 | 23 | 01 |
# +---------------------------------------+
#
# Used by:
#   - mining/shares.py, mining/jobs.py, stratum/server.py
# -----------------------------------------------------------
def reverse_hex(hex_str: str) -> str:
    return ''.join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)]))










# -----------------------------------------------------------
# reverse_hex_4b_chunks
# -----------------------------------------------------------
#
# Reverse a 32-byte hex string in 4-byte words (8 hex chars
# each). The stratum protocol transmits the previous block
# hash in this odd "word-swapped" form, so both job creation
# and header assembly need this exact transformation.
#
# INPUT:
# +---------------------------------------------------------------------------------------+
# | 01234567 | 89ABCDEF | 76543210 | FEDCBA98 | 0123ABCD | EF012345 | 6789ABCD | FEDCBA98 |
# +---------------------------------------------------------------------------------------+
#       |         |          |          |          |          |          |          |
#     FLIP      FLIP       FLIP       FLIP       FLIP       FLIP       FLIP       FLIP
#       V         |          |          |          |          |          |          |
# OUTPUT:         V          V          V          V          V          V          V
# +---------------------------------------------------------------------------------------+
# | 67452301 | EFCDAB89 | 10325476 | 98BADCFE | CDAB2301 | 452301EF | CDAB8967 | 98BADCFE |
# +---------------------------------------------------------------------------------------+
#
# Used by:
#   - mining/shares.py, mining/jobs.py, stratum/server.py
# -----------------------------------------------------------
def reverse_hex_4b_chunks(hex_str: str) -> str:
    hex_str_final = ""
    for i in range(0, 64, 8):  # Process 4-byte chunks (8 hex chars each)
        chunk = hex_str[i:i+8]
        hex_str_final += reverse_hex(chunk)
    return hex_str_final
