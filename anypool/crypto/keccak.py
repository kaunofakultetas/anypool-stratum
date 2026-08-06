############################################################
#  [*] Keccak-256 (original padding)
#
#  CryptoNote coins hash with the ORIGINAL Keccak submission
#  (pad byte 0x01), not the finalized NIST SHA-3 (pad byte
#  0x06) — so hashlib.sha3_256 CANNOT be used. This is a pure
#  Python Keccak-f[1600] sponge, ~100 lines, fast enough for
#  the few hashes per job/share the pool needs (transaction
#  ids, tree hashes, block ids). The MILLIONS of hashes of
#  the actual PoW live in crypto/cryptonight.py (C).
#
#  Used by:
#    - crypto/cn_base58.py           — address checksums
#    - families/cryptonote/blob.py   — tx hashes, tree hash,
#                                      block ids
############################################################


# Rotation offsets of the 24 rho steps, in (x, y) order
_ROTC = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
         27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44]

# Lane permutation of the pi step
_PILN = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
         15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1]

# Round constants of the iota step
_RNDC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

_MASK = 0xFFFFFFFFFFFFFFFF








############################################################
# _keccak_f
############################################################
#
# One Keccak-f[1600] permutation of the 25-lane state: all
# 24 rounds of theta, rho+pi, chi and iota, as plain integer
# math on 64-bit lanes (masked with _MASK). Mutates and
# returns the state list.
#
# Used by:
#   - keccak_256 (below) — once per 136-byte block
############################################################

def _keccak_f(state):
    for rnd in range(24):

        # theta
        bc = [state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20]
              for i in range(5)]
        for i in range(5):
            t = bc[(i + 4) % 5] ^ (((bc[(i + 1) % 5] << 1) | (bc[(i + 1) % 5] >> 63)) & _MASK)
            for j in range(0, 25, 5):
                state[j + i] ^= t

        # rho + pi
        t = state[1]
        for i in range(24):
            j = _PILN[i]
            bc[0] = state[j]
            r = _ROTC[i]
            state[j] = ((t << r) | (t >> (64 - r))) & _MASK
            t = bc[0]

        # chi
        for j in range(0, 25, 5):
            row = state[j:j + 5]
            for i in range(5):
                state[j + i] = row[i] ^ ((~row[(i + 1) % 5]) & row[(i + 2) % 5]) & _MASK

        # iota
        state[0] ^= _RNDC[rnd]

    return state








############################################################
# keccak_256
############################################################
#
# The CryptoNote "cn_fast_hash": Keccak-256 with rate 1088
# (136-byte blocks) and the original 0x01 padding.
#
# Used by:
#   - crypto/cn_base58.py, families/cryptonote/blob.py
############################################################

def keccak_256(data: bytes) -> bytes:
    rate = 136
    state = [0] * 25

    # Original Keccak multi-rate padding: 0x01 ... 0x80
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] |= 0x80

    for block_start in range(0, len(padded), rate):
        block = padded[block_start:block_start + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        _keccak_f(state)

    out = b"".join(state[i].to_bytes(8, "little") for i in range(4))
    return out
