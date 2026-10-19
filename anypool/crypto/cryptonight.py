############################################################
#  [*] CryptoNight PoW
#
#  The one place the pool touches the actual CryptoNote
#  proof-of-work. CryptoNight builds a 2 MB scratchpad and
#  walks it ~1M times — pure Python would take SECONDS per
#  hash, so this wraps the py-cryptonight C extension (the
#  same code Monero's own test suite uses). Imported lazily:
#  Bitcoin-family pools and most of the test suite never need
#  the extension installed.
#
#  Also home to the difficulty math of CryptoNote coins,
#  which is pleasantly simpler than Bitcoin's bits/targets: a
#  hash is valid when, read as a little-endian 256-bit number
#  and multiplied by the difficulty, it stays below 2^256.
#
#  Used by:
#    - families/cryptonote/server.py — share validation
#    - families/cryptonote/jobs.py   — compact job targets
############################################################


# 2^256 — one past the largest 256-bit value, not the
# largest itself
_UINT256 = 1 << 256








############################################################
# cn_slow_hash
############################################################
#
# The PoW hash of a (nonced) hashing blob — 76 bytes for a
# typical block. Variant 0 is classic CryptoNight — what a
# chain frozen at block major version 1 (like Bitlitas)
# uses. The C extension is imported on first use (see the
# header).
#
# Used by:
#   - families/cryptonote/server.py — process_share()
############################################################

def cn_slow_hash(data: bytes, variant: int = 0) -> bytes:
    import pycryptonight
    return pycryptonight.cn_slow_hash(data, variant)








############################################################
# hash_meets_difficulty
############################################################
#
# Monero's check_hash(): read the 32-byte PoW hash as a
# LITTLE-endian integer and require that, multiplied by the
# difficulty, it stays below 2^256. Used for both pool
# shares and network blocks so the pool's block verdict can
# never disagree with the daemon's.
#
# Used by:
#   - families/cryptonote/server.py — process_share()
############################################################

def hash_meets_difficulty(pow_hash: bytes, difficulty: int) -> bool:
    return int.from_bytes(pow_hash, "little") * difficulty < _UINT256








############################################################
# compact_target
############################################################
#
# The 4-byte target field of a CryptoNote stratum job: the
# top 32 bits of the full 256-bit target (the largest
# 256-bit value divided by the difficulty), transmitted
# little-endian as hex. Miners compare the top of their hash
# against it. Any difficulty below 2^32 fits — far beyond
# what a CPU-mined pool needs; a larger one, or one below 1,
# raises ValueError.
#
# Used by:
#   - families/cryptonote/jobs.py — CnJobManager.make_job(),
#     the job's target
############################################################

def compact_target(difficulty: int) -> str:
    if difficulty < 1:
        raise ValueError("difficulty must be >= 1")
    if difficulty > 0xFFFFFFFF:
        # The 4-byte job target cannot express this; it would
        # silently encode target 0 and no share could ever pass.
        raise ValueError("difficulty exceeds the 4-byte job target encoding")
    target = (_UINT256 - 1) // difficulty
    return target.to_bytes(32, "big")[:4][::-1].hex()
