# -----------------------------------------------------------
#  [*] Share Validation
#
#  Rebuilds what the miner claims to have hashed and checks
#  it. The heart of it is build_header(): given a job and the
#  four values the miner chose (extranonce2, ntime, nonce —
#  extranonce1 was assigned by us), it reconstructs the exact
#  80-byte block header and its Scrypt PoW hash.
#
#  This ONE function is used both to validate shares and to
#  build the header of a block we submit to the network — so
#  a share we accept as a block is guaranteed to serialize to
#  the same header we submit. (Previously the logic existed
#  twice and could drift apart.)
#
#  Endianness cheat-sheet for the header fields, going from
#  the stratum job values to serialized header bytes:
#
#    version   — byte-reversed          (reverse_hex)
#    prevhash  — word-reversed          (reverse_hex_4b_chunks)
#    merkle    — used as-is             (already header order)
#    ntime     — byte-reversed          (reverse_hex)
#    nbits     — byte-reversed          (reverse_hex)
#    nonce     — byte-reversed          (reverse_hex)
#
#  The PoW function itself is NOT hardcoded here — it comes
#  from the active coin's definition (anypool/coins/), so
#  supporting a non-Scrypt coin needs no change in this file.
#
#  Used by:
#    - stratum/server.py     — process_share() + _submit_block()
#    - stratum/connection.py — validate_share_params() on submit
# -----------------------------------------------------------

from typing import Dict, List, Tuple

from anypool import coins, display
from anypool.crypto.hashing import reverse_hex, reverse_hex_4b_chunks, sha256d
from anypool.crypto.merkle import calculate_merkle_root_from_branch


# How far a miner may roll ntime away from the job's ntime.
# Forward matches the network's own future-block tolerance
# (2 hours); a little backward slack covers clock skew.
NTIME_FORWARD_SLACK = 7200
NTIME_BACKWARD_SLACK = 600




# -----------------------------------------------------------
# validate_share_params
# -----------------------------------------------------------
#
# Sanity check of a raw mining.submit parameter list before
# anything is done with it: exactly 5 entries, and the three
# miner-chosen values must be valid 4-byte hex strings.
#
# Expected params:
#   [worker_name, job_id, extra_nonce2, ntime, nonce]
#
# Used by:
#   - stratum/connection.py — handle_submit()
# -----------------------------------------------------------
def validate_share_params(params: List) -> bool:
    if len(params) != 5:
        return False

    worker_name, job_id, extra_nonce2, ntime, nonce = params

    try:
        # Must parse as hex
        int(extra_nonce2, 16)
        int(ntime, 16)
        int(nonce, 16)

        # Must all be exactly 4 bytes (8 hex chars)
        if len(extra_nonce2) != 8:
            return False
        if len(ntime) != 8:
            return False
        if len(nonce) != 8:
            return False

        return True

    except (ValueError, TypeError):
        return False










# -----------------------------------------------------------
# ntime_within_range
# -----------------------------------------------------------
#
# True when the miner's ntime stays inside the allowed window
# around the job's ntime. Miners legitimately "roll" ntime a
# few seconds to extend their nonce space, but an unbounded
# ntime would let a share claim a timestamp the network would
# never accept in a real block.
#
# Used by:
#   - stratum/server.py — process_share()
# -----------------------------------------------------------
def ntime_within_range(job_ntime_hex: str, ntime_hex: str) -> bool:
    job_ntime = int(job_ntime_hex, 16)
    ntime = int(ntime_hex, 16)
    return (job_ntime - NTIME_BACKWARD_SLACK) <= ntime <= (job_ntime + NTIME_FORWARD_SLACK)










# -----------------------------------------------------------
# build_header
# -----------------------------------------------------------
#
# Reconstructs the 80-byte block header a miner hashed for a
# given job + nonce combination, in four steps:
#
#   1. Reassemble the coinbase tx (txid serialization):
#        coinb1 + extranonce1 + extranonce2 + coinb2
#      and double-SHA256 it into the coinbase txid.
#   2. Fold the txid through the job's merkle branch to get
#      the merkle root.
#   3. Convert each header field to serialized byte order
#      (see the cheat-sheet in the module header).
#   4. Concatenate into the header and hash it with the
#      active coin's PoW function.
#
# Returns (pow_hash_hex, header_hex, header_bytes).
# The caller compares int(pow_hash_hex, 16) against the
# pool / network targets.
#
# `context` only labels the DEBUG panels so logs show whether
# the header was built during validation or block submission.
#
# Used by:
#   - stratum/server.py — process_share() and _submit_block()
# -----------------------------------------------------------
def build_header(job: Dict, extra_nonce1: str, extra_nonce2: str,
                 ntime: str, nonce: str, context: str = "validate_share") -> Tuple[str, str, bytes]:

    # Step 1: Reassemble the coinbase tx and hash it into its txid
    coinbase_txid_hex = job["coinb1"] + extra_nonce1 + extra_nonce2 + job["coinb2"]
    coinbase_txid_le = sha256d(bytes.fromhex(coinbase_txid_hex)).hex()
    coinbase_txid_be = coinbase_txid_le[::-1]  # For display purposes

    display.debug_box(f"Coinbase Elements as concatenated in {context}()", [
        "Coinb1: ".ljust(15) +        job["coinb1"],
        "Extra Nonce 1: ".ljust(15) + extra_nonce1,
        "Extra Nonce 2: ".ljust(15) + extra_nonce2,
        "Coinb2: ".ljust(15) +        job["coinb2"],
        "",
        "Coinbase: ".ljust(15) +      coinbase_txid_hex,
        "Coinbase TXID: ".ljust(15) + coinbase_txid_be,
    ])


    # Step 2: Fold the coinbase txid through the merkle branch
    merkle_root_le = calculate_merkle_root_from_branch(
        coinbase_txid_le, job["merkle_branch"], 0
    )

    display.debug_box(f"Merkle Root Elements as passed to calculate_merkle_root_from_branch() in {context}()", [
        "Coinbase TXID: ".ljust(25) +          coinbase_txid_be,
        "Merkle Branch: ".ljust(25) +          str(job["merkle_branch"]),
        "",
        "Calculated Merkle Root: ".ljust(25) + merkle_root_le,
    ])


    # Step 3: Convert every field into serialized header byte order
    version_final = reverse_hex(job["version"])
    prevhash_final = reverse_hex_4b_chunks(job["prevhash"])
    merkle_final = merkle_root_le
    ntime_final = reverse_hex(ntime)
    nbits_final = reverse_hex(job["nbits"])
    nonce_final = reverse_hex(nonce)


    # Step 4: Concatenate into the 80-byte header and PoW-hash it
    header_hex = version_final + prevhash_final + merkle_final + ntime_final + nbits_final + nonce_final
    header_bytes = bytes.fromhex(header_hex)
    pow_hash_hex = coins.active().pow_hash(header_bytes)

    display.debug_box(f"Header Elements as Concatenated in {context}()", [
        "Version: ".ljust(15) +  version_final,
        "PrevHash: ".ljust(15) + prevhash_final,
        "Merkle: ".ljust(15) +   merkle_final,
        "NTime: ".ljust(15) +    ntime_final,
        "NBits: ".ljust(15) +    nbits_final,
        "Nonce: ".ljust(15) +    nonce_final,
        "",
        "PoW Hash: ".ljust(15) + pow_hash_hex,
    ])


    return pow_hash_hex, header_hex, header_bytes
