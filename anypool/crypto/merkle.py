# -----------------------------------------------------------
#  [*] Merkle Tree
#
#  The two halves of the stratum merkle dance:
#
#    calculate_merkle_branch()           — pool side.
#      When a job is created we compute the list of sibling
#      hashes ("the branch") that proves the coinbase tx
#      (index 0) up to the merkle root. The branch is sent
#      to miners inside mining.notify.
#
#    calculate_merkle_root_from_branch() — both sides.
#      The miner (and we, when validating its share) folds
#      the coinbase txid through the branch to reproduce the
#      merkle root that goes into the block header.
#
#  IMPORTANT: all hashes in and out of this module are raw
#  double-SHA256 bytes rendered as hex — NO endianness
#  conversion happens here. Getting this wrong was the
#  hardest bug in this project; keep it that way.
#
#  Used by:
#    - mining/jobs.py   — branch calculation at job creation
#    - mining/shares.py — root recomputation at share validation
# -----------------------------------------------------------

from typing import List

from anypool.crypto.hashing import sha256d




# -----------------------------------------------------------
# calculate_merkle_branch
# -----------------------------------------------------------
#
# Given all transaction hashes of the block (coinbase first)
# and the index of the tx to prove, returns the list of
# sibling hashes needed to rebuild the root from that leaf.
#
# Works level by level: pad to an even count, record the
# sibling of our index (idx ^ 1), hash the pairs into the
# next level, halve the index, repeat until one node is left.
#
# Used by:
#   - mining/jobs.py — build_job() proves the coinbase (index 0)
# -----------------------------------------------------------
def calculate_merkle_branch(tx_hashes: List[str], index_to_prove: int) -> List[str]:
    if not tx_hashes:
        return []

    # Start with all txids as raw bytes (NO endianness conversion for hashing)
    level = [bytes.fromhex(txid) for txid in tx_hashes]
    branch = []
    idx = index_to_prove

    while len(level) > 1:

        # Pad to even count
        if len(level) % 2 == 1:
            level.append(level[-1])

        # Record our sibling on this level (XOR flips the last bit of the index)
        sibling_idx = idx ^ 1
        if sibling_idx < len(level):
            branch.append(level[sibling_idx].hex())

        # Hash the pairs into the next level
        next_level = []
        for i in range(0, len(level), 2):
            combined = level[i] + level[i + 1]
            next_level.append(sha256d(combined))

        level = next_level
        idx //= 2

    return branch










# -----------------------------------------------------------
# calculate_merkle_root_from_branch
# -----------------------------------------------------------
#
# Folds a leaf hash through its merkle branch to reproduce
# the root. The index parity at each level decides whether
# the sibling is concatenated on the left or the right.
#
# The returned hex is in header (little-endian) byte order —
# it can be dropped straight into the 80-byte block header.
#
# Used by:
#   - mining/shares.py — build_header() during share validation
# -----------------------------------------------------------
def calculate_merkle_root_from_branch(leaf_hex: str, branch: List[str], index: int) -> str:
    # Start with leaf as raw bytes (NO endianness conversion for hashing)
    current = bytes.fromhex(leaf_hex)

    for sibling_hex in branch:
        sibling = bytes.fromhex(sibling_hex)  # Raw bytes, no conversion
        if index % 2 == 1:
            combined = sibling + current
        else:
            combined = current + sibling
        current = sha256d(combined)
        index //= 2

    # Return as little-endian hex (header format)
    return current.hex()
