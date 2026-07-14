# -----------------------------------------------------------
#  [*] Tests — Merkle Tree
#
#  Covers anypool/crypto/merkle.py, in two layers:
#
#    - the real (degenerate) case from KNF block 1777: a
#      coinbase-only block has an EMPTY branch and its merkle
#      root IS the coinbase txid;
#    - synthetic multi-transaction trees, checked for the
#      fundamental branch/root property: folding any leaf
#      through its branch reproduces the full tree's root.
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
# -----------------------------------------------------------

import unittest

from anypool.crypto.hashing import sha256d
from anypool.crypto.merkle import calculate_merkle_branch, calculate_merkle_root_from_branch
from tests import vectors




# -----------------------------------------------------------
# reference_merkle_root
# -----------------------------------------------------------
#
# Straightforward bottom-up merkle root, implemented
# independently from the module under test so the branch
# math is verified against something, not against itself.
#
# Used by:
#   - tests/test_merkle.py — property tests below
# -----------------------------------------------------------
def reference_merkle_root(tx_hashes_hex):
    level = [bytes.fromhex(h) for h in tx_hashes_hex]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0].hex()










class TestBlock1777(unittest.TestCase):


    # -----------------------------------------------------------
    # A coinbase-only block has an empty merkle branch.
    # -----------------------------------------------------------
    def test_single_tx_branch_is_empty(self):
        coinbase_txid = "e24f32b428288decdf51631020c509bb204549af34a0d5d7e4cb75900056db97"
        self.assertEqual(calculate_merkle_branch([coinbase_txid], 0), [])






    # -----------------------------------------------------------
    # With an empty branch, the root is the leaf itself. This is
    # exactly what happened for the accepted share of block 1777:
    # the real coinbase txid became the header's merkle root.
    # -----------------------------------------------------------
    def test_block_1777_root_equals_coinbase_txid(self):
        coinbase_hex = (vectors.COINB1 + vectors.EXTRANONCE1 +
                        vectors.EXTRANONCE2 + vectors.COINB2)
        coinbase_txid_le = sha256d(bytes.fromhex(coinbase_hex)).hex()

        root = calculate_merkle_root_from_branch(coinbase_txid_le, [], 0)
        self.assertEqual(root, vectors.MERKLE_ROOT_LE)










class TestBranchRootProperty(unittest.TestCase):


    # -----------------------------------------------------------
    # For trees of 2..8 leaves: the branch computed for the
    # coinbase (index 0) must fold back to the same root as the
    # independent reference implementation.
    # -----------------------------------------------------------
    def test_branch_folds_back_to_root(self):
        for tx_count in range(2, 9):
            with self.subTest(tx_count=tx_count):
                txids = [sha256d(bytes([i])).hex() for i in range(tx_count)]

                expected_root = reference_merkle_root(txids)
                branch = calculate_merkle_branch(txids, 0)
                folded_root = calculate_merkle_root_from_branch(txids[0], branch, 0)

                self.assertEqual(folded_root, expected_root)






    # -----------------------------------------------------------
    # The branch of the coinbase must not depend on the coinbase
    # itself — that is what allows the pool to compute ONE branch
    # per job while every miner has a different extranonce.
    # -----------------------------------------------------------
    def test_branch_independent_of_coinbase(self):
        other_txids = [sha256d(bytes([i])).hex() for i in range(1, 5)]

        coinbase_a = sha256d(b"coinbase-a").hex()
        coinbase_b = sha256d(b"coinbase-b").hex()

        branch_a = calculate_merkle_branch([coinbase_a] + other_txids, 0)
        branch_b = calculate_merkle_branch([coinbase_b] + other_txids, 0)

        self.assertEqual(branch_a, branch_b)






    # -----------------------------------------------------------
    # Empty input is a valid degenerate case.
    # -----------------------------------------------------------
    def test_empty_input(self):
        self.assertEqual(calculate_merkle_branch([], 0), [])




if __name__ == "__main__":
    unittest.main()
