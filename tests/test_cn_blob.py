############################################################
#  [*] Tests — CryptoNote Block Blobs
#
#  Covers families/cryptonote/blob.py against REAL blocks of
#  the live Bitlitas chain (see cn_vectors.py): if parsing,
#  the keccak, the miner tx hash or the tree hash were wrong
#  in any byte, the computed block ids could not match the
#  ids the network itself reports.
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
############################################################


import unittest

from anypool.families.cryptonote.blob import (
    block_id,
    hashing_blob,
    parse_block,
    tree_hash,
    with_extranonce,
    with_nonce,
)
from anypool.crypto.keccak import keccak_256
from tests import cn_vectors








class TestParseBlock(unittest.TestCase):






    ############################################################
    # The final block of the original chain parses with every
    # byte accounted for.
    ############################################################

    def test_parse_final_block(self):
        blob = bytes.fromhex(cn_vectors.BLOCK_46860_BLOB)
        parsed = parse_block(blob)

        self.assertEqual(parsed["major_version"], 1)
        self.assertEqual(parsed["nonce_offset"], 39)
        self.assertEqual(len(parsed["prev_id"]), 32)
        self.assertEqual(parsed["tx_hashes"], [])






    ############################################################
    # A blob with extra bytes after the tx hashes must raise —
    # every byte has to be accounted for, never mis-parsed.
    ############################################################

    def test_trailing_bytes_rejected(self):
        blob = bytes.fromhex(cn_vectors.BLOCK_46860_BLOB) + b"\x00"
        with self.assertRaises(ValueError):
            parse_block(blob)






    ############################################################
    # A blob cut short must raise as well (the varint reader
    # surfaces truncation as IndexError, structural checks as
    # ValueError — either way, never a quiet mis-parse).
    ############################################################

    def test_truncated_blob_rejected(self):
        blob = bytes.fromhex(cn_vectors.BLOCK_46860_BLOB)[:-8]
        with self.assertRaises((ValueError, IndexError)):
            parse_block(blob)








class TestBlockId(unittest.TestCase):






    ############################################################
    # The final block of the original chain: its recomputed id
    # must equal what the network reports (miner tx only — a
    # single tree leaf).
    ############################################################

    def test_final_block_id(self):
        blob = bytes.fromhex(cn_vectors.BLOCK_46860_BLOB)
        self.assertEqual(block_id(blob).hex(), cn_vectors.BLOCK_46860_ID)






    ############################################################
    # A block carrying one mempool tx: two tree leaves, the
    # simplest real pairing case.
    ############################################################

    def test_block_with_one_tx(self):
        blob = bytes.fromhex(cn_vectors.BLOCK_38372_BLOB)
        self.assertEqual(len(parse_block(blob)["tx_hashes"]), 1)
        self.assertEqual(block_id(blob).hex(), cn_vectors.BLOCK_38372_ID)






    ############################################################
    # A block carrying three mempool txs: four tree leaves,
    # exercising the power-of-two reduction of tree_hash.
    ############################################################

    def test_block_with_three_txs(self):
        blob = bytes.fromhex(cn_vectors.BLOCK_42965_BLOB)
        self.assertEqual(len(parse_block(blob)["tx_hashes"]), 3)
        self.assertEqual(block_id(blob).hex(), cn_vectors.BLOCK_42965_ID)








class TestTreeHash(unittest.TestCase):






    ############################################################
    # One leaf hashes to itself — no keccak round at all.
    ############################################################

    def test_single_leaf_is_itself(self):
        leaf = keccak_256(b"leaf")
        self.assertEqual(tree_hash([leaf]), leaf)






    ############################################################
    # Two leaves: exactly one pair hash.
    ############################################################

    def test_two_leaves(self):
        a, b = keccak_256(b"a"), keccak_256(b"b")
        self.assertEqual(tree_hash([a, b]), keccak_256(a + b))






    ############################################################
    # Three leaves: CryptoNote pair-hashes the TAIL (b, c)
    # first and leaves the head alone — not Bitcoin's
    # duplicate-the-last-leaf padding.
    ############################################################

    def test_three_leaves_pairs_the_tail(self):
        a, b, c = (keccak_256(x) for x in (b"a", b"b", b"c"))
        self.assertEqual(tree_hash([a, b, c]),
                         keccak_256(a + keccak_256(b + c)))






    ############################################################
    # No leaves is a caller bug and must raise.
    ############################################################

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            tree_hash([])








class TestHashingBlob(unittest.TestCase):






    ############################################################
    # The classic 76-byte layout: header(43) + root(32) +
    # tx count varint(1).
    ############################################################

    def test_hashing_blob_layout(self):
        blob = bytes.fromhex(cn_vectors.BLOCK_46860_BLOB)
        hb = hashing_blob(blob)
        self.assertEqual(len(hb), 76)
        # header prefix is shared verbatim with the full blob
        self.assertEqual(hb[:43], blob[:43])
        # miner-tx-only block: count varint == 1
        self.assertEqual(hb[-1], 1)








class TestInjection(unittest.TestCase):






    ############################################################
    # Nonce injection: only the 4 nonce bytes change, and the
    # hashing blob of a template picks the change up.
    ############################################################

    def test_with_nonce(self):
        blob = bytes.fromhex(cn_vectors.BLOCK_46860_BLOB)
        parsed = parse_block(blob)
        patched = with_nonce(blob, b"\xAA\xBB\xCC\xDD", parsed["nonce_offset"])

        self.assertEqual(len(patched), len(blob))
        self.assertEqual(patched[parsed["nonce_offset"]:parsed["nonce_offset"] + 4],
                         b"\xAA\xBB\xCC\xDD")
        self.assertEqual(patched[:parsed["nonce_offset"]], blob[:parsed["nonce_offset"]])
        self.assertEqual(patched[parsed["nonce_offset"] + 4:], blob[parsed["nonce_offset"] + 4:])






    ############################################################
    # Extranonce injection into a REAL template: the blob
    # still parses, and distinct extranonces yield distinct
    # hashing blobs (each miner gets unique work).
    ############################################################

    def test_with_extranonce_changes_work(self):
        blob = bytes.fromhex(cn_vectors.TEMPLATE_BLOB)
        ro = cn_vectors.TEMPLATE_RESERVED_OFFSET
        rs = cn_vectors.TEMPLATE_RESERVE_SIZE

        one = with_extranonce(blob, b"MINER-01", ro, rs)
        two = with_extranonce(blob, b"MINER-02", ro, rs)

        parse_block(one)  # must still be structurally valid
        self.assertEqual(len(one), len(blob))
        self.assertNotEqual(hashing_blob(one), hashing_blob(two))






    ############################################################
    # An extranonce longer than the reserved space would
    # overwrite real template bytes — must raise.
    ############################################################

    def test_extranonce_too_large_rejected(self):
        blob = bytes.fromhex(cn_vectors.TEMPLATE_BLOB)
        with self.assertRaises(ValueError):
            with_extranonce(blob, b"X" * 17, cn_vectors.TEMPLATE_RESERVED_OFFSET, 16)
