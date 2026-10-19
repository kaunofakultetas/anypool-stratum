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








############################################################
# TestParseBlock
############################################################
#
# parse_block() on the real final block: every byte
# accounted for, and a blob with bytes too many or too few
# refused instead of mis-parsed.
############################################################

class TestParseBlock(unittest.TestCase):






    ############################################################
    # test_parse_final_block
    ############################################################
    #
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
    # test_trailing_bytes_rejected
    ############################################################
    #
    # A blob with extra bytes after the tx hashes must raise —
    # every byte has to be accounted for, never mis-parsed.
    ############################################################

    def test_trailing_bytes_rejected(self):
        blob = bytes.fromhex(cn_vectors.BLOCK_46860_BLOB) + b"\x00"
        with self.assertRaises(ValueError):
            parse_block(blob)






    ############################################################
    # test_truncated_blob_rejected
    ############################################################
    #
    # A blob cut short must raise as well (the varint reader
    # surfaces truncation as IndexError, structural checks as
    # ValueError — either way, never a quiet mis-parse).
    ############################################################

    def test_truncated_blob_rejected(self):
        blob = bytes.fromhex(cn_vectors.BLOCK_46860_BLOB)[:-8]
        with self.assertRaises((ValueError, IndexError)):
            parse_block(blob)








############################################################
# TestBlockId
############################################################
#
# block_id() recomputed for real blocks carrying no, one and
# three mempool transactions, against the ids the network
# reports — the parsing, the keccak, the miner tx hash and
# the tree hash all have to be right for these to match.
############################################################

class TestBlockId(unittest.TestCase):






    ############################################################
    # test_final_block_id
    ############################################################
    #
    # The final block of the original chain: its recomputed id
    # must equal what the network reports (miner tx only — a
    # single tree leaf).
    ############################################################

    def test_final_block_id(self):
        blob = bytes.fromhex(cn_vectors.BLOCK_46860_BLOB)
        self.assertEqual(block_id(blob).hex(), cn_vectors.BLOCK_46860_ID)






    ############################################################
    # test_block_with_one_tx
    ############################################################
    #
    # A block carrying one mempool tx: two tree leaves, the
    # simplest real pairing case.
    ############################################################

    def test_block_with_one_tx(self):
        blob = bytes.fromhex(cn_vectors.BLOCK_38372_BLOB)
        self.assertEqual(len(parse_block(blob)["tx_hashes"]), 1)
        self.assertEqual(block_id(blob).hex(), cn_vectors.BLOCK_38372_ID)






    ############################################################
    # test_block_with_three_txs
    ############################################################
    #
    # A block carrying three mempool txs: four tree leaves,
    # exercising the power-of-two reduction of tree_hash.
    ############################################################

    def test_block_with_three_txs(self):
        blob = bytes.fromhex(cn_vectors.BLOCK_42965_BLOB)
        self.assertEqual(len(parse_block(blob)["tx_hashes"]), 3)
        self.assertEqual(block_id(blob).hex(), cn_vectors.BLOCK_42965_ID)








############################################################
# TestTreeHash
############################################################
#
# tree_hash() on its own, leaf count by leaf count, pinning
# where CryptoNote's tree differs from Bitcoin's merkle
# tree.
############################################################

class TestTreeHash(unittest.TestCase):






    ############################################################
    # test_single_leaf_is_itself
    ############################################################
    #
    # One leaf hashes to itself — no keccak round at all.
    ############################################################

    def test_single_leaf_is_itself(self):
        leaf = keccak_256(b"leaf")
        self.assertEqual(tree_hash([leaf]), leaf)






    ############################################################
    # test_two_leaves
    ############################################################
    #
    # Two leaves: exactly one pair hash.
    ############################################################

    def test_two_leaves(self):
        a, b = keccak_256(b"a"), keccak_256(b"b")
        self.assertEqual(tree_hash([a, b]), keccak_256(a + b))






    ############################################################
    # test_three_leaves_pairs_the_tail
    ############################################################
    #
    # Three leaves: CryptoNote pair-hashes the TAIL — the last
    # two leaves — first and leaves the head alone, not
    # Bitcoin's duplicate-the-last-leaf padding.
    ############################################################

    def test_three_leaves_pairs_the_tail(self):
        a, b, c = (keccak_256(x) for x in (b"a", b"b", b"c"))
        self.assertEqual(tree_hash([a, b, c]),
                         keccak_256(a + keccak_256(b + c)))






    ############################################################
    # test_empty_rejected
    ############################################################
    #
    # No leaves is a caller bug and must raise.
    ############################################################

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            tree_hash([])








############################################################
# TestHashingBlob
############################################################
#
# hashing_blob(): the short blob miners actually hash,
# derived from a full block.
############################################################

class TestHashingBlob(unittest.TestCase):






    ############################################################
    # test_hashing_blob_layout
    ############################################################
    #
    # The classic 76-byte layout: the block's 43-byte header
    # copied verbatim, the 32-byte tree root, then the
    # transaction count as a one-byte varint.
    ############################################################

    def test_hashing_blob_layout(self):
        blob = bytes.fromhex(cn_vectors.BLOCK_46860_BLOB)
        hb = hashing_blob(blob)
        self.assertEqual(len(hb), 76)
        # header prefix is shared verbatim with the full blob
        self.assertEqual(hb[:43], blob[:43])
        # miner-tx-only block: count varint == 1
        self.assertEqual(hb[-1], 1)








############################################################
# TestInjection
############################################################
#
# with_nonce() and with_extranonce(): writing a miner's
# nonce or a client's extranonce into a blob without
# disturbing any other byte, and refusing an extranonce the
# reserved space cannot hold.
############################################################

class TestInjection(unittest.TestCase):






    ############################################################
    # test_with_nonce
    ############################################################
    #
    # Nonce injection: the 4 bytes at the nonce offset take
    # the new nonce, and every other byte of the blob stays
    # as it was.
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
    # test_with_extranonce_changes_work
    ############################################################
    #
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
    # test_extranonce_too_large_rejected
    ############################################################
    #
    # An extranonce longer than the reserved space would
    # overwrite real template bytes — must raise.
    ############################################################

    def test_extranonce_too_large_rejected(self):
        blob = bytes.fromhex(cn_vectors.TEMPLATE_BLOB)
        with self.assertRaises(ValueError):
            with_extranonce(blob, b"X" * 17, cn_vectors.TEMPLATE_RESERVED_OFFSET, 16)
