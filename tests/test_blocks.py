############################################################
#  [*] Tests — Block Assembly
#
#  Covers families/bitcoin/blocks.py: the serialized block
#  layout around a solved header, the varint transaction
#  count — the field a naive single-byte count corrupts for
#  blocks with more than 252 transactions — and the MWEB
#  section, written exactly when the template carries MWEB
#  data. The MWEB cases replay real blocks a KnfCoin regtest
#  node accepted across its MWEB activation (see
#  tests/mweb_vectors.py): rebuilt from the same template and
#  share, each must come out byte for byte as accepted.
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
############################################################


import unittest

from anypool.families.bitcoin.blocks import assemble_block
from anypool.families.bitcoin.jobs import build_job
from anypool.families.bitcoin.shares import build_header
from tests import mweb_vectors, vectors








############################################################
# rebuild
############################################################
#
# One accepted block from tests/mweb_vectors.py, rebuilt the
# way the pool built it: the job from its template, the
# header from the share that solved it, the block around
# them. Hands back the job, the header, its PoW hash and the
# assembled block hex.
#
# Used by:
#   - tests/test_blocks.py — TestMwebBlocks (below)
############################################################

def rebuild(vector):
    job = build_job(vector["template"], "00000001")
    pow_hash, header_hex, _ = build_header(job, vector["extranonce1"], vector["extranonce2"],
                                           vector["ntime"], vector["nonce"])
    block_hex = assemble_block(job, vector["extranonce1"], vector["extranonce2"], header_hex)
    return job, header_hex, pow_hash, block_hex








class TestAssembleBlock(unittest.TestCase):






    ############################################################
    # Block 1777 layout: header + tx count 01 + full (witness)
    # coinbase with the miner's extranonces, and nothing after
    # it. The network accepted 1777 with a lone MWEB marker
    # byte appended, which its node never read; a block before
    # MWEB ends after its last transaction (see TestMwebBlocks
    # for a node accepting exactly that).
    ############################################################

    def test_block_1777_layout(self):
        job = build_job(vectors.TEMPLATE, "00000001")

        block_hex = assemble_block(job, vectors.EXTRANONCE1, vectors.EXTRANONCE2,
                                   vectors.HEADER_HEX)

        expected_coinbase = (job["coinb1_full"] + vectors.EXTRANONCE1 +
                             vectors.EXTRANONCE2 + job["coinb2_full"])
        expected_block = vectors.HEADER_HEX + "01" + expected_coinbase

        self.assertEqual(block_hex, expected_block)






    ############################################################
    # Template transactions must be appended verbatim, and the
    # tx count must include the coinbase.
    ############################################################

    def test_transactions_appended(self):
        template = dict(vectors.TEMPLATE)
        template["transactions"] = [
            {"txid": "aa" * 32, "data": "deadbeef"},
            {"txid": "bb" * 32, "data": "cafebabe"},
        ]
        job = build_job(template, "00000002")

        block_hex = assemble_block(job, vectors.EXTRANONCE1, vectors.EXTRANONCE2,
                                   vectors.HEADER_HEX)

        self.assertTrue(block_hex.endswith("deadbeefcafebabe"))
        tx_count_pos = len(vectors.HEADER_HEX)
        self.assertEqual(block_hex[tx_count_pos:tx_count_pos+2], "03")  # coinbase + 2 txs






    ############################################################
    # Above 252 transactions the count must switch to the "fd"
    # varint form — a single count byte would serialize a
    # corrupt block here.
    ############################################################

    def test_varint_tx_count_above_252(self):
        template = dict(vectors.TEMPLATE)
        template["transactions"] = [{"txid": "cc" * 32, "data": "00"} for _ in range(300)]
        job = build_job(template, "00000003")

        block_hex = assemble_block(job, vectors.EXTRANONCE1, vectors.EXTRANONCE2,
                                   vectors.HEADER_HEX)

        tx_count_pos = len(vectors.HEADER_HEX)
        # 301 transactions -> varint fd2d01 (0x012d little-endian)
        self.assertEqual(block_hex[tx_count_pos:tx_count_pos+6], "fd2d01")








class TestMwebBlocks(unittest.TestCase):






    ############################################################
    # The block before MWEB: rebuilt from its template and
    # share it is the block the node accepted — ending right
    # after the coinbase, with no MWEB marker.
    ############################################################

    def test_block_before_mweb_is_byte_exact(self):
        vector = mweb_vectors.PRE_MWEB_BLOCK
        job, header_hex, pow_hash, block_hex = rebuild(vector)

        self.assertEqual(header_hex, vector["header_hex"])
        self.assertEqual(pow_hash, vector["pow_hash"])
        self.assertEqual(block_hex, vector["block_hex"])
        self.assertTrue(block_hex.endswith(job["coinb2_full"]))






    ############################################################
    # The first MWEB block: coinbase, the peg-in, the HogEx,
    # then the marker and the template's MWEB data — the exact
    # bytes the node accepted.
    ############################################################

    def test_first_mweb_block_is_byte_exact(self):
        vector = mweb_vectors.FIRST_MWEB_BLOCK
        job, header_hex, pow_hash, block_hex = rebuild(vector)

        self.assertEqual(header_hex, vector["header_hex"])
        self.assertEqual(pow_hash, vector["pow_hash"])
        self.assertEqual(block_hex, vector["block_hex"])

        transactions = vector["template"]["transactions"]
        self.assertEqual(len(transactions), 2)                    # peg-in + HogEx
        self.assertEqual(transactions[0]["txid"], mweb_vectors.PEGIN_TXID)
        self.assertTrue(block_hex.endswith(transactions[-1]["data"] + "01" + vector["template"]["mweb"]))






    ############################################################
    # The next MWEB block: its HogEx spends the previous one,
    # no peg-in needed — again exactly the accepted bytes.
    ############################################################

    def test_next_mweb_block_is_byte_exact(self):
        vector = mweb_vectors.NEXT_MWEB_BLOCK
        job, header_hex, pow_hash, block_hex = rebuild(vector)

        self.assertEqual(header_hex, vector["header_hex"])
        self.assertEqual(block_hex, vector["block_hex"])
        self.assertEqual(len(vector["template"]["transactions"]), 1)        # the HogEx alone
        self.assertTrue(block_hex.endswith("01" + vector["template"]["mweb"]))






    ############################################################
    # MWEB data with no template transaction to be its HogEx
    # describes a block no node would accept: refused here
    # rather than serialized.
    ############################################################

    def test_mweb_data_without_a_hogex_is_refused(self):
        template = dict(mweb_vectors.NEXT_MWEB_BLOCK["template"], transactions=[])
        job = build_job(template, "00000004")

        with self.assertRaises(ValueError):
            assemble_block(job, vectors.EXTRANONCE1, vectors.EXTRANONCE2, vectors.HEADER_HEX)






    ############################################################
    # An empty "mweb" field is no MWEB data: the block ends
    # after its transactions, without a marker.
    ############################################################

    def test_empty_mweb_data_writes_no_section(self):
        template = dict(mweb_vectors.NEXT_MWEB_BLOCK["template"], mweb="")
        job = build_job(template, "00000005")

        block_hex = assemble_block(job, vectors.EXTRANONCE1, vectors.EXTRANONCE2, vectors.HEADER_HEX)

        self.assertTrue(block_hex.endswith(template["transactions"][-1]["data"]))








if __name__ == "__main__":
    unittest.main()
