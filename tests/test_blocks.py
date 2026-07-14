# -----------------------------------------------------------
#  [*] Tests — Block Assembly
#
#  Covers anypool/blocks.py: the serialized block layout
#  around a solved header, and the varint transaction count
#  (which the pre-refactor code got wrong for blocks with
#  more than 252 transactions).
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
# -----------------------------------------------------------

import unittest

from anypool.mining.blocks import assemble_block
from anypool.mining.jobs import build_job
from tests import vectors




class TestAssembleBlock(unittest.TestCase):


    # -----------------------------------------------------------
    # Block 1777 layout: header + tx count 01 + full (witness)
    # coinbase with the miner's extranonces + MWEB marker.
    # -----------------------------------------------------------
    def test_block_1777_layout(self):
        job = build_job(vectors.TEMPLATE, "00000001")

        block_hex = assemble_block(job, vectors.EXTRANONCE1, vectors.EXTRANONCE2, vectors.HEADER_HEX)

        expected_coinbase = (job["coinb1_full"] + vectors.EXTRANONCE1 +
                             vectors.EXTRANONCE2 + job["coinb2_full"])
        expected_block = vectors.HEADER_HEX + "01" + expected_coinbase + "01"

        self.assertEqual(block_hex, expected_block)






    # -----------------------------------------------------------
    # Template transactions must be appended verbatim, and the
    # tx count must include the coinbase.
    # -----------------------------------------------------------
    def test_transactions_appended(self):
        template = dict(vectors.TEMPLATE)
        template["transactions"] = [
            {"txid": "aa" * 32, "data": "deadbeef"},
            {"txid": "bb" * 32, "data": "cafebabe"},
        ]
        job = build_job(template, "00000002")

        block_hex = assemble_block(job, vectors.EXTRANONCE1, vectors.EXTRANONCE2, vectors.HEADER_HEX)

        self.assertIn("deadbeefcafebabe", block_hex)
        tx_count_pos = len(vectors.HEADER_HEX)
        self.assertEqual(block_hex[tx_count_pos:tx_count_pos+2], "03")  # coinbase + 2 txs






    # -----------------------------------------------------------
    # Above 252 transactions the count must switch to the "fd"
    # varint form — the bug the old single-byte code had.
    # -----------------------------------------------------------
    def test_varint_tx_count_above_252(self):
        template = dict(vectors.TEMPLATE)
        template["transactions"] = [{"txid": "cc" * 32, "data": "00"} for _ in range(300)]
        job = build_job(template, "00000003")

        block_hex = assemble_block(job, vectors.EXTRANONCE1, vectors.EXTRANONCE2, vectors.HEADER_HEX)

        tx_count_pos = len(vectors.HEADER_HEX)
        # 301 transactions -> varint fd2d01 (0x012d little-endian)
        self.assertEqual(block_hex[tx_count_pos:tx_count_pos+6], "fd2d01")




if __name__ == "__main__":
    unittest.main()
