# -----------------------------------------------------------
#  [*] Tests — Coinbase Builder
#
#  Covers anypool/coinbase.py. The central assertion:
#  build_coinbase_parts() fed with the block 1777 template
#  must reproduce, byte for byte, the coinb1/coinb2 halves
#  the pool sent to the ASIC that mined the accepted block.
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
# -----------------------------------------------------------

import unittest

from anypool.mining.coinbase import bip34_height_push, build_coinbase_parts, to_varint
from tests import vectors




class TestToVarint(unittest.TestCase):


    # -----------------------------------------------------------
    # All four encoding ranges of the Bitcoin varint.
    # -----------------------------------------------------------
    def test_encoding_ranges(self):
        self.assertEqual(to_varint(0), "00")
        self.assertEqual(to_varint(252), "fc")
        self.assertEqual(to_varint(253), "fdfd00")
        self.assertEqual(to_varint(65535), "fdffff")
        self.assertEqual(to_varint(65536), "fe00000100")
        self.assertEqual(to_varint(0x100000000), "ff0000000001000000")










class TestBip34HeightPush(unittest.TestCase):


    # -----------------------------------------------------------
    # Block 1777's height push, as seen at the end of the real
    # coinb1: length 0x02, then 0x6f1 little-endian = "f106".
    # -----------------------------------------------------------
    def test_block_1777_height(self):
        self.assertEqual(bip34_height_push(1777).hex(), "02f106")






    # -----------------------------------------------------------
    # CScriptNum corner cases: zero, and the sign-bit padding
    # byte when the top byte has its high bit set.
    # -----------------------------------------------------------
    def test_corner_cases(self):
        self.assertEqual(bip34_height_push(0), b"\x00")
        self.assertEqual(bip34_height_push(1).hex(), "0101")
        # 128 has the high bit set -> needs a 0x00 padding byte
        self.assertEqual(bip34_height_push(128).hex(), "028000")
        self.assertEqual(bip34_height_push(255).hex(), "02ff00")
        self.assertEqual(bip34_height_push(256).hex(), "020001")










class TestBuildCoinbaseParts(unittest.TestCase):


    # -----------------------------------------------------------
    # Byte-for-byte reproduction of the coinbase halves that
    # built KNF block 1777 (both txid and witness variants).
    # -----------------------------------------------------------
    def test_block_1777_parts(self):
        parts = build_coinbase_parts(vectors.TEMPLATE)

        self.assertEqual(parts["coinb1_txid"], vectors.COINB1)
        self.assertEqual(parts["coinb2_txid"], vectors.COINB2)
        self.assertEqual(parts["coinb1_full"], vectors.COINB1_FULL)

        # The witness variant of coinb2 is coinb2 with the witness
        # stack (0x01 items, one 32-byte reserved value) inserted
        # right before the 4-byte locktime
        witness_stack = "01200000000000000000000000000000000000000000000000000000000000000000"
        expected_coinb2_full = vectors.COINB2[:-8] + witness_stack + vectors.COINB2[-8:]
        self.assertEqual(parts["coinb2_full"], expected_coinb2_full)






    # -----------------------------------------------------------
    # Without a witness commitment in the template, the txid and
    # full serializations must be identical (non-segwit block).
    # -----------------------------------------------------------
    def test_no_witness_template(self):
        template = dict(vectors.TEMPLATE)
        del template["default_witness_commitment"]

        parts = build_coinbase_parts(template)

        self.assertEqual(parts["coinb1_txid"], parts["coinb1_full"])
        self.assertEqual(parts["coinb2_txid"], parts["coinb2_full"])




if __name__ == "__main__":
    unittest.main()
