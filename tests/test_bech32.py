# -----------------------------------------------------------
#  [*] Tests — Bech32 Address Decoding
#
#  Covers anypool/crypto/bech32.py. The anchor vector is the
#  pool's real KNF reward address: it must decode to the
#  exact P2WPKH payout script found inside the coinbase of
#  the network-accepted block 1777.
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
# -----------------------------------------------------------

import unittest

from anypool.crypto.bech32 import bech32_decode, convertbits, p2wpkh_script_for_address
from tests import vectors




class TestP2wpkhScript(unittest.TestCase):


    # -----------------------------------------------------------
    # The pool's real reward address must decode to the exact
    # payout script embedded in the accepted block's coinbase.
    # -----------------------------------------------------------
    def test_reward_address_to_script(self):
        script = p2wpkh_script_for_address(vectors.REWARD_ADDR, "knf")
        self.assertEqual(script, vectors.PAYOUT_SCRIPT)






    # -----------------------------------------------------------
    # A wrong network prefix must be refused, even for an
    # otherwise perfectly valid address.
    # -----------------------------------------------------------
    def test_wrong_prefix_rejected(self):
        with self.assertRaises(ValueError):
            p2wpkh_script_for_address(vectors.REWARD_ADDR, "tltc")






    # -----------------------------------------------------------
    # Uppercase form of the same address is equally valid per
    # BIP-173 and must decode to the same script.
    # -----------------------------------------------------------
    def test_uppercase_address(self):
        script = p2wpkh_script_for_address(vectors.REWARD_ADDR.upper(), "knf")
        self.assertEqual(script, vectors.PAYOUT_SCRIPT)










class TestBech32Decode(unittest.TestCase):


    # -----------------------------------------------------------
    # Corrupted checksums and malformed strings decode to None.
    # -----------------------------------------------------------
    def test_malformed_addresses(self):
        corrupted = vectors.REWARD_ADDR[:-1] + ("a" if vectors.REWARD_ADDR[-1] != "a" else "b")
        self.assertEqual(bech32_decode(corrupted), (None, None))
        self.assertEqual(bech32_decode("no-separator-here"), (None, None))
        self.assertEqual(bech32_decode("Mixed1CASE"), (None, None))
        self.assertEqual(bech32_decode("knf1"), (None, None))






    # -----------------------------------------------------------
    # The decoded human-readable part must match the coin prefix.
    # -----------------------------------------------------------
    def test_hrp_extraction(self):
        hrp, data = bech32_decode(vectors.REWARD_ADDR)
        self.assertEqual(hrp, "knf")
        self.assertIsNotNone(data)
        self.assertEqual(data[0], 0)  # witness version 0










class TestConvertbits(unittest.TestCase):


    # -----------------------------------------------------------
    # 5-bit -> 8-bit regrouping must be reversible and produce
    # exactly the 20-byte witness program for our address.
    # -----------------------------------------------------------
    def test_witness_program_length(self):
        _, data = bech32_decode(vectors.REWARD_ADDR)
        prog = bytes(convertbits(data[1:], 5, 8, False))
        self.assertEqual(len(prog), 20)
        self.assertEqual("0014" + prog.hex(), vectors.PAYOUT_SCRIPT)






    # -----------------------------------------------------------
    # Out-of-range values must be refused.
    # -----------------------------------------------------------
    def test_rejects_out_of_range(self):
        self.assertIsNone(convertbits([32], 5, 8, False))   # 32 does not fit in 5 bits
        self.assertIsNone(convertbits([-1], 5, 8, False))




if __name__ == "__main__":
    unittest.main()
