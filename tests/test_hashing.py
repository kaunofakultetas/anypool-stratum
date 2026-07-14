# -----------------------------------------------------------
#  [*] Tests — Hashing & Hex Primitives
#
#  Covers anypool/crypto/hashing.py. The Scrypt test hashes
#  the real header of KNF block 1777 and expects the exact
#  PoW hash the network accepted — if the endianness handling
#  anywhere in hashing.py drifts, this fails.
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
# -----------------------------------------------------------

import unittest

from anypool.crypto.hashing import reverse_hex, reverse_hex_4b_chunks, scrypt_pow_hash, sha256d
from tests import vectors




class TestSha256d(unittest.TestCase):


    # -----------------------------------------------------------
    # Double SHA256 of an empty string is a well-known constant.
    # -----------------------------------------------------------
    def test_known_vector_empty_input(self):
        self.assertEqual(
            sha256d(b"").hex(),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        )






    # -----------------------------------------------------------
    # sha256d of block 1777's header equals its block hash
    # (byte-reversed for display, as printed by the pool).
    # -----------------------------------------------------------
    def test_block_1777_header_hash(self):
        header_bytes = bytes.fromhex(vectors.HEADER_HEX)
        self.assertEqual(
            sha256d(header_bytes)[::-1].hex(),
            vectors.BLOCK_SHA256
        )










class TestScryptPowHash(unittest.TestCase):


    # -----------------------------------------------------------
    # The crown jewel: the exact 80-byte header the ASIC solved
    # must produce the exact PoW hash the network accepted.
    # -----------------------------------------------------------
    def test_block_1777_pow_hash(self):
        header_bytes = bytes.fromhex(vectors.HEADER_HEX)
        self.assertEqual(scrypt_pow_hash(header_bytes), vectors.SCRYPT_HASH)






    # -----------------------------------------------------------
    # Anything that is not exactly 80 bytes must be refused.
    # -----------------------------------------------------------
    def test_rejects_wrong_length(self):
        with self.assertRaises(ValueError):
            scrypt_pow_hash(b"\x00" * 79)
        with self.assertRaises(ValueError):
            scrypt_pow_hash(b"\x00" * 81)










class TestReverseHex(unittest.TestCase):


    # -----------------------------------------------------------
    # The example straight from the function's docstring.
    # -----------------------------------------------------------
    def test_byte_reversal(self):
        self.assertEqual(reverse_hex("0123456789abcdef"), "efcdab8967452301")






    # -----------------------------------------------------------
    # Reversing twice must be the identity.
    # -----------------------------------------------------------
    def test_round_trip(self):
        original = vectors.TEMPLATE["previousblockhash"]
        self.assertEqual(reverse_hex(reverse_hex(original)), original)






    # -----------------------------------------------------------
    # Version field of block 1777: job value -> header value.
    # -----------------------------------------------------------
    def test_block_1777_version(self):
        self.assertEqual(reverse_hex(vectors.JOB_VERSION), "00000020")










class TestReverseHex4bChunks(unittest.TestCase):


    # -----------------------------------------------------------
    # Word-swapping the wire-format prevhash of block 1777 must
    # give the prevhash bytes inside the accepted header.
    # -----------------------------------------------------------
    def test_block_1777_prevhash_to_header_form(self):
        header_prevhash = vectors.HEADER_HEX[8:8+64]
        self.assertEqual(
            reverse_hex_4b_chunks(vectors.JOB_PREVHASH_WIRE),
            header_prevhash
        )






    # -----------------------------------------------------------
    # Applying the word swap twice must be the identity.
    # -----------------------------------------------------------
    def test_round_trip(self):
        original = vectors.JOB_PREVHASH_WIRE
        self.assertEqual(reverse_hex_4b_chunks(reverse_hex_4b_chunks(original)), original)




if __name__ == "__main__":
    unittest.main()
