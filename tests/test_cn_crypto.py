############################################################
#  [*] Tests — CryptoNote Crypto Primitives
#
#  Covers crypto/keccak.py (original-padding Keccak-256 —
#  the one thing hashlib cannot provide), crypto/cn_base58.py
#  (block-wise base58 + address checksums) and the difficulty
#  math of crypto/cryptonight.py. The PoW hash itself is
#  covered by test_cn_pow.py (needs the C extension, i.e. the
#  container).
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
############################################################


import unittest

from anypool.crypto import cn_base58
from anypool.crypto.cryptonight import compact_target, hash_meets_difficulty
from anypool.crypto.keccak import keccak_256
from tests import cn_vectors








############################################################
# TestKeccak
############################################################
#
# keccak_256() against published vectors of ORIGINAL
# Keccak-256 — the padding CryptoNote hashes with, which
# hashlib's sha3_256 does not use — plus an input long
# enough to need more than one sponge block.
############################################################

class TestKeccak(unittest.TestCase):






    ############################################################
    # test_empty
    ############################################################
    #
    # The published empty-input vector of ORIGINAL Keccak-256.
    # sha3_256 gives a different digest (NIST changed the
    # padding), so this also proves we are not accidentally on
    # hashlib.
    ############################################################

    def test_empty(self):
        self.assertEqual(keccak_256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")






    ############################################################
    # test_abc
    ############################################################
    #
    # The published "abc" vector of original Keccak-256.
    ############################################################

    def test_abc(self):
        self.assertEqual(keccak_256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")






    ############################################################
    # test_multiblock_input
    ############################################################
    #
    # 200 bytes crosses the 136-byte sponge rate, so this
    # exercises the multi-block absorb path — checked only
    # for the digest length and for one byte less changing
    # the digest; no published vector pins its value.
    ############################################################

    def test_multiblock_input(self):
        self.assertEqual(len(keccak_256(b"\x5a" * 200)), 32)
        self.assertNotEqual(keccak_256(b"\x5a" * 200), keccak_256(b"\x5a" * 199))








############################################################
# TestCnBase58
############################################################
#
# cn_base58: CryptoNote's block-wise base58 with its keccak
# checksum — the layer REWARD_ADDR is validated with — and
# the varints block parsing borrows from it.
############################################################

class TestCnBase58(unittest.TestCase):






    ############################################################
    # test_encode_decode_roundtrip
    ############################################################
    #
    # encode_addr and decode_addr are exact inverses over the
    # address layer used to validate REWARD_ADDR.
    ############################################################

    def test_encode_decode_roundtrip(self):
        payload = bytes(range(64))
        addr = cn_base58.encode_addr(18, payload)
        prefix, decoded = cn_base58.decode_addr(addr)
        self.assertEqual(prefix, 18)
        self.assertEqual(decoded, payload)






    ############################################################
    # test_real_address_shape
    ############################################################
    #
    # The repo's test address decodes to the canonical shape:
    # prefix 18, a 64-byte payload of spend and view keys, 95
    # characters.
    ############################################################

    def test_real_address_shape(self):
        prefix, payload = cn_base58.decode_addr(cn_vectors.TEST_ADDRESS)
        self.assertEqual(prefix, 18)
        self.assertEqual(len(payload), 64)
        self.assertEqual(len(cn_vectors.TEST_ADDRESS), 95)






    ############################################################
    # test_corrupted_checksum_rejected
    ############################################################
    #
    # Flipping one character breaks the keccak checksum and
    # must be rejected — a typoed REWARD_ADDR dies at startup.
    ############################################################

    def test_corrupted_checksum_rejected(self):
        addr = cn_vectors.TEST_ADDRESS
        tampered = addr[:-1] + ("2" if addr[-1] != "2" else "3")
        with self.assertRaises(ValueError):
            cn_base58.decode_addr(tampered)






    ############################################################
    # test_invalid_character_rejected
    ############################################################
    #
    # "0", "O", "I" and "l" are excluded from the base58
    # alphabet and must raise.
    ############################################################

    def test_invalid_character_rejected(self):
        with self.assertRaises(ValueError):
            cn_base58.decode("0OIl")






    ############################################################
    # test_varint_roundtrip
    ############################################################
    #
    # write_varint and read_varint are inverses across the
    # 1-byte, 2-byte and multi-byte encodings.
    ############################################################

    def test_varint_roundtrip(self):
        for value in (0, 1, 18, 127, 128, 300, 2 ** 40):
            encoded = cn_base58.write_varint(value)
            decoded, offset = cn_base58.read_varint(encoded, 0)
            self.assertEqual(decoded, value)
            self.assertEqual(offset, len(encoded))








############################################################
# TestDifficultyMath
############################################################
#
# The CryptoNote difficulty math of cryptonight.py: the
# 4-byte compact target a job carries, and the check of a
# hash against a difficulty that every share and block
# verdict rests on.
############################################################

class TestDifficultyMath(unittest.TestCase):






    ############################################################
    # test_compact_target_known_value
    ############################################################
    #
    # A known difficulty encodes to the target value
    # CryptoNote pools hand out for it — the conventional
    # 4-byte little-endian top of the 256-bit target that
    # every CryptoNote pool/miner pair agrees on.
    ############################################################

    def test_compact_target_known_value(self):
        self.assertEqual(compact_target(5000), "711b0d00")






    ############################################################
    # test_compact_target_diff_1
    ############################################################
    #
    # Difficulty 1 encodes as all-ones — the loosest target
    # the 4 bytes can express.
    ############################################################

    def test_compact_target_diff_1(self):
        self.assertEqual(compact_target(1), "ffffffff")






    ############################################################
    # test_compact_target_rejects_unencodable_difficulty
    ############################################################
    #
    # A difficulty that no longer fits 32 bits would encode
    # as a zero target that no share could ever satisfy — it
    # must fail loudly instead.
    ############################################################

    def test_compact_target_rejects_unencodable_difficulty(self):
        with self.assertRaises(ValueError):
            compact_target(0x100000000)






    ############################################################
    # test_zero_hash_meets_anything
    ############################################################
    #
    # The zero hash satisfies any difficulty — the trivially
    # true end of the check, as zero times any difficulty
    # stays under 2^256.
    ############################################################

    def test_zero_hash_meets_anything(self):
        self.assertTrue(hash_meets_difficulty(b"\x00" * 32, 10 ** 12))






    ############################################################
    # test_max_hash_only_meets_diff_1
    ############################################################
    #
    # The all-ones hash is the worst possible: passes only
    # difficulty 1.
    ############################################################

    def test_max_hash_only_meets_diff_1(self):
        max_hash = b"\xff" * 32
        self.assertTrue(hash_meets_difficulty(max_hash, 1))
        self.assertFalse(hash_meets_difficulty(max_hash, 2))






    ############################################################
    # test_boundary
    ############################################################
    #
    # Right at the boundary — hash 2^255 (read little-endian)
    # passes difficulty 1 and fails difficulty 2, pinning the
    # strict comparison: a product of exactly 2^256 fails.
    ############################################################

    def test_boundary(self):
        hash_bytes = (1 << 255).to_bytes(32, "little")
        self.assertTrue(hash_meets_difficulty(hash_bytes, 1))
        self.assertFalse(hash_meets_difficulty(hash_bytes, 2))
