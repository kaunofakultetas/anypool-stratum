############################################################
#  [*] Tests — CryptoNight PoW
#
#  Proves the pool's share-validation math end to end on the
#  REAL final block of the Bitlitas chain (height 46860): its
#  hashing blob, hashed with cn/0, must produce a PoW hash
#  that satisfies the difficulty the network mined it at.
#  If the blob derivation, the variant or the difficulty
#  comparison were wrong, this could not pass.
#
#  Needs the py-cryptonight C extension, so it is skipped
#  outside the container (where the suite is meant to run).
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
############################################################


import unittest

from anypool.crypto.cryptonight import hash_meets_difficulty
from anypool.families.cryptonote.blob import hashing_blob
from tests import cn_vectors


# Only the stratum image carries the C extension; probed here
# so the class below is skipped elsewhere instead of erroring
try:
    import pycryptonight  # noqa: F401
    HAVE_CRYPTONIGHT = True
except ImportError:
    HAVE_CRYPTONIGHT = False








############################################################
# TestCryptoNightPoW
############################################################
#
# The real CryptoNight hash through the py-cryptonight
# extension: a published vector first, then the real final
# block judged against its own network difficulty and
# against an absurd one. Skipped, not failed, where the
# extension is missing.
############################################################

@unittest.skipUnless(HAVE_CRYPTONIGHT, "py-cryptonight not installed (run inside the container)")
class TestCryptoNightPoW(unittest.TestCase):






    ############################################################
    # test_known_vector
    ############################################################
    #
    # Library sanity: a published cn/0 vector, so a broken or
    # variant-confused extension is caught before any chain
    # data is blamed.
    ############################################################

    def test_known_vector(self):
        from anypool.crypto.cryptonight import cn_slow_hash
        self.assertEqual(
            cn_slow_hash(b"This is a test", 0).hex(),
            "a084f01d1437a09c6985401b60d43554ae105802c5f5d8a9b3253649c0be6605")






    ############################################################
    # test_real_block_meets_its_network_difficulty
    ############################################################
    #
    # The real block: hashing its blob must beat the network
    # difficulty of the block itself — exactly the check the
    # pool performs to decide "this share is a BLOCK".
    ############################################################

    def test_real_block_meets_its_network_difficulty(self):
        from anypool.crypto.cryptonight import cn_slow_hash

        blob = bytes.fromhex(cn_vectors.BLOCK_46860_BLOB)
        pow_hash = cn_slow_hash(hashing_blob(blob), 0)

        self.assertTrue(
            hash_meets_difficulty(pow_hash, cn_vectors.BLOCK_46860_DIFFICULTY),
            "final chain block failed its own difficulty — blob or PoW math is wrong")






    ############################################################
    # test_real_block_fails_absurd_difficulty
    ############################################################
    #
    # The same real block must NOT meet an absurdly higher
    # difficulty — proof the check actually discriminates
    # instead of always passing.
    ############################################################

    def test_real_block_fails_absurd_difficulty(self):
        from anypool.crypto.cryptonight import cn_slow_hash

        blob = bytes.fromhex(cn_vectors.BLOCK_46860_BLOB)
        pow_hash = cn_slow_hash(hashing_blob(blob), 0)

        self.assertFalse(hash_meets_difficulty(pow_hash, 10 ** 18))
