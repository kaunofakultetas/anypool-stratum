############################################################
#  [*] Pinned Defects — Address Codecs and Hash Helpers
#
#  Known bugs of anypool/crypto/, each pinned as a regression
#  test that states the WANTED behaviour and fails today,
#  marked @unittest.expectedFailure — once a fix lands the
#  unexpected success fails the run, the cue to drop the
#  decorator and move the test into its home file:
#
#    - two malformed bech32 addresses that pass the checksum
#      escape the decoder as IndexError and TypeError, so
#      startup validation dies with a traceback instead of
#      its readable REWARD_ADDR error
#    - a crafted CryptoNote address does the same with an
#      IndexError
#    - reverse_hex_4b_chunks() silently drops everything past
#      the first 32 bytes of its input
#
#  The malformed addresses are crafted here with the codecs'
#  own checksum functions, so each passes the checksum and
#  fails exactly where the defect sits.
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
############################################################


import unittest
from unittest import mock

from anypool import config
from anypool.crypto import cn_base58
from anypool.crypto.bech32 import bech32_hrp_expand, bech32_polymod
from anypool.crypto.hashing import reverse_hex_4b_chunks
from anypool.crypto.keccak import keccak_256


# The bech32 alphabet: a 5-bit value's character
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"








############################################################
# bech32_address
############################################################
#
# A bech32 string with a valid checksum around any 5-bit data
# part — BIP173's encoder, built on the decoder's own
# checksum functions — so a test can hand the decoder shapes
# no wallet would ever produce.
#
# Used by:
#   - TestBech32RewardAddress (below)
############################################################

def bech32_address(hrp, data):
    polymod = bech32_polymod(bech32_hrp_expand(hrp) + data + [0] * 6) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32_CHARSET[value] for value in data + checksum)








############################################################
# validate_reward_address
############################################################
#
# config.validate() for one coin, network and REWARD_ADDR.
#
# Used by:
#   - the test cases below
############################################################

def validate_reward_address(coin, network, address):
    with mock.patch.multiple("anypool.config", COIN=coin, COIN_NETWORK=network, REWARD_ADDR=address):
        config.validate()








############################################################
# TestBech32RewardAddress
############################################################
#
# A REWARD_ADDR the bech32 decoder cannot read must stop the
# pool with the readable configuration error, whatever is
# wrong with it.
############################################################

class TestBech32RewardAddress(unittest.TestCase):






    ############################################################
    # test_an_address_of_only_a_checksum_is_refused_cleanly
    ############################################################
    #
    # A data part that is nothing but the checksum decodes to
    # no data at all; reading its witness version raises
    # IndexError, which validate() does not turn into its
    # REWARD_ADDR error.
    ############################################################

    @unittest.expectedFailure
    def test_an_address_of_only_a_checksum_is_refused_cleanly(self):
        with self.assertRaises(SystemExit):
            validate_reward_address("KNF", "mainnet", bech32_address("knf", []))






    ############################################################
    # test_a_badly_padded_program_is_refused_cleanly
    ############################################################
    #
    # A witness program of 33 five-bit groups leaves five
    # spare bits on conversion to bytes; convertbits() gives
    # up with None and bytes() of None raises TypeError, past
    # validate()'s REWARD_ADDR error.
    ############################################################

    @unittest.expectedFailure
    def test_a_badly_padded_program_is_refused_cleanly(self):
        with self.assertRaises(SystemExit):
            validate_reward_address("KNF", "mainnet", bech32_address("knf", [0] + [31] * 33))








############################################################
# TestCryptonoteRewardAddress
############################################################
#
# The same for the CryptoNote address codec.
############################################################

class TestCryptonoteRewardAddress(unittest.TestCase):






    ############################################################
    # test_a_body_of_only_varint_continuation_bytes_is_refused_cleanly
    ############################################################
    #
    # A checksum-valid address body made only of varint
    # continuation bytes runs the prefix read off its end, and
    # the IndexError escapes validate() as a traceback.
    ############################################################

    @unittest.expectedFailure
    def test_a_body_of_only_varint_continuation_bytes_is_refused_cleanly(self):
        body = bytes([0x80]) * 8
        address = cn_base58.encode(body + keccak_256(body)[:4])

        with self.assertRaises(SystemExit):
            validate_reward_address("LTL", "mainnet", address)








############################################################
# TestReverseHex4bChunks
############################################################
#
# The word swap must never lose input.
############################################################

class TestReverseHex4bChunks(unittest.TestCase):






    ############################################################
    # test_nothing_past_32_bytes_is_dropped_silently
    ############################################################
    #
    # Only the first 64 hex chars are converted; the rest of a
    # longer input vanishes without a word. Converting all of
    # it, or refusing it, would each be fine.
    ############################################################

    @unittest.expectedFailure
    def test_nothing_past_32_bytes_is_dropped_silently(self):
        hex_str = "00112233" * 9
        try:
            converted = reverse_hex_4b_chunks(hex_str)
        except ValueError:
            return
        self.assertEqual(len(converted), len(hex_str))








if __name__ == "__main__":
    unittest.main()
