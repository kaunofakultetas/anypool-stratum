# -----------------------------------------------------------
#  [*] Tests — Coin Registry & Definitions
#
#  Covers anypool/coins/: every registered coin must be
#  internally consistent, the getblocktemplate request must
#  adapt to old daemons (no rules param), and the address
#  schemes must produce the right payout script types.
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
# -----------------------------------------------------------

import unittest

from anypool import coins
from tests import vectors
from tests.test_base58 import DOGE_ADDR, DOGE_HASH160




class TestRegistry(unittest.TestCase):


    # -----------------------------------------------------------
    # Every registered coin must be complete and consistent.
    # -----------------------------------------------------------
    def test_definitions_are_consistent(self):
        for symbol, coin in coins.REGISTRY.items():
            with self.subTest(coin=symbol):
                self.assertEqual(coin.name, symbol)
                self.assertTrue(callable(coin.pow_hash))
                self.assertGreater(coin.difficulty_1_target, 0)
                self.assertGreater(len(coin.networks()), 0)






    # -----------------------------------------------------------
    # active() must follow the COIN environment variable
    # (pinned to KNF by tests/__init__.py).
    # -----------------------------------------------------------
    def test_active_coin(self):
        self.assertIs(coins.active(), coins.REGISTRY["KNF"])










class TestGbtRequest(unittest.TestCase):


    # -----------------------------------------------------------
    # Modern Litecoin-family daemons get the rules list, plus
    # the longpollid when re-arming a longpoll.
    # -----------------------------------------------------------
    def test_modern_coin_request(self):
        knf = coins.get_coin("KNF")

        self.assertEqual(knf.gbt_request(), [{"rules": ["segwit", "mweb"]}])
        self.assertEqual(
            knf.gbt_request(longpollid="abc123"),
            [{"rules": ["segwit", "mweb"], "longpollid": "abc123"}]
        )






    # -----------------------------------------------------------
    # Old daemons (Dogecoin) get NO request object at all for a
    # plain poll — some predate the rules mechanism entirely.
    # -----------------------------------------------------------
    def test_old_coin_request(self):
        doge = coins.get_coin("DOGE")

        self.assertEqual(doge.gbt_request(), [])
        self.assertEqual(doge.gbt_request(longpollid="abc123"), [{"longpollid": "abc123"}])










class TestAddressSchemes(unittest.TestCase):


    # -----------------------------------------------------------
    # KNF (bech32 scheme) must produce the P2WPKH script from
    # the accepted block 1777.
    # -----------------------------------------------------------
    def test_bech32_scheme(self):
        knf = coins.get_coin("KNF")
        script = knf.address_scheme.payout_script(vectors.REWARD_ADDR, "mainnet")
        self.assertEqual(script, vectors.PAYOUT_SCRIPT)






    # -----------------------------------------------------------
    # DOGE (base58 scheme) must produce a legacy P2PKH script.
    # -----------------------------------------------------------
    def test_base58_scheme(self):
        doge = coins.get_coin("DOGE")
        script = doge.address_scheme.payout_script(DOGE_ADDR, "mainnet")
        self.assertEqual(script, "76a914" + DOGE_HASH160 + "88ac")






    # -----------------------------------------------------------
    # Feeding one coin's address to another coin's scheme must
    # fail — the config validator relies on this.
    # -----------------------------------------------------------
    def test_cross_coin_addresses_rejected(self):
        with self.assertRaises(ValueError):
            coins.get_coin("KNF").address_scheme.payout_script(DOGE_ADDR, "mainnet")
        with self.assertRaises(ValueError):
            coins.get_coin("DOGE").address_scheme.payout_script(vectors.REWARD_ADDR, "mainnet")




if __name__ == "__main__":
    unittest.main()
