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




    # -----------------------------------------------------------
    # Bitcoin Core REFUSES getblocktemplate without the segwit
    # rule — it must always be requested.
    # -----------------------------------------------------------
    def test_btc_request(self):
        btc = coins.get_coin("BTC")

        self.assertEqual(btc.gbt_request(), [{"rules": ["segwit"]}])
        self.assertEqual(
            btc.gbt_request(longpollid="abc123"),
            [{"rules": ["segwit"], "longpollid": "abc123"}]
        )










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




    # -----------------------------------------------------------
    # BTC bech32 scheme, checked against the canonical BIP173
    # reference vectors (same 20-byte program on both networks).
    # testnet3 and testnet4 share the "tb" prefix — the same
    # address must decode identically on both.
    # -----------------------------------------------------------
    def test_btc_bech32_scheme(self):
        btc = coins.get_coin("BTC")
        expected_script = "0014751e76e8199196d454941c45d1b3a323f1433bd6"

        script = btc.address_scheme.payout_script(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "mainnet")
        self.assertEqual(script, expected_script)

        for network in ("testnet3", "testnet4"):
            script = btc.address_scheme.payout_script(
                "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", network)
            self.assertEqual(script, expected_script)

        # Mainnet address on testnet (and vice versa) must fail
        with self.assertRaises(ValueError):
            btc.address_scheme.payout_script(
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "testnet3")
        with self.assertRaises(ValueError):
            btc.address_scheme.payout_script(
                "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "mainnet")










class TestVersionRolling(unittest.TestCase):


    # -----------------------------------------------------------
    # BTC carries the standard BIP320 mask; every other coin
    # must decline version rolling (mask 0) — Dogecoin's
    # version bits encode the AuxPoW chain id, and the scrypt
    # coins were validated without rolling.
    # -----------------------------------------------------------
    def test_masks(self):
        self.assertEqual(coins.get_coin("BTC").version_rolling_mask, 0x1FFFE000)
        for symbol in ("KNF", "LTC", "DOGE"):
            self.assertEqual(coins.get_coin(symbol).version_rolling_mask, 0,
                             f"{symbol} must not allow version rolling")




if __name__ == "__main__":
    unittest.main()
