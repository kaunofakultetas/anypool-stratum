############################################################
#  [*] Tests — Coin Registry & Definitions
#
#  Covers anypool/coins/: every registered coin must be
#  internally consistent, the getblocktemplate request must
#  adapt to old daemons (no rules param), the address schemes
#  must produce the right payout script types, only BTC may
#  let miners roll the version, and the MWEB peg-in settings
#  — carried by exactly the coins with MWEB — must read and
#  judge the environment the way an operator expects.
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
############################################################


import os
import unittest
from unittest import mock

from anypool import coins
from anypool.coins.base import MwebPegin, is_positive_decimal
from tests import vectors
from tests.test_base58 import DOGE_ADDR, DOGE_HASH160








############################################################
# TestRegistry
############################################################
#
# The coin registry as a whole: every definition complete
# for its family, every coin bootable through its family's
# runner, and the active coin following the configuration.
############################################################

class TestRegistry(unittest.TestCase):






    ############################################################
    # test_definitions_are_consistent
    ############################################################
    #
    # Every registered coin must be complete and consistent —
    # the contract differs per family, so each is checked
    # against the fields ITS family actually uses.
    ############################################################

    def test_definitions_are_consistent(self):
        for symbol, coin in coins.REGISTRY.items():
            with self.subTest(coin=symbol):
                self.assertEqual(coin.name, symbol)
                self.assertIn(coin.family, ("bitcoin", "cryptonote"))
                self.assertGreater(len(coin.networks()), 0)

                if coin.family == "bitcoin":
                    self.assertTrue(callable(coin.pow_hash))
                    self.assertGreater(coin.difficulty_1_target, 0)
                else:
                    self.assertGreaterEqual(coin.cn_variant, 0)
                    self.assertGreater(coin.reserve_size, 0)






    ############################################################
    # test_every_coin_resolves_to_a_runner
    ############################################################
    #
    # Every registered coin must resolve to a runner module —
    # a coin whose family has no implementation would only
    # fail at boot, in production.
    ############################################################

    def test_every_coin_resolves_to_a_runner(self):
        # Redundant: os and mock are already imported at module
        # level, and the os.environ patch below changes nothing
        # the lookup reads — config.py takes COIN from the
        # environment once, at import, and the config.COIN
        # patch beside it sets the value itself
        import os
        from unittest import mock

        from anypool import families

        for symbol in coins.REGISTRY:
            with self.subTest(coin=symbol):
                with mock.patch.dict(os.environ, {"COIN": symbol}), \
                     mock.patch("anypool.config.COIN", symbol):
                    runner = families.active()
                    self.assertTrue(callable(runner.run))






    ############################################################
    # test_active_coin
    ############################################################
    #
    # active() must return the coin config.COIN names — KNF,
    # the COIN value tests/__init__.py pins before config.py
    # reads the environment.
    ############################################################

    def test_active_coin(self):
        self.assertIs(coins.active(), coins.REGISTRY["KNF"])








############################################################
# TestGbtRequest
############################################################
#
# The getblocktemplate request each coin's daemon needs —
# the rules it must ask for, or no request object at all
# for daemons older than the rules mechanism.
############################################################

class TestGbtRequest(unittest.TestCase):






    ############################################################
    # test_modern_coin_request
    ############################################################
    #
    # Modern Litecoin-family daemons get the rules list, plus
    # the longpollid when re-arming a longpoll.
    ############################################################

    def test_modern_coin_request(self):
        knf = coins.get_coin("KNF")

        self.assertEqual(knf.gbt_request(), [{"rules": ["segwit", "mweb"]}])
        self.assertEqual(
            knf.gbt_request(longpollid="abc123"),
            [{"rules": ["segwit", "mweb"], "longpollid": "abc123"}]
        )






    ############################################################
    # test_old_coin_request
    ############################################################
    #
    # Old daemons (Dogecoin) get NO request object at all for a
    # plain poll — some predate the rules mechanism entirely.
    ############################################################

    def test_old_coin_request(self):
        doge = coins.get_coin("DOGE")

        self.assertEqual(doge.gbt_request(), [])
        self.assertEqual(doge.gbt_request(longpollid="abc123"), [{"longpollid": "abc123"}])






    ############################################################
    # test_btc_request
    ############################################################
    #
    # Bitcoin Core REFUSES getblocktemplate without the segwit
    # rule — it must always be requested.
    ############################################################

    def test_btc_request(self):
        btc = coins.get_coin("BTC")

        self.assertEqual(btc.gbt_request(), [{"rules": ["segwit"]}])
        self.assertEqual(
            btc.gbt_request(longpollid="abc123"),
            [{"rules": ["segwit"], "longpollid": "abc123"}]
        )








############################################################
# TestAddressSchemes
############################################################
#
# The payout script each coin's address scheme turns a
# reward address into, and the refusal of another coin's or
# another network's address — what stops a misconfigured
# pool at boot instead of paying a block away.
############################################################

class TestAddressSchemes(unittest.TestCase):






    ############################################################
    # test_bech32_scheme
    ############################################################
    #
    # KNF (bech32 scheme) must produce the P2WPKH script from
    # the accepted block 1777.
    ############################################################

    def test_bech32_scheme(self):
        knf = coins.get_coin("KNF")
        script = knf.address_scheme.payout_script(vectors.REWARD_ADDR, "mainnet")
        self.assertEqual(script, vectors.PAYOUT_SCRIPT)






    ############################################################
    # test_base58_scheme
    ############################################################
    #
    # DOGE (base58 scheme) must produce a legacy P2PKH script.
    ############################################################

    def test_base58_scheme(self):
        doge = coins.get_coin("DOGE")
        script = doge.address_scheme.payout_script(DOGE_ADDR, "mainnet")
        self.assertEqual(script, "76a914" + DOGE_HASH160 + "88ac")






    ############################################################
    # test_cross_coin_addresses_rejected
    ############################################################
    #
    # Feeding one coin's address to another coin's scheme must
    # fail — the config validator relies on this.
    ############################################################

    def test_cross_coin_addresses_rejected(self):
        with self.assertRaises(ValueError):
            coins.get_coin("KNF").address_scheme.payout_script(DOGE_ADDR, "mainnet")
        with self.assertRaises(ValueError):
            coins.get_coin("DOGE").address_scheme.payout_script(vectors.REWARD_ADDR, "mainnet")






    ############################################################
    # test_btc_bech32_scheme
    ############################################################
    #
    # BTC bech32 scheme, checked against the canonical BIP173
    # reference vectors (same 20-byte program on both networks).
    # testnet3 and testnet4 share the "tb" prefix — the same
    # address must decode identically on both.
    ############################################################

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








############################################################
# TestVersionRolling
############################################################
#
# Which coins let miners roll the header version (BIP310),
# and with which mask.
############################################################

class TestVersionRolling(unittest.TestCase):






    ############################################################
    # test_masks
    ############################################################
    #
    # BTC carries the standard BIP320 mask; KNF, LTC and
    # Dogecoin must decline version rolling (mask 0) —
    # Dogecoin's version bits encode the AuxPoW chain id, and
    # the scrypt coins were validated without rolling.
    ############################################################

    def test_masks(self):
        self.assertEqual(coins.get_coin("BTC").version_rolling_mask, 0x1FFFE000)
        for symbol in ("KNF", "LTC", "DOGE"):
            self.assertEqual(coins.get_coin(symbol).version_rolling_mask, 0,
                             f"{symbol} must not allow version rolling")








############################################################
# TestMwebPegin
############################################################
#
# The MWEB peg-in settings: which coins carry them, how they
# are read from the environment and judged, and the decimal
# check the amount and the fee rate go through.
############################################################

class TestMwebPegin(unittest.TestCase):






    ############################################################
    # test_coins_with_mweb_carry_peg_in_settings
    ############################################################
    #
    # Exactly the coins with MWEB carry peg-in settings — KNF
    # and LTC; Bitcoin and Dogecoin have neither.
    ############################################################

    def test_coins_with_mweb_carry_peg_in_settings(self):
        for symbol, coin in coins.REGISTRY.items():
            if coin.family != "bitcoin":
                continue
            with self.subTest(coin=symbol):
                self.assertEqual(coin.mweb_pegin is not None, coin.has_mweb)
        self.assertEqual({symbol for symbol, coin in coins.REGISTRY.items() if getattr(coin, "has_mweb", False)},
                         {"KNF", "LTC"})






    ############################################################
    # test_settings_come_from_the_environment
    ############################################################
    #
    # The settings come from MWEB_PEGIN_AMOUNT, _WALLET and
    # _FEE_RATE, trimmed, an empty wallet name meaning none —
    # and with none of them set, nothing is set.
    ############################################################

    def test_settings_come_from_the_environment(self):
        variables = {"MWEB_PEGIN_AMOUNT": " 0.5 ", "MWEB_PEGIN_WALLET": " pool ", "MWEB_PEGIN_FEE_RATE": "10"}
        with mock.patch.dict(os.environ, variables):
            self.assertEqual(MwebPegin.from_environment(), MwebPegin("0.5", "pool", "10"))

        with mock.patch.dict(os.environ, {"MWEB_PEGIN_AMOUNT": "1", "MWEB_PEGIN_WALLET": "  "}):
            self.assertIsNone(MwebPegin.from_environment().wallet)

        with mock.patch.dict(os.environ):
            for variable in variables:
                os.environ.pop(variable, None)
            settings = MwebPegin.from_environment()
        self.assertEqual(settings, MwebPegin())
        self.assertFalse(settings.is_set())






    ############################################################
    # test_problems_name_the_setting
    ############################################################
    #
    # Valid settings have no problem; each broken one names
    # the setting to fix.
    ############################################################

    def test_problems_name_the_setting(self):
        for settings in (MwebPegin(), MwebPegin("1"), MwebPegin("0.00000001", "pool", "12.5")):
            with self.subTest(settings=settings):
                self.assertIsNone(settings.problem())

        cases = [
            (MwebPegin("0"), "MWEB_PEGIN_AMOUNT"),
            (MwebPegin("one"), "MWEB_PEGIN_AMOUNT"),
            (MwebPegin("0.000000001"), "MWEB_PEGIN_AMOUNT"),
            (MwebPegin("1", fee_rate="-5"), "MWEB_PEGIN_FEE_RATE"),
            (MwebPegin("1", fee_rate="1.0001"), "MWEB_PEGIN_FEE_RATE"),
            (MwebPegin(wallet="pool"), "need MWEB_PEGIN_AMOUNT"),
            (MwebPegin(fee_rate="10"), "need MWEB_PEGIN_AMOUNT"),
        ]
        for settings, named in cases:
            with self.subTest(settings=settings):
                self.assertIn(named, settings.problem())






    ############################################################
    # test_positive_decimals
    ############################################################
    #
    # Positive numbers within the decimal places pass; zero,
    # negatives, words, empty text, NaN, infinity and anything
    # finer than the places allow are refused.
    ############################################################

    def test_positive_decimals(self):
        for text, places in (("1", 8), ("0.00000001", 8), ("21000000", 8), ("0.5", 8),
                             ("10", 3), ("12.5", 3), ("0.001", 3)):
            with self.subTest(text=text, places=places):
                self.assertTrue(is_positive_decimal(text, places))

        for text, places in (("0", 8), ("-1", 8), ("abc", 8), ("", 8), ("NaN", 8), ("Infinity", 8),
                             ("0.000000001", 8), ("1.0001", 3), ("1,5", 8)):
            with self.subTest(text=text, places=places):
                self.assertFalse(is_positive_decimal(text, places))








if __name__ == "__main__":
    unittest.main()
