############################################################
#  [*] Tests — Startup Validation of Coin Settings
#
#  Covers how config.py's startup validation treats the
#  settings only some coins have — the MWEB peg-in settings,
#  which live in the definitions of the coins with MWEB — so
#  a misconfigured pool stops at boot rather than at the
#  first MWEB block weeks later:
#
#    - a coin with MWEB passes with no peg-in settings, an
#      amount alone, or the full set
#    - a coin with MWEB whose peg-in settings have a problem
#      stops the pool, naming the setting
#    - peg-in settings in the environment of a coin without
#      MWEB (Bitcoin, Dogecoin) stop the pool, while that
#      coin with none set passes
#
#  The settings themselves are covered in tests/test_coins.py.
#
#  This module never imports the tests package itself: the
#  KNF setup validate() runs against is in place because an
#  earlier module of the run imported tests/__init__.py (or
#  because the module was named through the package). A
#  discovery run narrowed to this file alone runs validate()
#  against the container's real configuration instead.
#
#  Used by:
#    - unittest discovery (run inside the stratum container)
############################################################


import contextlib
import dataclasses
import os
import unittest
from unittest import mock

from anypool import coins, config
from anypool.coins.base import MwebPegin


# A valid reward address for each coin the tests switch to
BTC_ADDRESS = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
DOGE_ADDRESS = "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"

# The environment variables the MWEB peg-in settings come from
PEGIN_VARIABLES = ("MWEB_PEGIN_AMOUNT", "MWEB_PEGIN_WALLET", "MWEB_PEGIN_FEE_RATE")








############################################################
# knf_with
############################################################
#
# The KNF definition (the coin tests/__init__.py pins) with
# the given peg-in settings in it, for one validate() call.
#
# Used by:
#   - TestCoinSettingsValidation (below) — its two KNF test
#     cases
############################################################

def knf_with(settings):
    knf = dataclasses.replace(coins.REGISTRY["KNF"], mweb_pegin=settings)
    return mock.patch.dict(coins.REGISTRY, {"KNF": knf})








############################################################
# coin_without_mweb
############################################################
#
# Switches the pool to a coin without MWEB, with a valid
# reward address for it, and the given peg-in variables as
# the only ones in the environment.
#
# Used by:
#   - TestCoinSettingsValidation (below) — its two test
#     cases on coins without MWEB
############################################################

@contextlib.contextmanager
def coin_without_mweb(coin, address, **environment):
    with mock.patch.multiple("anypool.config", COIN=coin, COIN_NETWORK="mainnet", REWARD_ADDR=address), \
         mock.patch.dict(os.environ):
        for variable in PEGIN_VARIABLES:
            os.environ.pop(variable, None)
        os.environ.update(environment)
        yield








############################################################
# TestCoinSettingsValidation
############################################################
#
# config.validate() over the MWEB peg-in settings: KNF with
# its definition's settings swapped per case, and Bitcoin
# and Dogecoin with the peg-in variables swapped in the
# environment.
############################################################

class TestCoinSettingsValidation(unittest.TestCase):






    ############################################################
    # test_valid_settings_pass
    ############################################################
    #
    # No peg-in settings, an amount alone, and the full set all
    # pass on KNF.
    ############################################################

    def test_valid_settings_pass(self):
        for settings in (MwebPegin(), MwebPegin("1"), MwebPegin("0.001", "pool", "10")):
            with self.subTest(settings=settings), knf_with(settings):
                config.validate()






    ############################################################
    # test_a_problem_stops_the_pool_naming_the_setting
    ############################################################
    #
    # A problem in the coin's peg-in settings stops the pool,
    # naming the setting.
    ############################################################

    def test_a_problem_stops_the_pool_naming_the_setting(self):
        cases = [
            (MwebPegin("0"), "MWEB_PEGIN_AMOUNT"),
            (MwebPegin("one"), "MWEB_PEGIN_AMOUNT"),
            (MwebPegin("1", fee_rate="-5"), "MWEB_PEGIN_FEE_RATE"),
            (MwebPegin(wallet="pool"), "need MWEB_PEGIN_AMOUNT"),
        ]
        for settings, named in cases:
            with self.subTest(settings=settings), knf_with(settings):
                with self.assertRaises(SystemExit) as stopped:
                    config.validate()
                self.assertIn(named, str(stopped.exception))






    ############################################################
    # test_peg_in_settings_on_a_coin_without_mweb_stop_the_pool
    ############################################################
    #
    # A coin without MWEB carries no peg-in settings, so any
    # in its environment would do nothing — they stop the pool.
    ############################################################

    def test_peg_in_settings_on_a_coin_without_mweb_stop_the_pool(self):
        for coin, address in (("BTC", BTC_ADDRESS), ("DOGE", DOGE_ADDRESS)):
            for variable in PEGIN_VARIABLES:
                with self.subTest(coin=coin, variable=variable), \
                     coin_without_mweb(coin, address, **{variable: "1"}):
                    with self.assertRaises(SystemExit) as stopped:
                        config.validate()
                    self.assertIn(f"{coin} has no MWEB", str(stopped.exception))






    ############################################################
    # test_coins_without_mweb_pass_without_peg_in_settings
    ############################################################
    #
    # The same coins without any peg-in setting pass.
    ############################################################

    def test_coins_without_mweb_pass_without_peg_in_settings(self):
        for coin, address in (("BTC", BTC_ADDRESS), ("DOGE", DOGE_ADDRESS)):
            with self.subTest(coin=coin), coin_without_mweb(coin, address):
                config.validate()








if __name__ == "__main__":
    unittest.main()
