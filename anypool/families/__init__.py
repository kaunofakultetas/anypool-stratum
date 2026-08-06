############################################################
#  [*] Coin Families
#
#  A "family" is everything that depends on which MINING
#  MODEL a coin uses — not which coin it is:
#
#    bitcoin/    — Bitcoin Core forks (BTC, LTC, DOGE, KNF).
#                  Stratum v1 (mining.subscribe/notify),
#                  getblocktemplate + longpoll, the pool
#                  builds coinbase + merkle, SHA256d/Scrypt.
#
#    cryptonote/ — CryptoNote coins (LTL/Bitlitas). The
#                  login/job/submit dialect XMRig speaks,
#                  get_block_template blobs with a reserved
#                  extranonce space, CryptoNight PoW.
#
#  Which family runs is decided ONCE, at boot, by the coin
#  selected via COIN — one pool process is always exactly one
#  coin and therefore one family. Adding a coin to an
#  existing family never touches family code (see coins/);
#  adding a NEW family means a new subpackage here exposing
#  an async run().
#
#  Used by:
#    - main.py — families.active().run()
############################################################


from anypool import coins








############################################################
# active
############################################################
#
# The runner module of the active coin's family. Imports
# lazily so a Bitcoin-family pool never imports CryptoNote
# dependencies and vice versa.
#
# Used by:
#   - main.py
############################################################

def active():
    family = coins.active().family

    if family == "bitcoin":
        from anypool.families.bitcoin import runner
        return runner

    if family == "cryptonote":
        from anypool.families.cryptonote import runner
        return runner

    raise SystemExit(f"[CONFIG] Unknown coin family '{family}'")
