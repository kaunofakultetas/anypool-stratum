############################################################
#  [*] Coin Definition Base
#
#  The contract every supported coin must fulfill. A coin of
#  the Bitcoin family is fully described by one frozen
#  CoinDefinition instance: which PoW function it uses, what
#  its difficulty-1 target is, which getblocktemplate rules
#  to request, how its addresses turn into payout scripts,
#  and whether it has the MWEB extension block — a coin that
#  has it also carries the operator's MWEB peg-in settings
#  (MwebPegin), the settings only such coins have. A
#  CryptoNote coin is described by the much smaller
#  CryptonoteCoinDefinition.
#
#  Adding a new coin never touches family or stratum code —
#  create a module for it in anypool/coins/, named after its
#  ticker symbol, with one definition, and register it in
#  anypool/coins/__init__.py. Older Bitcoin Core forks
#  without segwit (Dogecoin & friends) work by picking the
#  Base58P2PKH address scheme, an empty gbt_rules list and
#  leaving has_mweb off.
#
#  Used by:
#    - coins/btc.py, ltc.py, doge.py, knf.py — CoinDefinition
#    - coins/ltc.py, knf.py — MwebPegin
#    - coins/ltl.py — CryptonoteCoinDefinition
#    - coins/__init__.py — registry typing
#    - config.py — validate(), the MWEB peg-in settings
#    - families/bitcoin/mweb.py — the active coin's MwebPegin
############################################################


import os
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Callable, Dict, List, Optional








############################################################
# is_positive_decimal
############################################################
#
# Whether a setting reads as a positive decimal number with
# at most the given number of decimal places — the shape a
# node accepts for an amount (8 places) or a fee rate in
# satoshis per vbyte (3 places).
#
# Used by:
#   - MwebPegin.problem() (below)
#   - tests/test_coins.py
############################################################

def is_positive_decimal(text: str, places: int) -> bool:
    try:
        value = Decimal(text)
    except InvalidOperation:
        return False
    return value.is_finite() and value > 0 and value.as_tuple().exponent >= -places








############################################################
# MwebPegin
############################################################
#
# How a pool on a coin with MWEB gets its chain past the
# first MWEB block — the one block the node cannot build
# until a peg-in waits in its mempool (see
# families/bitcoin/mweb.py). With an amount set, the pool
# pegs that much in from the node's wallet itself when it
# finds the chain stuck there: from the named wallet (the
# node's only one when none is named), at the given fee rate
# in satoshis per vbyte (the wallet's own choice when unset).
# Without an amount the peg-in is the operator's job, and the
# pool's log says so.
#
# They are operator settings, read from the environment once
# at import like every other knob (MWEB_PEGIN_AMOUNT,
# MWEB_PEGIN_WALLET, MWEB_PEGIN_FEE_RATE), but they exist
# only for coins with MWEB, so they live in those coins'
# definitions rather than in config.py.
#
# Used by:
#   - coins/knf.py, coins/ltc.py — their mweb_pegin
#   - config.py — validate()
#   - families/bitcoin/mweb.py — active_pegin()
############################################################

@dataclass(frozen=True)
class MwebPegin:

    # The amount to peg in; empty leaves the peg-in to the
    # operator
    amount: str = ""

    # The loaded node wallet that pays; None means the node's
    # only wallet
    wallet: Optional[str] = None

    # Satoshis per vbyte; empty leaves the fee to the wallet
    fee_rate: str = ""






    ############################################################
    # from_environment
    ############################################################
    #
    # The settings as the operator gave them: MWEB_PEGIN_AMOUNT,
    # MWEB_PEGIN_WALLET and MWEB_PEGIN_FEE_RATE, trimmed, an
    # empty wallet name meaning none.
    #
    # Used by:
    #   - coins/knf.py, coins/ltc.py — their definitions
    #   - config.py — validate(), for coins without MWEB
    ############################################################

    @classmethod
    def from_environment(cls) -> "MwebPegin":
        return cls(
            amount=os.getenv("MWEB_PEGIN_AMOUNT", "").strip(),
            wallet=os.getenv("MWEB_PEGIN_WALLET", "").strip() or None,
            fee_rate=os.getenv("MWEB_PEGIN_FEE_RATE", "").strip(),
        )






    ############################################################
    # is_set
    ############################################################
    #
    # Whether the operator set any of the three at all.
    #
    # Used by:
    #   - config.py — validate()
    ############################################################

    def is_set(self) -> bool:
        return bool(self.amount or self.wallet or self.fee_rate)






    ############################################################
    # problem
    ############################################################
    #
    # The first thing wrong with the settings, worded for the
    # operator, or None: a wallet or fee rate does nothing
    # without an amount, and amount and fee rate must be
    # numbers the node will accept.
    #
    # Used by:
    #   - config.py — validate()
    ############################################################

    def problem(self) -> Optional[str]:
        if (self.wallet or self.fee_rate) and not self.amount:
            return "MWEB_PEGIN_WALLET and MWEB_PEGIN_FEE_RATE need MWEB_PEGIN_AMOUNT"
        if self.amount and not is_positive_decimal(self.amount, 8):
            return f"MWEB_PEGIN_AMOUNT '{self.amount}' is not a positive amount with at most 8 decimals"
        if self.fee_rate and not is_positive_decimal(self.fee_rate, 3):
            return f"MWEB_PEGIN_FEE_RATE '{self.fee_rate}' is not a positive rate (satoshis per vbyte, at most 3 decimals)"
        return None








############################################################
# CoinDefinition
############################################################
#
# The Bitcoin-family contract: the pool builds the coinbase
# and merkle tree itself and PoW-hashes 80-byte headers, so
# a coin must say how to hash, what difficulty 1 means,
# which template rules to request and how payout addresses
# turn into scripts. One frozen instance per coin.
#
# Used by:
#   - coins/btc.py, doge.py, knf.py, ltc.py — one instance
#     each
#   - coins/__init__.py — the return type of get_coin() and
#     active()
#   - config.py — validate(), the selected coin's networks,
#     address scheme and peg-in settings
#   - families/bitcoin/ — reads the active coin's fields
#     through coins.active()
############################################################

@dataclass(frozen=True)
class CoinDefinition:

    # Ticker symbol, e.g. "KNF" — informational: nothing in
    # the pool reads it (tests/test_coins.py checks that it
    # matches the REGISTRY key)
    name: str

    # Human-readable PoW algorithm name, e.g. "SCRYPT" —
    # informational: nothing reads it at the moment
    algo: str

    # The function hashing an 80-byte header into the PoW
    # hash (big-endian hex, comparable against a target)
    pow_hash: Callable[[bytes], str]

    # Reference target at difficulty 1 for this algorithm.
    # A difficulty's target is this value integer-divided by
    # the difficulty, and back (calculate_mining_target() and
    # calculate_mining_difficulty() in
    # families/bitcoin/server.py).
    difficulty_1_target: int

    # Rules to request from getblocktemplate. Empty list for
    # old daemons that predate the rules mechanism — the
    # request object then carries no rules, and is omitted
    # entirely unless a longpoll id has to go in it (see
    # gbt_request below).
    gbt_rules: List[str]

    # How REWARD_ADDR becomes the coinbase payout script
    # (Bech32P2WPKH or Base58P2PKH from coins/address.py)
    address_scheme: object

    # Litecoin-family MWEB extension: when True, the pool
    # watches the MWEB deployment and gets the chain past its
    # first MWEB block (families/bitcoin/mweb.py); "mweb"
    # belongs in gbt_rules then. A block's MWEB section itself
    # follows the template, so a coin without MWEB never
    # writes one.
    has_mweb: bool = False

    # The operator's MWEB peg-in settings (MwebPegin, from the
    # environment) — set exactly when has_mweb is, None for a
    # coin without MWEB
    mweb_pegin: Optional[MwebPegin] = None

    # BIP310 version-rolling mask: which header version bits a
    # miner may overwrite (AsicBoost). Modern SHA256 ASICs
    # refuse to mine without it, so BTC sets the standard
    # BIP320 mask 0x1fffe000. MUST stay 0 for coins whose
    # version bits carry meaning (e.g. Dogecoin's AuxPoW
    # chain id) — 0 makes the pool decline the extension.
    version_rolling_mask: int = 0

    # Which mining-model family this coin belongs to; decides
    # the stratum dialect, work construction and PoW check at
    # boot (see anypool/families/). Bitcoin Core forks are
    # described by THIS dataclass; CryptoNote coins by
    # CryptonoteCoinDefinition below.
    family: str = "bitcoin"






    ############################################################
    # networks
    ############################################################
    #
    # The network names this coin supports, the values
    # COIN_NETWORK may take — delegated to the address scheme,
    # which is the only part that differs per network.
    #
    # Used by:
    #   - config.py — validate()
    ############################################################

    def networks(self) -> List[str]:
        return self.address_scheme.networks()






    ############################################################
    # gbt_request
    ############################################################
    #
    # Builds the params list for getblocktemplate: a single
    # request object carrying the coin's rules (when it has
    # any) and the longpoll id (when one is given), or an
    # empty list when there is neither — an old daemon that
    # predates the rules mechanism then gets a plain poll.
    #
    # Used by:
    #   - families/bitcoin/server.py — _fetch_template(), the
    #     template fetch of create_job()
    #   - families/bitcoin/runner.py — longpoll_loop()
    ############################################################

    def gbt_request(self, longpollid: Optional[str] = None) -> List[Dict]:
        request = {}
        if self.gbt_rules:
            request["rules"] = self.gbt_rules
        if longpollid:
            request["longpollid"] = longpollid
        return [request] if request else []








############################################################
# CryptonoteCoinDefinition
############################################################
#
# The CryptoNote-family contract. Much smaller than the
# Bitcoin one: the DAEMON builds the whole block (the pool
# only writes an extranonce into the template's reserved
# space), so no payout scripts, GBT rules or header hashing
# — just the CN PoW variant and the address scheme.
#
# Used by:
#   - coins/ltl.py — its one instance
#   - config.py — validate(), the selected coin's networks
#     and address scheme
#   - families/cryptonote/server.py — reads the active
#     coin's reserve_size and cn_variant through
#     coins.active()
############################################################

@dataclass(frozen=True)
class CryptonoteCoinDefinition:

    # Ticker symbol, e.g. "LTL" — informational: nothing in
    # the pool reads it (tests/test_coins.py checks that it
    # matches the REGISTRY key)
    name: str

    # Human-readable PoW algorithm name, e.g. "CRYPTONIGHT" —
    # informational: nothing reads it at the moment
    algo: str

    # CryptoNight variant passed to the PoW library: 0 =
    # classic cn/0, which is what a chain frozen at block
    # major version 1 uses. The algo name announced to XMRig
    # does NOT follow it — job_payload() in
    # families/cryptonote/connection.py sends a hard-coded
    # "cn/0", so a coin on another variant would need that
    # changed as well.
    cn_variant: int

    # How the pool validates REWARD_ADDR at startup
    # (CryptoNoteAddress from coins/address.py); the daemon
    # receives the address string itself and builds the
    # coinbase from it
    address_scheme: object

    # Bytes of TX_EXTRA_NONCE space requested from the daemon
    # via get_block_template's reserve_size — the pool writes
    # its per-client extranonce in here. 16 leaves room to
    # spare around the 8 bytes actually used.
    reserve_size: int = 16

    family: str = "cryptonote"






    ############################################################
    # networks
    ############################################################
    #
    # Same contract as CoinDefinition.networks() — delegated
    # to the address scheme.
    #
    # Used by:
    #   - config.py — validate()
    ############################################################

    def networks(self) -> List[str]:
        return self.address_scheme.networks()
