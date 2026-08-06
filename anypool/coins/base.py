############################################################
#  [*] Coin Definition Base
#
#  The contract every supported coin must fulfill. A coin is
#  fully described by one frozen CoinDefinition instance:
#  which PoW function it uses, what its difficulty-1 target
#  is, which getblocktemplate rules to request, how its
#  addresses turn into payout scripts, and whether its blocks
#  carry an MWEB extension tail.
#
#  Adding a new coin never touches family or stratum code —
#  create anypool/coins/<symbol>.py with one CoinDefinition
#  and register it in anypool/coins/__init__.py. Older
#  Bitcoin Core forks without segwit (Dogecoin & friends)
#  work by picking the Base58P2PKH address scheme, an empty
#  gbt_rules list and has_mweb=False.
#
#  Used by:
#    - coins/btc.py, ltc.py, doge.py, knf.py — CoinDefinition
#    - coins/ltl.py — CryptonoteCoinDefinition
#    - coins/__init__.py — registry typing
############################################################


from dataclasses import dataclass
from typing import Callable, Dict, List, Optional








############################################################
# The Bitcoin-family contract: the pool builds the coinbase
# and merkle tree itself and PoW-hashes 80-byte headers, so
# a coin must say how to hash, what difficulty 1 means,
# which template rules to request and how payout addresses
# turn into scripts.
############################################################

@dataclass(frozen=True)
class CoinDefinition:

    # Ticker symbol, e.g. "KNF"
    name: str

    # Human-readable PoW algorithm name, e.g. "SCRYPT"
    algo: str

    # The function hashing an 80-byte header into the PoW
    # hash (big-endian hex, comparable against a target)
    pow_hash: Callable[[bytes], str]

    # Reference target at difficulty 1 for this algorithm:
    #   target = difficulty_1_target // difficulty
    difficulty_1_target: int

    # Rules to request from getblocktemplate. Empty list for
    # old daemons that predate the rules mechanism — the
    # request object is then omitted entirely.
    gbt_rules: List[str]

    # How REWARD_ADDR becomes the coinbase payout script
    # (Bech32P2WPKH or Base58P2PKH from coins/address.py)
    address_scheme: object

    # Litecoin-family MWEB extension: when True, serialized
    # blocks carry the MWEB tail after the transactions
    # (marker byte + optional extension data). Must be False
    # for plain Bitcoin Core forks like Dogecoin, or every
    # submitted block would be malformed.
    has_mweb: bool = False

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
    # The network names this coin supports ("mainnet", ...) —
    # delegated to the address scheme, which is the only part
    # that differs per network.
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
    # Builds the getblocktemplate params for this coin:
    #
    #   rules + longpollid  -> [{"rules": [...], "longpollid": x}]
    #   rules only          -> [{"rules": [...]}]
    #   nothing             -> []   (old daemons, plain poll)
    #
    # Used by:
    #   - families/bitcoin/server.py — create_job()
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
# The CryptoNote-family contract. Much smaller than the
# Bitcoin one: the DAEMON builds the whole block (the pool
# only writes an extranonce into the template's reserved
# space), so no payout scripts, GBT rules or header hashing
# — just the CN PoW variant and the address scheme.
############################################################

@dataclass(frozen=True)
class CryptonoteCoinDefinition:

    # Ticker symbol, e.g. "LTL"
    name: str

    # Human-readable PoW algorithm name, e.g. "CRYPTONIGHT"
    algo: str

    # CryptoNight variant passed to the PoW library (and the
    # algo name announced to XMRig): 0 = classic cn/0, which
    # is what a chain frozen at block major version 1 uses.
    cn_variant: int

    # How the pool validates REWARD_ADDR and what it announces
    # to miners (CryptoNoteAddress from coins/address.py)
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
