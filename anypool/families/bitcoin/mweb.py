############################################################
#  [*] MWEB Activation
#
#  What a pool has to know about the MimbleWimble Extension
#  Block on Litecoin-family chains — on any chain, at any
#  height: nothing here assumes where MWEB activates, the
#  node's own deployment report says where the chain stands.
#
#  Two things make the activation a pool's business:
#
#    - once MWEB is active, every block ends with a HogEx
#      transaction followed by the MWEB section; the block
#      template carries both, and blocks.py serializes the
#      section exactly when the template has one;
#    - the FIRST MWEB block cannot be built until a peg-in
#      waits in the node's mempool. Its HogEx would spend the
#      previous block's HogEx, and there is none, so without
#      a peg-in it has no input and the node refuses every
#      block template: mining stops at that height until
#      someone pegs coins in.
#
#  MwebWatch follows the deployment from block to block and
#  announces each change of its state, with the height of the
#  first MWEB block once the node's report allows it. When
#  getblocktemplate fails it checks whether this is that
#  stall; if so it explains the remedy (again every few
#  minutes while the chain stays stuck) and, when the active
#  coin's MWEB peg-in settings name an amount
#  (MWEB_PEGIN_AMOUNT), sends the peg-in itself from the
#  node's wallet.
#
#  Used by:
#    - families/bitcoin/server.py — StratumServer owns one
#      MwebWatch for coins with has_mweb
############################################################


from time import monotonic
from typing import Dict, Optional

from anypool import coins, display
from anypool.coins.base import MwebPegin
from anypool.node.rpc import NodeRPCError


# How long a FAILED peg-in waits before the next attempt on the
# same stuck tip: long enough not to hammer a wallet without
# coins, short enough to pick up the operator's fix
PEGIN_RETRY_SECONDS = 60

# How often the stall is explained again while the chain stays
# stuck — a stopped chain must not go quiet in the log
STALL_REMINDER_SECONDS = 600








############################################################
# deployment_state
############################################################
#
# One deployment's state from the node's own report, read the
# same way on every chain: getblockchaininfo's softforks
# (Litecoin Core and its forks) or getdeploymentinfo's
# deployments (newer Bitcoin Core). An entry is buried, bip9
# (start by time) or bip8 (start by height), with its details
# under a key named after its type. Returns the status as the
# node words it, whether the rules apply to the NEXT block,
# the height the status began at, the activation height the
# node reports for an active deployment, and the signalling
# statistics of a started one — or None when the node does
# not know the deployment at all.
#
# Used by:
#   - MwebWatch.observe() and MwebWatch.diagnose() (below)
#   - tests/test_mweb.py
############################################################

def deployment_state(chain_info: Optional[Dict], name: str = "mweb") -> Optional[Dict]:
    if not isinstance(chain_info, dict):
        return None

    deployments = chain_info.get("softforks") or chain_info.get("deployments") or {}
    entry = deployments.get(name)
    if not isinstance(entry, dict):
        return None

    details = entry.get(entry.get("type"))
    details = details if isinstance(details, dict) else {}
    statistics = details.get("statistics") or {}
    active = bool(entry.get("active"))

    return {
        "status": details.get("status") or ("active" if active else "defined"),
        "active": active,
        "since": details.get("since", entry.get("height")),
        "height": entry.get("height"),
        "period": statistics.get("period"),
        "threshold": statistics.get("threshold"),
        "elapsed": statistics.get("elapsed"),
        "count": statistics.get("count"),
    }








############################################################
# activation_height
############################################################
#
# The height of the first block the deployment's rules apply
# to, when it can be told: the node names it once the
# deployment is active (or buried); a locked-in deployment
# activates one signalling period after it locked in, and as
# the node only reports the period while signalling is under
# way, the caller may pass the period it remembered from
# then. None while the height cannot be known yet.
#
# Used by:
#   - MwebWatch.observe() (below)
############################################################

def activation_height(state: Optional[Dict], period: Optional[int] = None) -> Optional[int]:
    if not state:
        return None
    if state["height"] is not None:
        return state["height"]
    if state["status"] == "active":
        return state["since"]

    period = state["period"] or period
    if state["status"] == "locked_in" and state["since"] is not None and period:
        return state["since"] + period
    return None








############################################################
# first_block_pending
############################################################
#
# Whether the NEXT block is the chain's first MWEB block: the
# deployment applies to the next block, while the tip itself
# carries no MWEB section (getblock lists an "mweb" entry for
# every block that has one). That is the one block that needs
# a peg-in in the mempool before the node can build it.
#
# Used by:
#   - MwebWatch.diagnose() (below)
############################################################

def first_block_pending(state: Optional[Dict], tip_block: Optional[Dict]) -> bool:
    return bool(state and state["active"] and isinstance(tip_block, dict) and "mweb" not in tip_block)








############################################################
# send_pegin
############################################################
#
# Pegs coins into MWEB through the node's wallet: a fresh MWEB
# address of that wallet, then a payment of the amount to it —
# the payment is the peg-in transaction the first MWEB
# block's HogEx spends. Named arguments let the fee rate ride
# along without the payment call's other optional parameters.
# Returns the peg-in's txid; a refusal (no wallet loaded, not
# enough coins, no fee estimate) is raised as the node's
# NodeRPCError.
#
# Used by:
#   - MwebWatch.diagnose() (below)
############################################################

async def send_pegin(rpc, amount: str, wallet: Optional[str], fee_rate: str = "") -> str:
    address = await rpc.call("getnewaddress", ["", "mweb"], wallet=wallet)

    payment = {"address": address, "amount": amount}
    if fee_rate:
        payment["fee_rate"] = fee_rate
    return await rpc.call("sendtoaddress", payment, wallet=wallet)








############################################################
# pegin_hint
############################################################
#
# One line telling the operator what to fix when the node
# refused the peg-in: a node without wallet support, no wallet
# loaded or none named, not enough coins, a fee rate under the
# wallet's minimum, no fee estimate on a quiet chain. The
# wallet words several of these under one code (a fee rate
# too low and a wallet too poor share -6), so the message is
# read before the code. Anything else — and any failure that
# is no refusal by the node — gets no hint.
#
# Used by:
#   - MwebWatch.diagnose() (below)
############################################################

def pegin_hint(error: Exception) -> Optional[str]:
    if not isinstance(error, NodeRPCError):
        return None

    message = str(error.message or "").lower()
    if "minimum fee rate" in message or "min relay fee" in message:
        return "MWEB_PEGIN_FEE_RATE is below the wallet's minimum fee rate: raise it."
    if "fee estimation" in message or "fallbackfee" in message:
        return "Set MWEB_PEGIN_FEE_RATE (satoshis per vbyte): the wallet has no fee estimate."
    if "insufficient funds" in message:
        return "The wallet has no spendable coins to peg in."
    if error.code == -32601:
        return "The node runs without wallet support: enable a wallet on it, or peg in from another node."
    if error.code in (-18, -19):
        return "Load a wallet on the node, or name the one to use in MWEB_PEGIN_WALLET."
    return None








############################################################
# active_pegin
############################################################
#
# The MWEB peg-in settings of the coin being mined — part of
# its definition, as the settings only coins with MWEB have
# (see MwebPegin in coins/base.py); settings that peg in
# nothing for a coin that carries none.
#
# Used by:
#   - MwebWatch.observe() and MwebWatch.diagnose() (below)
############################################################

def active_pegin() -> MwebPegin:
    return getattr(coins.active(), "mweb_pegin", None) or MwebPegin()








class MwebWatch:






    ############################################################
    # __init__
    ############################################################
    #
    # Nothing seen yet: no deployment status announced, no
    # signalling period known, no stuck tip, no peg-in attempt.
    #
    # Used by:
    #   - families/bitcoin/server.py — StratumServer.__init__()
    ############################################################

    def __init__(self):
        self.status = None
        self.period = None
        self.stuck_tip = None
        self.reported_at = None
        self.attempt = None






    ############################################################
    # observe
    ############################################################
    #
    # Reads the deployment's state after a new tip and announces
    # it whenever it changed, so the operator sees signalling
    # start, lock-in (with the coming activation height) and
    # activation as they happen. The signalling period is
    # remembered while the node reports it — a locked-in
    # deployment's activation height follows from it. A node
    # that cannot answer, or does not know MWEB, is left alone:
    # this is reporting, never part of mining.
    #
    # Used by:
    #   - families/bitcoin/server.py — create_job(), in the
    #     background after each new tip
    ############################################################

    async def observe(self, rpc) -> Optional[Dict]:
        try:
            chain = await rpc.call("getblockchaininfo")
        except Exception:
            return None

        state = deployment_state(chain)
        if state is None:
            return None

        self.period = state["period"] or self.period
        if state["status"] != self.status:
            self.status = state["status"]
            display.mweb_status_panel(state, activation_height(state, self.period),
                                      chain.get("blocks", 0) + 1, active_pegin().amount)
        return state






    ############################################################
    # diagnose
    ############################################################
    #
    # Called when getblocktemplate failed. Answers "other" unless
    # the next block is the chain's first MWEB block; then it
    # explains the stall (once per stuck tip, and again every
    # STALL_REMINDER_SECONDS while it lasts) and answers
    # "stalled" — or, when the coin's peg-in settings name an
    # amount, sends the peg-in and answers "unstuck", so the
    # caller asks for the template again at once. One peg-in
    # per stuck tip: a failed attempt is retried after
    # PEGIN_RETRY_SECONDS, a sent one is never repeated. The
    # attempt is marked before the wallet call, so a template
    # poll running alongside cannot send a second one.
    #
    # Used by:
    #   - families/bitcoin/server.py — _fetch_template()
    ############################################################

    async def diagnose(self, rpc, error: Exception) -> str:
        # STEP 1: is the next block the chain's first MWEB block?
        # =======================================================
        try:
            chain = await rpc.call("getblockchaininfo")
            tip_hash = chain["bestblockhash"]
            tip = await rpc.call("getblock", [tip_hash, 1])
        except Exception:
            return "other"
        if not first_block_pending(deployment_state(chain), tip):
            return "other"


        # STEP 2: explain the stall — when the tip is new, and
        # again every STALL_REMINDER_SECONDS while it lasts
        # ====================================================
        height = chain["blocks"] + 1
        settings = active_pegin()
        now = monotonic()
        if tip_hash != self.stuck_tip:
            self.stuck_tip, self.reported_at, self.attempt = tip_hash, None, None
        if self.reported_at is None or now - self.reported_at >= STALL_REMINDER_SECONDS:
            self.reported_at = now
            display.mweb_stall_panel(height, tip_hash, error, settings.amount,
                                     self.attempt["txid"] if self.attempt else None)


        # STEP 3: the peg-in, when the pool is told to send it
        # ====================================================
        if not settings.amount:
            return "stalled"
        if self.attempt and (self.attempt["txid"] or self.attempt["sending"]
                             or now - self.attempt["at"] < PEGIN_RETRY_SECONDS):
            return "stalled"

        self.attempt = {"txid": None, "sending": True, "at": now}
        try:
            txid = await send_pegin(rpc, settings.amount, settings.wallet, settings.fee_rate)
        except Exception as failure:
            self.attempt = {"txid": None, "sending": False, "at": monotonic()}
            display.mweb_pegin_panel(height, settings.amount, None, failure, pegin_hint(failure))
            return "stalled"

        self.attempt = {"txid": txid, "sending": False, "at": monotonic()}
        display.mweb_pegin_panel(height, settings.amount, txid, None, None)
        return "unstuck"
