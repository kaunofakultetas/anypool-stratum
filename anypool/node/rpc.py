############################################################
#  [*] Full Node RPC Client
#
#  One of the two places in the codebase that talk HTTP —
#  monero_rpc.py is its CryptoNote counterpart. A thin
#  JSON-RPC 1.0 client for the Bitcoin-style coin daemon
#  (litecoind/knfd), used for:
#
#    getblocktemplate            — poll for new work (every 5s)
#    getblocktemplate (longpoll) — blocks until the chain tip
#                                  moves, for instant job cuts
#    submitblock                 — hand a solved block to the
#                                  network
#    getblockchaininfo, getblock — the MWEB deployment watch
#                                  (families/bitcoin/mweb.py)
#    getnewaddress, sendtoaddress — the optional MWEB peg-in,
#                                  through the node's wallet
#
#  One aiohttp session is created lazily on the first call
#  and reused for the lifetime of the process — opening a
#  fresh session per call would burn a TCP+auth handshake on
#  every single poll.
#
#  Every call carries a timeout (default 10s) so a hung node
#  can never silently freeze the job refresh loop. Longpoll
#  calls override it, since blocking is their whole point.
#
#  A refusal comes back as a NodeRPCError carrying the node's
#  own error code and message. Bitcoin Core-style nodes send
#  refusals with HTTP 500, so the body is read whatever the
#  status says; only a body that is no JSON-RPC answer at all
#  (an HTML error page from an overloaded node or a proxy)
#  falls back to the bare HTTP status.
#
#  Used by:
#    - families/bitcoin/server.py — StratumServer owns one
#      NodeRPC instance
#    - families/bitcoin/runner.py — longpoll + shutdown
#    - families/bitcoin/mweb.py — deployment reads, peg-in,
#      and NodeRPCError for the peg-in's failure hints
############################################################


import json
from typing import Any, Dict, List, Optional, Union
from urllib.parse import quote

import aiohttp

from anypool import config


# Default per-call timeout in seconds. Normal node calls answer
# in milliseconds; hitting this means the node is down or hung.
DEFAULT_TIMEOUT = 10.0








############################################################
# NodeRPCError
############################################################
#
# A node's refusal of one call: the JSON-RPC error object it
# answered with, its code and message kept apart so a caller
# can tell a refusal it can explain (no wallet loaded, not
# enough funds) from every other failure. The text reads
# "RPC Error: " followed by the node's error object, the
# same log line the pool has always printed for a refusal.
#
# Used by:
#   - NodeRPC.call (below) — every refusal
#   - families/bitcoin/mweb.py — the peg-in's failure hints
############################################################

class NodeRPCError(Exception):






    ############################################################
    # __init__
    ############################################################
    #
    # Keeps the whole error object, and its code and message
    # when the node sent the usual object with both fields;
    # anything else keeps no code and its text as the message.
    #
    # Used by:
    #   - NodeRPC.call (below)
    ############################################################

    def __init__(self, error: Any):
        self.error = error
        self.code = error.get("code") if isinstance(error, dict) else None
        self.message = error.get("message") if isinstance(error, dict) else str(error)
        super().__init__(f"RPC Error: {error}")








############################################################
# NodeRPC
############################################################
#
# The client of a Bitcoin-style daemon, one per pool
# process: the node URL and basic-auth credentials from
# config, and one aiohttp session opened on the first call
# and reused by every call after it until close(). Every
# question the Bitcoin family asks its node — templates,
# block submission, the MWEB deployment watch and peg-in —
# goes through the single call() below, so timeouts and
# error handling are decided in one place.
#
# Used by:
#   - families/bitcoin/server.py — StratumServer creates the
#     instance and calls through it
#   - families/bitcoin/runner.py — longpoll_loop() and the
#     teardown in run(), through server.rpc
#   - families/bitcoin/mweb.py — send_pegin() and MwebWatch
#     are handed the instance
############################################################

class NodeRPC:






    ############################################################
    # __init__
    ############################################################
    #
    # Stores credentials from config. The session is not created
    # here because aiohttp needs a running event loop.
    #
    # Used by:
    #   - families/bitcoin/server.py — StratumServer.__init__()
    ############################################################

    def __init__(self):
        self.url = config.RPC_URL
        self.auth = aiohttp.BasicAuth(config.RPC_USER, config.RPC_PASS)
        self.session: Optional[aiohttp.ClientSession] = None






    ############################################################
    # call
    ############################################################
    #
    # Performs one JSON-RPC call and returns its "result" field.
    # Raises on any error the node reports (and on timeout), so
    # callers can treat a return value as a successful response.
    #
    # `params` is a list of positional arguments or a dict of
    # named ones — named arguments let a caller set one late
    # optional parameter without spelling out all the others.
    # `wallet` routes the call to one loaded wallet's own
    # endpoint, which wallet calls need once a node has more
    # than one wallet loaded; None keeps the plain endpoint.
    #
    # `timeout` overrides the 10s default — longpoll callers
    # pass None (no timeout at all) because their request is
    # MEANT to hang until the chain tip moves.
    #
    # Used by:
    #   - families/bitcoin/server.py — _fetch_template() and _submit_block()
    #   - families/bitcoin/runner.py — longpoll_loop()
    #   - families/bitcoin/mweb.py — MwebWatch.observe() and
    #     MwebWatch.diagnose(), send_pegin()
    ############################################################

    async def call(self, method: str, params: Union[List, Dict, None] = None,
                   timeout: Optional[float] = DEFAULT_TIMEOUT, wallet: Optional[str] = None) -> Any:
        if params is None:
            params = []

        payload = {
            "jsonrpc": "1.0",
            "id": "stratum",
            "method": method,
            "params": params
        }

        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(auth=self.auth)

        url = self.url if wallet is None else f"{self.url}/wallet/{quote(wallet, safe='')}"

        request_timeout = aiohttp.ClientTimeout(total=timeout)
        async with self.session.post(url, json=payload, timeout=request_timeout) as resp:
            body = await resp.text()

            try:
                data = json.loads(body)
            except ValueError:
                data = None

            # The node's own error object outranks the HTTP status —
            # refusals travel under HTTP 500
            if isinstance(data, dict) and data.get("error"):
                raise NodeRPCError(data["error"])

            # Overloaded/broken nodes answer with an HTML error page —
            # surface the real status instead of a JSON decode error
            if resp.status != 200 or not isinstance(data, dict):
                raise Exception(f"RPC HTTP {resp.status} from node: {body[:200].strip()}")

            return data["result"]






    ############################################################
    # close
    ############################################################
    #
    # Graceful shutdown of the shared HTTP session.
    #
    # Used by:
    #   - families/bitcoin/runner.py — run() teardown
    ############################################################

    async def close(self) -> None:
        if self.session and not self.session.closed:
            await self.session.close()
