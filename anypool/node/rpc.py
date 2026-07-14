# -----------------------------------------------------------
#  [*] Full Node RPC Client
#
#  The only place in the codebase that talks HTTP. A thin
#  JSON-RPC 1.0 client for the coin daemon (litecoind/knfd),
#  used for exactly two calls:
#
#    getblocktemplate — poll for new work (every 5s)
#    submitblock      — hand a solved block to the network
#
#  One aiohttp session is created lazily on the first call
#  and reused for the lifetime of the process — the previous
#  implementation opened a new session per call, which is
#  wasteful when polling every few seconds.
#
#  Used by:
#    - stratum/server.py — StratumServer owns one NodeRPC instance
# -----------------------------------------------------------

from typing import Any, List, Optional

import aiohttp

from anypool import config




class NodeRPC:


    # -----------------------------------------------------------
    # __init__
    # -----------------------------------------------------------
    #
    # Stores credentials from config. The session is not created
    # here because aiohttp needs a running event loop.
    #
    # Used by:
    #   - stratum/server.py — StratumServer.__init__()
    # -----------------------------------------------------------
    def __init__(self):
        self.url = config.RPC_URL
        self.auth = aiohttp.BasicAuth(config.RPC_USER, config.RPC_PASS)
        self.session: Optional[aiohttp.ClientSession] = None






    # -----------------------------------------------------------
    # call
    # -----------------------------------------------------------
    #
    # Performs one JSON-RPC call and returns its "result" field.
    # Raises on any error the node reports, so callers can treat
    # a return value as a successful response.
    #
    # Used by:
    #   - stratum/server.py — create_job() and _submit_block()
    # -----------------------------------------------------------
    async def call(self, method: str, params: List = None) -> Any:
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

        async with self.session.post(self.url, json=payload) as resp:
            data = await resp.json()
            if "error" in data and data["error"]:
                raise Exception(f"RPC Error: {data['error']}")
            return data["result"]






    # -----------------------------------------------------------
    # close
    # -----------------------------------------------------------
    #
    # Graceful shutdown of the shared HTTP session.
    #
    # Used by:
    #   - main.py — on server shutdown
    # -----------------------------------------------------------
    async def close(self) -> None:
        if self.session and not self.session.closed:
            await self.session.close()
