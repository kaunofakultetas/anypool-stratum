############################################################
#  [*] Monero-style Node RPC Client
#
#  The CryptoNote counterpart of rpc.py. Monero-family
#  daemons (bitlitasd) expose JSON-RPC 2.0 under the /json_rpc
#  path plus a set of plain HTTP endpoints (/getheight,
#  /getinfo). Three differences from the Bitcoin client:
#
#    - methods live at {url}/json_rpc, not at /
#    - no HTTP auth (the 0.11 daemon uses none by default)
#    - errors come back as {"error": {...}} INSIDE a 200
#      response; a missing "result" is always a failure
#
#  Used for exactly three calls:
#
#    getblocktemplate  — wallet_address + reserve_size ->
#                        blocktemplate_blob to mine on
#    submitblock       — hand a solved block blob to the
#                        network
#    /getheight        — cheap tip poll (the 0.11 daemon has
#                        no longpoll; see cryptonote/runner)
#
#  Used by:
#    - families/cryptonote/server.py, runner.py
############################################################


from typing import Any, Optional

import aiohttp

from anypool import config


# Default per-call timeout in seconds. Normal node calls answer
# in milliseconds; hitting this means the node is down or hung.
DEFAULT_TIMEOUT = 10.0








class MoneroRPC:






    ############################################################
    # __init__
    ############################################################
    #
    # The session is not created here because aiohttp needs a
    # running event loop.
    #
    # Used by:
    #   - families/cryptonote/server.py — CnStratumServer.__init__()
    ############################################################

    def __init__(self):
        self.url = config.RPC_URL
        self.session: Optional[aiohttp.ClientSession] = None






    ############################################################
    # _session_get
    ############################################################
    #
    # The lazily-created shared session (recreated if closed).
    #
    # Used by:
    #   - call() and plain() below
    ############################################################

    async def _session_get(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()
        return self.session






    ############################################################
    # call
    ############################################################
    #
    # One JSON-RPC 2.0 call against {url}/json_rpc. Returns the
    # "result" object; raises on transport errors, non-200
    # statuses and in-band {"error": ...} answers, so callers
    # can treat any return value as success.
    #
    # Used by:
    #   - families/cryptonote/server.py — create_job(), _submit_block()
    ############################################################

    async def call(self, method: str, params: Any = None,
                   timeout: Optional[float] = DEFAULT_TIMEOUT) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "id": "stratum",
            "method": method,
            "params": params if params is not None else {},
        }

        session = await self._session_get()
        request_timeout = aiohttp.ClientTimeout(total=timeout)
        async with session.post(f"{self.url}/json_rpc", json=payload,
                                timeout=request_timeout) as resp:
            if resp.status != 200:
                body = (await resp.text())[:200]
                raise Exception(f"RPC HTTP {resp.status} from node: {body.strip()}")

            data = await resp.json(content_type=None)
            if data.get("error"):
                raise Exception(f"RPC Error: {data['error']}")
            if "result" not in data:
                raise Exception(f"RPC response missing result: {str(data)[:200]}")
            return data["result"]






    ############################################################
    # plain
    ############################################################
    #
    # One call against a plain endpoint like /getheight. These
    # answer a bare JSON object with a "status" field instead
    # of the JSON-RPC envelope.
    #
    # Used by:
    #   - families/cryptonote/runner.py — height poll loop
    ############################################################

    async def plain(self, path: str,
                    timeout: Optional[float] = DEFAULT_TIMEOUT) -> Any:
        session = await self._session_get()
        request_timeout = aiohttp.ClientTimeout(total=timeout)
        async with session.get(f"{self.url}{path}", timeout=request_timeout) as resp:
            if resp.status != 200:
                body = (await resp.text())[:200]
                raise Exception(f"RPC HTTP {resp.status} from node: {body.strip()}")
            return await resp.json(content_type=None)






    ############################################################
    # close
    ############################################################
    #
    # Graceful shutdown of the shared HTTP session.
    #
    # Used by:
    #   - families/cryptonote/runner.py — on server shutdown
    ############################################################

    async def close(self) -> None:
        if self.session and not self.session.closed:
            await self.session.close()
