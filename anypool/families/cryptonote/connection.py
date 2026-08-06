############################################################
#  [*] CryptoNote Stratum Client Connection
#
#  One CnConnection per connected miner, speaking the
#  CryptoNote stratum dialect (what XMRig and every other
#  CryptoNote miner talks):
#
#    login      — miner announces itself (its "login" is a
#                 worker name for this solo pool); we reply
#                 with a session id and its first job
#    getjob     — explicit request for fresh work
#    submit     — one share: {id, job_id, nonce, result};
#                 forwarded to CnStratumServer.process_share()
#    keepalived — heartbeat, answered with KEEPALIVED
#
#  Unlike the Bitcoin dialect there are no difficulty or
#  clean-jobs notifications: difficulty travels INSIDE each
#  job as the compact "target" field, and a pushed "job"
#  notification implicitly obsoletes the previous one.
#
#  Per-connection difficulty (the CryptoNote convention for
#  what Bitcoin miners do via mining.suggest_difficulty): a
#  miner may request its own difficulty with either
#
#      login:    "workername+25000"
#      password: "d=25000"
#
#  so one pool port can serve a CPU and a rented rig at once.
#  The request is clamped by the server (see
#  CnStratumServer.effective_difficulty).
#
#  Framing and connection lifecycle live in the shared base
#  (anypool/stratum/base.py) — this file is only the dialect.
#
#  Used by:
#    - families/cryptonote/runner.py — handle_client() is the
#      asyncio.start_server connection callback
############################################################


import secrets

from anypool.families.cryptonote.errors import (
    ERROR_MALFORMED_NONCE,
    ERROR_UNAUTHENTICATED,
    as_rpc_error,
)
from anypool.stratum.base import BaseStratumConnection








############################################################
# _is_hex
############################################################
#
# True for a non-empty pure-hex string. int(s, 16) is not
# enough for wire input — it tolerates "0x" prefixes,
# underscores and surrounding whitespace.
#
# Used by:
#   - CnConnection.handle_submit() — nonce/result shape gates
############################################################

def _is_hex(s: str) -> bool:
    return bool(s) and all(c in "0123456789abcdefABCDEF" for c in s)








############################################################
# parse_client_difficulty
############################################################
#
# Extracts a requested per-connection difficulty from the
# login parameters, following the conventions CryptoNote
# miners expect ("worker+DIFF" in the login, or "d=DIFF" in
# the password — XMRig users pass either). Returns
# (worker_name_without_suffix, difficulty_or_None); anything
# unparsable degrades gracefully to no request.
#
# Used by:
#   - CnConnection.handle_login()
#   - tests/test_cn_server.py
############################################################

def parse_client_difficulty(login: str, password: str):
    login = login or ""
    requested = None

    if "+" in login:
        login, _, suffix = login.rpartition("+")
        if suffix.isdigit() and int(suffix) >= 1:
            requested = int(suffix)
        else:
            login = f"{login}+{suffix}"  # not a difficulty; restore

    if requested is None and password:
        for part in password.split(","):
            key, _, value = part.partition("=")
            if key.strip().lower() in ("d", "diff") and value.strip().isdigit() and int(value) >= 1:
                requested = int(value)
                break

    return login, requested








class CnConnection(BaseStratumConnection):






    ############################################################
    # __init__
    ############################################################
    #
    # Socket lifecycle and framing come from the shared base;
    # this adds the CryptoNote-dialect state: the session id
    # handed out at login and this connection's extranonce —
    # the 8 bytes that personalize every blob it receives.
    #
    # Used by:
    #   - handle_client() (bottom of this file)
    ############################################################

    def __init__(self, reader, writer, server):
        super().__init__(reader, writer, server)

        self.session_id = secrets.token_hex(8)
        self.extranonce = server.next_client_extranonce()

        # Per-connection difficulty request (None = pool default),
        # set at login and clamped by the server at every job cut
        self.requested_difficulty = None

        # The most recent job cut for this connection (server
        # reads it for the broadcast panel)
        self.last_job = None






    ############################################################
    # send_response
    ############################################################
    #
    # CryptoNote miners expect the full JSON-RPC 2.0 envelope
    # in responses ("jsonrpc": "2.0"), so this overrides the
    # base's bare {id, result, error} shape.
    #
    # Used by:
    #   - the handlers below
    ############################################################

    async def send_response(self, message_id, result=None, error=None):
        await self.send_message({
            "id": message_id,
            "jsonrpc": "2.0",
            "result": result,
            "error": error,
        })






    ############################################################
    # job_payload
    ############################################################
    #
    # Cuts a fresh personalized job from the server's job
    # manager and renders it as the wire object miners expect.
    # The "algo" field tells modern XMRig which algorithm to
    # run without local configuration.
    #
    # Used by:
    #   - handle_login(), handle_getjob(), push_job()
    ############################################################

    def job_payload(self) -> dict:
        difficulty = self.server.effective_difficulty(self.requested_difficulty)
        job = self.server.job_manager.make_job(self, self.extranonce, difficulty)
        self.last_job = job
        return {
            "blob": job["hashing_blob"].hex(),
            "job_id": job["job_id"],
            "target": job["target"],
            "height": job["height"],
            "algo": "cn/0",
            "id": self.session_id,
        }






    ############################################################
    # push_job
    ############################################################
    #
    # Sends a fresh job as a server-initiated "job"
    # notification — the dialect's way to obsolete the
    # miner's previous work (there is no clean-jobs flag).
    #
    # Used by:
    #   - families/cryptonote/server.py — broadcast_new_jobs()
    ############################################################

    async def push_job(self):
        await self.send_message({
            "jsonrpc": "2.0",
            "method": "job",
            "params": self.job_payload(),
        })






    ############################################################
    # process_message
    ############################################################
    #
    # Routes one parsed message to its handler. Every request
    # gets SOME answer — an unanswered id stalls miners.
    #
    # Used by:
    #   - stratum/base.py — BaseStratumConnection.handle()
    ############################################################

    async def process_message(self, message):
        method = message.get("method")
        params = message.get("params") or {}
        msg_id = message.get("id")

        try:
            if method == "login":
                await self.handle_login(msg_id, params)
            elif method == "getjob":
                await self.handle_getjob(msg_id, params)
            elif method == "submit":
                await self.handle_submit(msg_id, params)
            elif method == "keepalived":
                await self.send_response(msg_id, {"status": "KEEPALIVED"})
            else:
                print(f"[DEBUG] Unknown method from {self.client_ip}: {method}")
                if msg_id is not None:
                    await self.send_response(msg_id, None,
                                             as_rpc_error(f"Method '{method}' not supported"))

        except Exception as e:
            print(f"[PROCESS] {self.client_ip} error processing {method}: {e}")






    ############################################################
    # handle_login
    ############################################################
    #
    # The dialect's handshake. In a payout pool the "login"
    # field carries the miner's wallet address; this solo pool
    # treats it as a worker name and accepts anyone (fine for
    # a private/teaching pool, do NOT expose publicly as-is).
    # The reply carries the session id and the first job, so
    # the miner starts hashing on the spot.
    #
    # Used by:
    #   - process_message()
    ############################################################

    async def handle_login(self, msg_id, params):
        worker, requested = parse_client_difficulty(
            str(params.get("login") or ""), str(params.get("pass") or ""))
        self.worker_name = worker or self.client_ip
        self.requested_difficulty = requested
        self.miner_software = params.get("agent", "Unknown")
        self.authorized = True

        difficulty_note = ""
        if requested:
            difficulty_note = (f" (requested difficulty {requested:,}, granted "
                               f"{self.server.effective_difficulty(requested):,})")
        print(f"[LOGIN] {self.client_ip} - {self.miner_software} logged in "
              f"as {self.worker_name}{difficulty_note}")

        # Make sure a template exists before cutting the first job
        if self.server.job_manager.template is None:
            await self.server.create_job()
        if self.server.job_manager.template is None:
            await self.send_response(msg_id, None,
                                     as_rpc_error("Pool has no work yet, try again"))
            return

        await self.send_response(msg_id, {
            "id": self.session_id,
            "job": self.job_payload(),
            "status": "OK",
        })






    ############################################################
    # handle_getjob
    ############################################################
    #
    # Explicit work request (rare — miners mostly live off
    # pushed jobs).
    #
    # Used by:
    #   - process_message()
    ############################################################

    async def handle_getjob(self, msg_id, params):
        if not self.authorized:
            await self.send_response(msg_id, None, as_rpc_error(ERROR_UNAUTHENTICATED))
            return
        await self.send_response(msg_id, self.job_payload())






    ############################################################
    # handle_submit
    ############################################################
    #
    # Receives one share: {"id": session, "job_id": ...,
    # "nonce": 8 hex chars, "result": 64-hex PoW hash}. The
    # verdict comes from the server; rejections carry the
    # conventional message strings miners parse (see
    # errors.py).
    #
    # Used by:
    #   - process_message()
    ############################################################

    async def handle_submit(self, msg_id, params):
        if not self.authorized or params.get("id") != self.session_id:
            await self.send_response(msg_id, None, as_rpc_error(ERROR_UNAUTHENTICATED))
            return

        job_id = str(params.get("job_id", ""))
        nonce = str(params.get("nonce", ""))
        result_hex = str(params.get("result", ""))

        # Cheap shape gates before any server work (the Bitcoin
        # family does the same via validate_share_params): the
        # nonce is 4 bytes, the result a 32-byte hash, both hex.
        if len(nonce) != 8 or not _is_hex(nonce):
            print(f"[SUBMIT] {self.client_ip} rejected malformed nonce: {nonce[:20]!r}")
            await self.send_response(msg_id, None, as_rpc_error(ERROR_MALFORMED_NONCE))
            return
        if len(result_hex) != 64 or not _is_hex(result_hex):
            print(f"[SUBMIT] {self.client_ip} rejected malformed result: {result_hex[:20]!r}")
            await self.send_response(msg_id, None, as_rpc_error("Malformed result hash"))
            return

        try:
            accepted, error = await self.server.process_share(self, job_id, nonce, result_hex)
            if accepted:
                await self.send_response(msg_id, {"status": "OK"})
            else:
                await self.send_response(msg_id, None, as_rpc_error(error))
        except Exception as e:
            print(f"[SUBMIT] {self.client_ip} share processing error: {e}")
            await self.send_response(msg_id, None, as_rpc_error("Internal error"))








############################################################
# handle_client
############################################################
#
# The asyncio.start_server callback: wraps every accepted
# TCP connection in a CnConnection and runs its loop until
# disconnect.
#
# Used by:
#   - families/cryptonote/runner.py — asyncio.start_server(...)
############################################################

async def handle_client(reader, writer, server):
    connection = CnConnection(reader, writer, server)
    await connection.handle()
