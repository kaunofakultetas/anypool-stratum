# -----------------------------------------------------------
#  [*] Stratum Client Connection
#
#  One StratumConnection per connected miner. Owns the raw
#  TCP stream and speaks the line-delimited JSON-RPC dialect
#  of the stratum v1 protocol:
#
#    mining.subscribe  — miner announces itself; we assign
#                        its unique extranonce1 and send the
#                        current difficulty + job
#    mining.authorize  — miner names its worker
#    mining.submit     — miner submits a share; forwarded to
#                        StratumServer.process_share()
#
#  This layer only frames/parses messages and manages the
#  connection lifecycle — all mining decisions (validation,
#  targets, job state) belong to server.py.
#
#  Used by:
#    - main.py — handle_client() is the asyncio.start_server
#                connection callback
# -----------------------------------------------------------

import asyncio
import json
import random

from anypool.mining.shares import validate_share_params




class StratumConnection:


    # -----------------------------------------------------------
    # __init__
    # -----------------------------------------------------------
    #
    # Binds the connection to its TCP stream and asks the
    # server for a unique extranonce1 — this is what makes
    # every miner's coinbase (and thus merkle root) distinct.
    #
    # Used by:
    #   - stratum/connection.py — handle_client()
    # -----------------------------------------------------------
    def __init__(self, reader, writer, server):
        self.reader = reader
        self.writer = writer
        self.server = server

        self.authorized = False
        self.worker_name = None
        self.miner_software = "Unknown"
        self.subscription_id = None

        # Unique per connection, prepended to every coinbase
        self.extra_nonce1 = server.next_extranonce1()

        self.client_ip = writer.get_extra_info('peername')[0]






    # -----------------------------------------------------------
    # handle
    # -----------------------------------------------------------
    #
    # The connection's main loop: read one JSON line at a
    # time and dispatch it, until the miner disconnects or an
    # unrecoverable error occurs. Read timeouts (30 min) are
    # NOT fatal — idle miners stay connected. Cleanup always
    # runs: the client is removed from broadcasts and the
    # socket is closed.
    #
    # Used by:
    #   - stratum/connection.py — handle_client()
    # -----------------------------------------------------------
    async def handle(self):
        try:
            self.server.add_client(self)

            while True:
                try:
                    data = await asyncio.wait_for(self.reader.readline(), timeout=1800.0)

                    # Empty read means the client closed the connection
                    if not data:
                        print(f"[CONNECTION] {self.client_ip} closed connection")
                        break

                    try:
                        raw_message = data.decode().strip()
                        if not raw_message:
                            continue

                        message = json.loads(raw_message)
                        await self.process_message(message)

                    except json.JSONDecodeError:
                        print(f"[CONNECTION] {self.client_ip} sent invalid JSON: {raw_message[:200]}")
                        continue

                except asyncio.TimeoutError:
                    print(f"[CONNECTION] {self.client_ip} timeout, continuing...")
                    continue

                except Exception as conn_error:
                    if "Broken pipe" in str(conn_error) or "Connection reset" in str(conn_error):
                        print(f"[CONNECTION] {self.client_ip} disconnected")
                    else:
                        print(f"[CONNECTION] {self.client_ip} error: {conn_error}")
                    break

        except Exception as e:
            print(f"[CONNECTION] {self.client_ip or 'unknown'} handler error: {e}")

        finally:
            # Always deregister and close, whatever happened above
            self.server.remove_client(self)
            try:
                if not self.writer.is_closing():
                    self.writer.close()
                    await self.writer.wait_closed()
            except Exception as e:
                print(f"[CLEANUP] Error closing connection: {e}")






    # -----------------------------------------------------------
    # send_response
    # -----------------------------------------------------------
    #
    # JSON-RPC response to a specific request id (replies to
    # subscribe / authorize / submit).
    #
    # Used by:
    #   - stratum/connection.py — the handle_* methods below
    # -----------------------------------------------------------
    async def send_response(self, message_id, result=None, error=None):
        response = {"id": message_id, "result": result, "error": error}
        await self.send_message(response)






    # -----------------------------------------------------------
    # send_notification
    # -----------------------------------------------------------
    #
    # Server-initiated JSON-RPC notification (id: null), used
    # for mining.set_difficulty and mining.notify pushes.
    #
    # Used by:
    #   - stratum/connection.py — handle_subscribe()
    #   - stratum/server.py     — broadcast_new_job()
    # -----------------------------------------------------------
    async def send_notification(self, method, params):
        notification = {"id": None, "method": method, "params": params}
        await self.send_message(notification)






    # -----------------------------------------------------------
    # send_message
    # -----------------------------------------------------------
    #
    # Serializes one message onto the wire (newline-delimited
    # JSON). Errors are re-raised so callers can treat the
    # client as disconnected.
    #
    # Used by:
    #   - stratum/connection.py — send_response() / send_notification()
    # -----------------------------------------------------------
    async def send_message(self, message):
        try:
            data = json.dumps(message) + "\n"
            self.writer.write(data.encode())
            await self.writer.drain()
        except Exception as e:
            print(f"[SEND] Failed to send message to client: {e}")
            raise  # Re-raise to let caller handle cleanup






    # -----------------------------------------------------------
    # process_message
    # -----------------------------------------------------------
    #
    # Routes one parsed stratum message to its handler.
    # Unknown methods are logged and ignored (miners send
    # various optional extensions we don't need).
    #
    # Used by:
    #   - stratum/connection.py — handle()
    # -----------------------------------------------------------
    async def process_message(self, message):
        method = message.get("method")
        params = message.get("params", [])
        msg_id = message.get("id")

        try:
            if method == "mining.subscribe":
                await self.handle_subscribe(msg_id, params)
            elif method == "mining.authorize":
                await self.handle_authorize(msg_id, params)
            elif method == "mining.submit":
                await self.handle_submit(msg_id, params)
            else:
                print(f"[DEBUG] Unknown method from {self.client_ip}: {method}")

        except Exception as e:
            print(f"[PROCESS] {self.client_ip} error processing {method}: {e}")






    # -----------------------------------------------------------
    # handle_subscribe
    # -----------------------------------------------------------
    #
    # The stratum handshake. Replies with the subscription
    # ids, this connection's extranonce1 and the extranonce2
    # size (4 bytes), then immediately pushes the current
    # difficulty and job so the miner can start hashing
    # without waiting for the next broadcast.
    #
    # Used by:
    #   - stratum/connection.py — process_message()
    # -----------------------------------------------------------
    async def handle_subscribe(self, msg_id, params):

        # First param is the miner's user agent, e.g. "cpuminer/2.5.1"
        if params and len(params) > 0 and params[0]:
            self.miner_software = params[0]
        print(f"[SUBSCRIBE] {self.client_ip} - {self.miner_software} subscribing")

        self.subscription_id = f"{random.randint(0, 0xffffffff):08x}"
        extra_nonce2_size = 4

        response = [
            [["mining.set_difficulty", self.subscription_id], ["mining.notify", self.subscription_id]],
            self.extra_nonce1,
            extra_nonce2_size
        ]
        await self.send_response(msg_id, response)

        # Push current difficulty right away
        await self.send_notification("mining.set_difficulty", [self.server.pool_difficulty])

        # Make sure a job exists, then push it
        if not self.server.job_manager.current_job:
            await self.server.create_job()

        job = self.server.job_manager.current_job
        if job:
            job_params = [
                job["job_id"],
                job["prevhash"],       # Already stratum wire format — don't reverse
                job["coinb1"],
                job["coinb2"],
                job["merkle_branch"],
                job["version"],
                job["nbits"],
                job["ntime"],
                True                   # clean_jobs: drop any previous work
            ]
            await self.send_notification("mining.notify", job_params)






    # -----------------------------------------------------------
    # handle_authorize
    # -----------------------------------------------------------
    #
    # Records the worker name. No password check — this pool
    # accepts any worker (fine for a private/teaching pool,
    # do NOT expose publicly as-is).
    #
    # Used by:
    #   - stratum/connection.py — process_message()
    # -----------------------------------------------------------
    async def handle_authorize(self, msg_id, params):
        if len(params) >= 1:
            self.worker_name = params[0]
            self.authorized = True
            print(f"[AUTHORIZE] {self.client_ip} authorized worker: {self.worker_name}")
            await self.send_response(msg_id, True)
        else:
            await self.send_response(msg_id, False)






    # -----------------------------------------------------------
    # handle_submit
    # -----------------------------------------------------------
    #
    # Receives one share. Miners that skipped mining.authorize
    # are auto-authorized from the worker name in the submit —
    # some miner software submits before authorizing. After
    # parameter validation the share is judged by the server
    # and the verdict (true/false) is sent back.
    #
    # Expected params:
    #   [worker_name, job_id, extra_nonce2, ntime, nonce]
    #
    # Used by:
    #   - stratum/connection.py — process_message()
    # -----------------------------------------------------------
    async def handle_submit(self, msg_id, params):

        # Auto-authorize if the miner never sent mining.authorize
        if not self.authorized and len(params) >= 1:
            self.worker_name = params[0]
            self.authorized = True

        if not self.authorized:
            await self.send_response(msg_id, False)
            return

        if not validate_share_params(params):
            await self.send_response(msg_id, False)
            return

        worker_name, job_id, extra_nonce2, ntime, nonce = params

        try:
            accepted = await self.server.process_share(
                worker_name, job_id, self.extra_nonce1, extra_nonce2, ntime, nonce
            )
            await self.send_response(msg_id, accepted)
        except Exception as e:
            print(f"[SUBMIT] {self.client_ip} share processing error: {e}")
            await self.send_response(msg_id, False)










# -----------------------------------------------------------
# handle_client
# -----------------------------------------------------------
#
# The asyncio.start_server callback: wraps every accepted
# TCP connection in a StratumConnection and runs its loop
# until disconnect.
#
# Used by:
#   - main.py — asyncio.start_server(...)
# -----------------------------------------------------------
async def handle_client(reader, writer, server):
    connection = StratumConnection(reader, writer, server)
    await connection.handle()
