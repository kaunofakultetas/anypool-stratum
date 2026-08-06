############################################################
#  [*] Shared Stratum Plumbing
#
#  The protocol-neutral half of the miner-facing layer. Both
#  stratum dialects this pool speaks — Bitcoin stratum v1
#  (mining.subscribe/notify/submit) and the CryptoNote
#  dialect (login/getjob/submit) — are newline-delimited
#  JSON-RPC over raw TCP, so everything below the message
#  vocabulary is identical and lives here exactly once:
#
#    BaseStratumConnection — socket lifecycle, line framing,
#        JSON encode/decode, wire debug logging. Subclasses
#        implement process_message() with their dialect.
#
#    BasePoolServer — the connected-client registry, share/
#        block statistics and safe fire-and-forget background
#        tasks. Subclasses add job state and share judgment.
#
#  Used by:
#    - families/bitcoin/connection.py, server.py
#    - families/cryptonote/connection.py, server.py
############################################################


import asyncio
import json

from anypool import config








class BaseStratumConnection:






    ############################################################
    # __init__
    ############################################################
    #
    # Binds the connection to its TCP stream. Dialect-specific
    # state (extranonces, rolling masks, client ids) belongs
    # to the subclass __init__.
    #
    # Used by:
    #   - family connection subclasses
    ############################################################

    def __init__(self, reader, writer, server):
        self.reader = reader
        self.writer = writer
        self.server = server

        self.authorized = False
        self.worker_name = None
        self.miner_software = "Unknown"

        self.client_ip = writer.get_extra_info('peername')[0]






    ############################################################
    # handle
    ############################################################
    #
    # The connection's main loop: read one JSON line at a
    # time and dispatch it, until the miner disconnects or an
    # unrecoverable error occurs. Read timeouts (30 min) are
    # NOT fatal — idle miners stay connected. Cleanup always
    # runs: the client is removed from broadcasts and the
    # socket is closed.
    #
    # Used by:
    #   - family connection modules — handle_client()
    ############################################################

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

                        if config.DEBUG:
                            print(f"[WIRE-IN ] {self.client_ip} >> {raw_message[:400]}")

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






    ############################################################
    # process_message
    ############################################################
    #
    # The dialect: every family connection implements its own
    # method dispatch here.
    #
    # Used by:
    #   - handle() above
    ############################################################

    async def process_message(self, message):
        raise NotImplementedError






    ############################################################
    # send_response
    ############################################################
    #
    # A JSON-RPC response to a request id the miner sent.
    #
    # Used by:
    #   - families/bitcoin/connection.py    — every handler
    #   - families/cryptonote/connection.py — every handler
    ############################################################

    async def send_response(self, message_id, result=None, error=None):
        await self.send_message({"id": message_id, "result": result, "error": error})






    ############################################################
    # send_notification
    ############################################################
    #
    # A server-pushed JSON-RPC notification (id null). Only
    # the Bitcoin dialect uses these; the CryptoNote dialect
    # pushes its custom job frames through send_message.
    #
    # Used by:
    #   - families/bitcoin/connection.py — set_difficulty +
    #     notify after subscribe
    #   - families/bitcoin/server.py     — broadcast_new_job()
    ############################################################

    async def send_notification(self, method, params):
        await self.send_message({"id": None, "method": method, "params": params})






    ############################################################
    # send_message
    ############################################################
    #
    # Serializes one frame as a single JSON line and drains
    # the socket. Send errors are re-raised so callers treat
    # the client as disconnected.
    #
    # Used by:
    #   - send_response / send_notification (above)
    #   - families/cryptonote/connection.py — login result
    #     and pushed job frames
    ############################################################

    async def send_message(self, message):
        try:
            data = json.dumps(message) + "\n"
            if config.DEBUG:
                print(f"[WIRE-OUT] {self.client_ip} << {data.strip()[:400]}")
            self.writer.write(data.encode())
            await self.writer.drain()
        except Exception as e:
            print(f"[SEND] Failed to send message to client: {e}")
            raise  # Re-raise to let caller handle cleanup








class BasePoolServer:






    ############################################################
    # __init__
    ############################################################
    #
    # Zeroes the client registry, statistics and background-
    # task bookkeeping shared by every family server.
    #
    # Used by:
    #   - family server subclasses (super().__init__())
    ############################################################

    def __init__(self):

        # Lifetime statistics
        self.shares_submitted = 0
        self.shares_accepted = 0
        self.shares_rejected = 0
        self.blocks_found = 0

        # Connected miners
        self.connected_clients = set()

        # Strong references to in-flight background tasks (block
        # submissions, job broadcasts): the event loop itself only
        # keeps weak ones, so a fire-and-forget task could otherwise
        # be garbage-collected mid-flight.
        self.background_tasks = set()






    ############################################################
    # add_client
    ############################################################
    #
    # Puts a freshly connected miner on the broadcast list.
    #
    # Used by:
    #   - BaseStratumConnection.handle() — on connect
    ############################################################

    def add_client(self, client) -> None:
        self.connected_clients.add(client)
        print(f"[CLIENTS] Added client. Total: {len(self.connected_clients)}")






    ############################################################
    # remove_client
    ############################################################
    #
    # Takes a miner off the broadcast list. Safe to call
    # twice — the disconnect and send-failure paths race.
    #
    # Used by:
    #   - BaseStratumConnection.handle() — cleanup
    #   - family servers — when a broadcast send fails
    ############################################################

    def remove_client(self, client) -> None:
        self.connected_clients.discard(client)
        print(f"[CLIENTS] Removed client. Total: {len(self.connected_clients)}")






    ############################################################
    # _spawn
    ############################################################
    #
    # Runs a coroutine as a fire-and-forget background task while
    # keeping a strong reference until it finishes — asyncio only
    # holds weak references to tasks, so an unreferenced task can
    # be garbage-collected mid-flight.
    #
    # Used by:
    #   - family servers — job broadcasts, block submissions
    ############################################################

    def _spawn(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self.background_tasks.add(task)
        task.add_done_callback(self.background_tasks.discard)
        return task






    ############################################################
    # _print_stats
    ############################################################
    #
    # One-line lifetime counters, printed after every processed
    # share and again when a background block submission gets
    # accepted (that is the moment blocks_found moves).
    #
    # Used by:
    #   - family servers — process_share(), submission tasks
    ############################################################

    def _print_stats(self) -> None:
        if self.shares_submitted == 0:
            return
        print(f"[STATS] Shares: {self.shares_accepted}/{self.shares_submitted} ({100*self.shares_accepted/self.shares_submitted:.1f}%) | Blocks: {self.blocks_found}")
