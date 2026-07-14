# -----------------------------------------------------------
#  [*] Stratum Server Core
#
#  The stateful heart of the pool. StratumServer owns:
#
#    - the RPC client to the full node
#    - the JobManager (current + recent jobs)
#    - the pool/network difficulty and target state
#    - the set of connected miner clients
#    - lifetime share/block statistics
#
#  and orchestrates the three flows that make a pool a pool:
#
#    create_job()      — poll getblocktemplate, cut a fresh
#                        job when the chain tip moves, and
#                        broadcast it to every miner.
#    process_share()   — validate a submitted share against
#                        pool and network targets.
#    _submit_block()   — hand a network-grade share to the
#                        node as a complete block.
#
#  Per-connection protocol handling lives in connection.py;
#  this module never parses stratum messages itself.
#
#  Used by:
#    - main.py       — creates the single StratumServer
#    - stratum/connection.py — calls into it per miner message
# -----------------------------------------------------------

import asyncio
from typing import Dict

from anypool import coins, config, display
from anypool.crypto.hashing import reverse_hex, reverse_hex_4b_chunks, sha256d
from anypool.mining.blocks import assemble_block
from anypool.mining.jobs import JobManager, build_job
from anypool.mining.shares import build_header, ntime_within_range
from anypool.node.rpc import NodeRPC
from anypool.stratum.errors import (
    ERROR_DUPLICATE_SHARE,
    ERROR_JOB_NOT_FOUND,
    ERROR_LOW_DIFFICULTY,
    ERROR_OTHER,
    ERROR_TIME_OUT_OF_RANGE,
)




class StratumServer:


    # -----------------------------------------------------------
    # __init__
    # -----------------------------------------------------------
    #
    # Wires up the RPC client and JobManager, zeroes the stats,
    # derives the initial pool target from POOL_DIFFICULTY and
    # prints the startup banner.
    #
    # Used by:
    #   - main.py — once, at startup
    # -----------------------------------------------------------
    def __init__(self):
        self.rpc = NodeRPC()
        self.job_manager = JobManager()

        # Lifetime statistics
        self.shares_submitted = 0
        self.shares_accepted = 0
        self.shares_rejected = 0
        self.blocks_found = 0

        # Difficulty / target state (network side is learned
        # from the first block template)
        self.network_difficulty = None
        self.network_target = None
        self.pool_difficulty = config.POOL_DIFFICULTY
        self.pool_target = self.calculate_mining_target(config.POOL_DIFFICULTY)

        # Connected miners; each gets a unique extranonce1
        self.connected_clients = set()
        self.extranonce1_counter = 0

        display.startup_banner(self.pool_difficulty)






    # -----------------------------------------------------------
    # calculate_mining_target
    # -----------------------------------------------------------
    #
    # difficulty -> target. A share is valid when its hash,
    # read as a 256-bit integer, is at or below the target.
    # The difficulty-1 reference target comes from the active
    # coin's definition.
    #
    # Used by:
    #   - stratum/server.py — __init__() and create_job()
    # -----------------------------------------------------------
    def calculate_mining_target(self, difficulty: int) -> int:
        return coins.active().difficulty_1_target // difficulty






    # -----------------------------------------------------------
    # calculate_mining_difficulty
    # -----------------------------------------------------------
    #
    # target -> difficulty. The inverse of the above, used to
    # express the network target as a human-readable number.
    #
    # Used by:
    #   - stratum/server.py — create_job()
    # -----------------------------------------------------------
    def calculate_mining_difficulty(self, target: int) -> int:
        return coins.active().difficulty_1_target // target






    # -----------------------------------------------------------
    # next_extranonce1
    # -----------------------------------------------------------
    #
    # Hands out a unique 4-byte extranonce1 per connection so
    # every miner hashes a distinct coinbase (and can never
    # duplicate another miner's work).
    #
    # Used by:
    #   - stratum/connection.py — StratumConnection.__init__()
    # -----------------------------------------------------------
    def next_extranonce1(self) -> str:
        self.extranonce1_counter += 1
        return f"{self.extranonce1_counter:08x}"






    # -----------------------------------------------------------
    # add_client
    # -----------------------------------------------------------
    #
    # Registers a freshly connected miner for job broadcasts.
    #
    # Used by:
    #   - stratum/connection.py — StratumConnection.handle()
    # -----------------------------------------------------------
    def add_client(self, client) -> None:
        self.connected_clients.add(client)
        print(f"[CLIENTS] Added client. Total: {len(self.connected_clients)}")






    # -----------------------------------------------------------
    # remove_client
    # -----------------------------------------------------------
    #
    # Drops a miner from the broadcast list (disconnect or
    # send failure). Safe to call twice.
    #
    # Used by:
    #   - stratum/connection.py — StratumConnection.handle() cleanup
    #   - stratum/server.py     — broadcast_new_job() on send errors
    # -----------------------------------------------------------
    def remove_client(self, client) -> None:
        self.connected_clients.discard(client)
        print(f"[CLIENTS] Removed client. Total: {len(self.connected_clients)}")






    # -----------------------------------------------------------
    # broadcast_new_job
    # -----------------------------------------------------------
    #
    # Pushes the current job to every connected miner: first a
    # mining.set_difficulty, then the mining.notify with
    # clean_jobs=True (miners must abandon the previous job).
    # Clients that fail to receive are treated as disconnected
    # and removed.
    #
    # Used by:
    #   - stratum/server.py — create_job()
    #   - main.py   — after the initial job
    # -----------------------------------------------------------
    async def broadcast_new_job(self) -> None:
        job = self.job_manager.current_job
        if not job or not self.connected_clients:
            return

        # Copy: clients may get removed while we iterate
        clients_to_broadcast = list(self.connected_clients)
        disconnected_clients = set()

        notification_params = [
            job["job_id"], job["prevhash"], job["coinb1"], job["coinb2"],
            job["merkle_branch"], job["version"], job["nbits"], job["ntime"], True
        ]

        # Send sequentially so per-client failures can be caught
        for client in clients_to_broadcast:
            try:
                await client.send_notification("mining.set_difficulty", [self.pool_difficulty])
                await client.send_notification("mining.notify", notification_params)
            except Exception as e:
                print(f"[BROADCAST] Failed to send to client: {e}")
                disconnected_clients.add(client)

        for client in disconnected_clients:
            self.remove_client(client)
        if len(disconnected_clients) > 0:
            print(f"[BROADCAST] Removed {len(disconnected_clients)} disconnected clients")

        if self.connected_clients:
            display.broadcast_panel(job["job_id"], self.connected_clients)






    # -----------------------------------------------------------
    # create_job
    # -----------------------------------------------------------
    #
    # The job pipeline, run at startup and then every few
    # seconds by the refresh loop in main.py:
    #
    #   1. getblocktemplate from the node.
    #   2. If it describes the work we are already mining
    #      (same tip / mweb / target), keep the current job —
    #      miners hate pointless restarts.
    #   3. Otherwise refresh the difficulty/target state
    #      (optionally dropping pool difficulty to network
    #      difficulty, see POLL_DIFF_DROPPER).
    #   4. Build, store and broadcast the new job.
    #
    # Returns the current job, or None when the node call or
    # job construction failed (the refresh loop just retries).
    #
    # Used by:
    #   - main.py       — initial job + refresh loop
    #   - stratum/connection.py — handle_subscribe() when no job exists
    # -----------------------------------------------------------
    async def create_job(self) -> Dict:
        try:

            # Step 1: Fetch a fresh block template (request per coin definition)
            template = await self.rpc.call("getblocktemplate", coins.active().gbt_request())
            if not template or "previousblockhash" not in template:
                print(f"[ERROR] Invalid block template: {template}")
                return None


            # Step 2: Nothing changed? Keep the job miners are working on.
            if self.job_manager.is_same_work(template, self.network_target):
                return self.job_manager.current_job


            # Step 3: Refresh difficulty and target state
            self.network_target = int(template["target"], 16)
            self.network_difficulty = self.calculate_mining_difficulty(self.network_target)
            self.pool_target = self.calculate_mining_target(config.POOL_DIFFICULTY)
            self.pool_difficulty = config.POOL_DIFFICULTY

            # If the network difficulty drops below the pool's fixed
            # difficulty, mine at network difficulty instead
            if config.POLL_DIFF_DROPPER:
                if self.network_difficulty < config.POOL_DIFFICULTY:
                    self.pool_difficulty = self.network_difficulty
                    self.pool_target = self.network_target

            display.new_block_panel(template["height"] - 1, template["previousblockhash"])


            # Step 4: Build, store and broadcast the new job
            job = build_job(template, self.job_manager.next_job_id())
            self.job_manager.store(job)

            if self.connected_clients:
                print(f"[BROADCAST] BROADCASTING NEW JOB to {len(self.connected_clients)} clients...")
                asyncio.create_task(self.broadcast_new_job())

            display.job_created_panel(job, self.pool_difficulty, self.network_difficulty,
                                      self.pool_target, self.network_target)

            display.debug_box("DEBUG - StratumServer.create_job()", [
                "Stored job: ".ljust(25) +          job["job_id"],
                "Jobs in memory: ".ljust(25) +      str(len(self.job_manager.jobs)),
                "Job keys: ".ljust(25) +            str(list(self.job_manager.jobs.keys())),
                "Height: ".ljust(25) +              str(job["height"]),
                "Template transactions: ".ljust(25) + str(len(template.get("transactions", []))),
            ])

            return job

        except Exception as e:
            print(f"[ERROR] Failed to create job: {e}")
            return None






    # -----------------------------------------------------------
    # process_share
    # -----------------------------------------------------------
    #
    # Judges one submitted share:
    #
    #   1. Look up the EXACT job the miner worked on (stale
    #      job id -> reject).
    #   2. Cheap sanity gates: ntime inside the allowed window,
    #      not a duplicate of an earlier submission.
    #   3. Rebuild the header the miner hashed and its PoW
    #      hash (shares.build_header).
    #   4. hash <= pool target?     -> share accepted.
    #      hash <= network target?  -> it is a full block,
    #      submit it to the node.
    #
    # Returns (accepted, error): accepted travels back to the
    # miner as the mining.submit result, error is a standard
    # stratum error tuple (or None) shown in the miner's log.
    #
    # Used by:
    #   - stratum/connection.py — handle_submit()
    # -----------------------------------------------------------
    async def process_share(self, worker_name: str, job_id: str, extra_nonce1: str,
                            extra_nonce2: str, ntime: str, nonce: str):
        self.shares_submitted += 1

        try:

            # Step 1: Find the job this share belongs to
            job = self.job_manager.get(job_id)
            if not job:
                print("[SHARE] Stale/unknown job_id; rejecting")
                self.shares_rejected += 1
                return False, ERROR_JOB_NOT_FOUND


            # Step 2: Cheap sanity gates before any hashing work
            if not ntime_within_range(job["ntime"], ntime):
                print(f"[SHARE] ntime {ntime} outside allowed window of job ntime {job['ntime']}; rejecting")
                self.shares_rejected += 1
                return False, ERROR_TIME_OUT_OF_RANGE

            if not self.job_manager.register_share(job, extra_nonce1, extra_nonce2, ntime, nonce):
                print(f"[SHARE] Duplicate share for job {job_id} (nonce {nonce}); rejecting")
                self.shares_rejected += 1
                return False, ERROR_DUPLICATE_SHARE

            display.debug_box("DEBUG - Job and share details comparison", [
                "Job ID: ".ljust(25) +             job_id,
                "Job prevhash: ".ljust(25) +       job.get("prevhash", "MISSING"),
                "Job nbits: ".ljust(25) +          job.get("nbits", "MISSING"),
                "Job ntime: ".ljust(25) +          job.get("ntime", "MISSING"),
                "Job merkle branch: ".ljust(25) +  str(job.get("merkle_branch", "MISSING")),
                "Miner extra nonce1: ".ljust(25) + extra_nonce1,
                "Miner extra nonce2: ".ljust(25) + extra_nonce2,
                "Miner ntime: ".ljust(25) +        ntime,
                "Miner nonce: ".ljust(25) +        nonce,
            ], color="red")


            # Step 3: Rebuild the header the miner hashed
            result_hash, header_hex, header_bytes = build_header(
                job, extra_nonce1, extra_nonce2, ntime, nonce, context="process_share"
            )


            # Step 4: Compare against pool and network targets
            hash_int = int(result_hash, 16)
            is_accepted = hash_int <= self.pool_target
            is_block = is_accepted and hash_int <= self.network_target

            if is_accepted:
                self.shares_accepted += 1
            else:
                self.shares_rejected += 1

            display.share_result_panel(
                is_accepted=is_accepted,
                is_block=is_block,
                job_id=job_id,
                height=job["height"],
                result_hash=result_hash,
                sha256_hash=sha256d(header_bytes)[::-1].hex(),
                prevhash_display=reverse_hex_4b_chunks(reverse_hex(job["prevhash"])),
                pool_difficulty=self.pool_difficulty,
                network_difficulty=self.network_difficulty,
                pool_target=self.pool_target,
                network_target=self.network_target,
            )


            # Step 5: A network-grade share is a block — submit it
            if is_block:
                if await self._submit_block(job, extra_nonce1, extra_nonce2, header_hex):
                    self.blocks_found += 1

            return is_accepted, (None if is_accepted else ERROR_LOW_DIFFICULTY)

        except Exception as e:
            self.shares_rejected += 1
            print(f"[ERROR] Share processing failed: {e}")
            import traceback
            traceback.print_exc()
            return False, ERROR_OTHER

        finally:
            if self.shares_submitted > 0:
                print(f"[STATS] Shares: {self.shares_accepted}/{self.shares_submitted} ({100*self.shares_accepted/self.shares_submitted:.1f}%) | Blocks: {self.blocks_found}")






    # -----------------------------------------------------------
    # _submit_block
    # -----------------------------------------------------------
    #
    # Assembles the complete block around the already-verified
    # header and hands it to the node. The header comes from
    # the same build_header() call that validated the share,
    # so header and block body cannot disagree.
    #
    # submitblock returns null on success and an error string
    # ("bad-txnmrklroot", "high-hash", ...) on rejection.
    #
    # Used by:
    #   - stratum/server.py — process_share()
    # -----------------------------------------------------------
    async def _submit_block(self, job: Dict, extra_nonce1: str, extra_nonce2: str,
                            header_hex: str) -> bool:
        try:
            print("[SUBMIT] Building block for submission...")
            complete_block = assemble_block(job, extra_nonce1, extra_nonce2, header_hex,
                                            has_mweb=coins.active().has_mweb)

            print("[SUBMIT] Submitting to network...")
            result = await self.rpc.call("submitblock", [complete_block])

            if result is None:
                print("[SUBMIT] ✅ Block ACCEPTED by network!")
                return True
            else:
                print(f"[SUBMIT] ❌ Block REJECTED: {result}")
                return False

        except Exception as e:
            print(f"[SUBMIT] ❌ Block submission error: {e}")
            import traceback
            traceback.print_exc()
            return False
