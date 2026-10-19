############################################################
#  [*] CryptoNote Stratum Server Core
#
#  The stateful heart of a CryptoNote pool. CnStratumServer
#  owns the Monero-style RPC client, the CnJobManager, the
#  difficulty state and the client registry (via the shared
#  base), and orchestrates:
#
#    create_job()    — getblocktemplate from the daemon; when
#                      the chain tip moved (or a refresh
#                      forces it) every miner is pushed a
#                      freshly cut personalized job
#    process_share() — validate one submitted share by
#                      recomputing its CryptoNight hash
#    block submission — network-grade shares become full
#                      blocks, submitted in the background
#                      (the miner's reply never waits on the
#                      node round-trip)
#
#  The CryptoNight hash of a share takes ~100 ms of pure C
#  CPU — an eternity on the event loop — so it runs in the
#  default thread pool executor; the GIL is released inside
#  the C extension, keeping the pool responsive while
#  validating.
#
#  Used by:
#    - families/cryptonote/runner.py     — owns the instance
#    - families/cryptonote/connection.py — per-message calls
############################################################


import asyncio
import random
from typing import Dict, Optional, Tuple

from anypool import coins, config, display
from anypool.crypto.cryptonight import cn_slow_hash, hash_meets_difficulty
from anypool.families.cryptonote import errors
from anypool.families.cryptonote.blob import block_id, parse_block, with_nonce
from anypool.families.cryptonote.jobs import CnJobManager
from anypool.node.monero_rpc import MoneroRPC
from anypool.stratum.base import BasePoolServer


# How many recently solved parents the sibling-block guard
# remembers (same rationale as the Bitcoin family: a second
# solve on an already-submitted parent can only be stale).
MAX_SUBMITTED_PARENTS = 50








############################################################
# CnStratumServer
############################################################
#
# The one pool-wide object of a CryptoNote pool: every
# connection, both poll loops and the background block
# submissions share this instance. On top of the shared
# base (client registry, statistics, background tasks) it
# owns the daemon client, the job manager, the pool and
# network difficulty, the per-run extranonce source and the
# one-block-per-parent guard. Unlike the Bitcoin server it
# keeps no shared job to broadcast — the daemon builds the
# block, and each connection cuts its own personalized job
# from the current template whenever it needs one.
#
# Used by:
#   - families/cryptonote/runner.py — run() creates the
#     single instance and hands it to the poll loops and to
#     every connection
#   - families/cryptonote/connection.py — CnConnection asks
#     it for extranonces, difficulty, jobs and verdicts
############################################################

class CnStratumServer(BasePoolServer):






    ############################################################
    # __init__
    ############################################################
    #
    # Wires up RPC + job manager, derives the pool difficulty
    # from POOL_DIFFICULTY and prints the startup banner. The
    # random 4-byte instance token makes extranonces unique
    # across pool restarts (barring a one-in-four-billion
    # collision), so two runs do not hand out identical work.
    #
    # Used by:
    #   - families/cryptonote/runner.py — once, at startup
    ############################################################

    def __init__(self):
        super().__init__()

        self.rpc = MoneroRPC()
        self.job_manager = CnJobManager()

        self.pool_difficulty = config.POOL_DIFFICULTY
        self.network_difficulty = None

        self.instance_token = random.randbytes(4)
        self.client_id_counter = 0

        self.submitted_parents = {}

        display.startup_banner(self.pool_difficulty)






    ############################################################
    # next_client_extranonce
    ############################################################
    #
    # 8 unique bytes per connection (instance token + client
    # counter), written into the template's reserved space so
    # every miner hashes distinct work.
    #
    # Used by:
    #   - families/cryptonote/connection.py — CnConnection.__init__()
    ############################################################

    def next_client_extranonce(self) -> bytes:
        self.client_id_counter += 1
        return self.instance_token + self.client_id_counter.to_bytes(4, "big")






    ############################################################
    # effective_difficulty
    ############################################################
    #
    # The difficulty a job is actually cut at: the client's
    # requested per-connection difficulty (asked for at login,
    # see parse_client_difficulty) or the pool default, then
    # clamped — never above the 4-byte target encoding, never
    # below 1, and with POLL_DIFF_DROPPER never above the
    # network difficulty (same semantics as the Bitcoin
    # family's dropper, applied per client).
    #
    # Used by:
    #   - families/cryptonote/connection.py — job_payload(), handle_login()
    ############################################################

    def effective_difficulty(self, requested: Optional[int]) -> int:
        difficulty = requested if requested else self.pool_difficulty

        if config.POLL_DIFF_DROPPER and self.network_difficulty:
            difficulty = min(difficulty, self.network_difficulty)

        return max(1, min(difficulty, 0xFFFFFFFF))






    ############################################################
    # create_job
    ############################################################
    #
    # The template pipeline, run at startup, whenever the tip
    # poll sees the height move, after an accepted block, and
    # as a forced refresh every TEMPLATE_REFRESH_INTERVAL
    # (runner.py). The daemon builds the whole block around
    # the pool's REWARD_ADDR; this stores the template,
    # refreshes the difficulty state (POLL_DIFF_DROPPER may
    # lower the pool difficulty to the network's) and pushes
    # personalized jobs to every miner — but only when the
    # parent changed or the caller forces it (the periodic
    # refresh, for new mempool transactions). The template
    # itself is replaced on every fetch, so jobs cut in
    # between (login, getjob) already carry the newer
    # transactions.
    #
    # Returns the stored template, or None on failure (the
    # callers simply try again later).
    #
    # Used by:
    #   - families/cryptonote/runner.py — run() at startup,
    #     tip_poll_loop(), template_refresh_loop()
    #   - families/cryptonote/connection.py — handle_login()
    #     when no template exists yet
    #   - families/cryptonote/server.py — _submit_block_task(),
    #     the follow-up job after an accepted block
    ############################################################

    async def create_job(self, force_broadcast: bool = False) -> Optional[Dict]:
        try:
            # STEP 1: a fresh template from the daemon, built for
            # the pool's REWARD_ADDR with room for our extranonce
            # ===================================================
            coin = coins.active()
            template = await self.rpc.call("getblocktemplate", {
                "wallet_address": config.REWARD_ADDR,
                "reserve_size": coin.reserve_size,
            })
            if not template or "blocktemplate_blob" not in template:
                print(f"[ERROR] Invalid block template: {str(template)[:200]}")
                return None


            # STEP 2: store it (replaced even when the parent is
            # unchanged) and refresh the difficulty state
            # ==================================================
            is_new = self.job_manager.set_template(template, coin.reserve_size)

            self.network_difficulty = template["difficulty"]
            self.pool_difficulty = config.POOL_DIFFICULTY
            if config.POLL_DIFF_DROPPER and self.network_difficulty < config.POOL_DIFFICULTY:
                self.pool_difficulty = self.network_difficulty


            # STEP 3: announce a new parent; a new parent or a forced
            # refresh pushes personalized jobs to every miner
            # =======================================================
            if is_new:
                display.new_block_panel(template["height"] - 1, template["prev_hash"])

                blob = self.job_manager.template["blob"]
                tx_count = len(parse_block(blob)["tx_hashes"])
                display.cn_job_created_panel(
                    height=template["height"],
                    prev_hash=template["prev_hash"],
                    blob_size=len(blob),
                    tx_count=tx_count,
                    pool_difficulty=self.pool_difficulty,
                    network_difficulty=self.network_difficulty,
                )

            if is_new or force_broadcast:
                self._spawn(self.broadcast_new_jobs())

            display.debug_box("DEBUG - CnStratumServer.create_job()", [
                "New work: ".ljust(25) +               str(is_new),
                "Mining height: ".ljust(25) +          str(template["height"]),
                "Reserved offset: ".ljust(25) +        str(template["reserved_offset"]),
                "Jobs in memory: ".ljust(25) +         str(len(self.job_manager.jobs)),
                "Connected clients: ".ljust(25) +      str(len(self.connected_clients)),
            ])

            return self.job_manager.template

        except Exception as e:
            print(f"[ERROR] Failed to create job: {e}")
            return None






    ############################################################
    # broadcast_new_jobs
    ############################################################
    #
    # Cuts one personalized job per connected miner and pushes
    # it as a "job" notification. Clients that fail to receive
    # are treated as disconnected and removed. The registry is
    # filled on connect, not at login, so a connection that
    # has not logged in yet is pushed a job too (and takes a
    # slot in the job store).
    #
    # Used by:
    #   - families/cryptonote/server.py — create_job()
    ############################################################

    async def broadcast_new_jobs(self) -> None:
        if not self.connected_clients:
            return

        clients = list(self.connected_clients)
        disconnected = set()
        deliveries = []

        for client in clients:
            try:
                await client.push_job()
                deliveries.append((client, client.last_job))
            except Exception as e:
                print(f"[BROADCAST] Failed to send to client: {e}")
                disconnected.add(client)

        for client in disconnected:
            self.remove_client(client)

        if deliveries:
            display.cn_broadcast_panel(deliveries)






    ############################################################
    # process_share
    ############################################################
    #
    # Judges one submitted share, cheapest checks first: the
    # job must exist and belong to THIS connection and still
    # be at the current height, and the nonce must be 8 hex
    # chars and new for the job — the shape is checked again
    # although handle_submit() gates it, as the server does
    # not rely on its caller. Only then is the CryptoNight
    # hash recomputed, and the miner's claimed result must
    # equal it: a mismatch means broken or lying mining
    # software. A hash meeting the job's pool difficulty is
    # accepted; one meeting its network difficulty too is a
    # block, submitted in the background so the miner's
    # answer never waits on the node. Any unexpected error
    # rejects the share as invalid, traceback in the log.
    #
    # Staleness is judged by height alone: after a reorg that
    # swaps the parent but keeps the height, shares on jobs
    # cut from the old parent still pass.
    #
    # Returns whether the share was accepted, together with
    # its rejection message from errors.py — none for an
    # accepted share.
    #
    # Used by:
    #   - families/cryptonote/connection.py — handle_submit()
    ############################################################

    async def process_share(self, client, job_id: str, nonce: str,
                            result_hex: str) -> Tuple[bool, Optional[str]]:
        self.shares_submitted += 1

        try:
            # STEP 1: the exact job this share belongs to, then the
            # cheap gates — current height, nonce shape, no replay —
            # before any hashing work
            # ======================================================
            job = self.job_manager.get(job_id)
            if not job or job["client"] is not client:
                self.shares_rejected += 1
                print(f"[SHARE] Unknown/foreign job id {job_id}; rejecting")
                return False, errors.ERROR_INVALID_JOB

            template = self.job_manager.template
            if template is None or job["height"] != template["height"]:
                self.shares_rejected += 1
                print(f"[SHARE] Stale share for height {job['height']}; rejecting")
                return False, errors.ERROR_BLOCK_EXPIRED

            if len(nonce) != 8 or any(c not in "0123456789abcdefABCDEF" for c in nonce):
                self.shares_rejected += 1
                return False, errors.ERROR_MALFORMED_NONCE

            if not self.job_manager.register_nonce(job, nonce):
                self.shares_rejected += 1
                print(f"[SHARE] Duplicate nonce {nonce} for job {job_id}; rejecting")
                return False, errors.ERROR_DUPLICATE_SHARE

            display.debug_box("DEBUG - Job and share details comparison", [
                "Job ID: ".ljust(25) +             job_id,
                "Job height: ".ljust(25) +         str(job["height"]),
                "Job extranonce: ".ljust(25) +     job["extranonce"].hex(),
                "Job pool difficulty: ".ljust(25) + str(job["pool_difficulty"]),
                "Job target: ".ljust(25) +         job["target"],
                "Miner nonce: ".ljust(25) +        nonce,
                "Miner claimed result: ".ljust(25) + result_hex,
            ], color="red")


            # STEP 2: recompute the PoW hash of exactly what the
            # miner hashed (in the executor — ~100 ms of C); the
            # claimed result must match it
            # ==================================================
            nonced_blob = with_nonce(job["hashing_blob"], bytes.fromhex(nonce),
                                     job["nonce_offset"])
            variant = coins.active().cn_variant
            loop = asyncio.get_running_loop()
            pow_hash = await loop.run_in_executor(None, cn_slow_hash, nonced_blob, variant)

            if pow_hash.hex() != result_hex.lower():
                self.shares_rejected += 1
                print(f"[SHARE] Result hash mismatch from {client.client_ip} "
                      f"(claimed {result_hex[:16]}..., computed {pow_hash.hex()[:16]}...)")
                return False, errors.ERROR_INVALID_SHARE


            # STEP 3: judge against the difficulty snapshot THIS job
            # was issued under; a hash that also meets the network
            # difficulty is a block, submitted in the background
            # ======================================================
            # BUG (documented, not fixed): a block is only looked for
            # among accepted shares. With POLL_DIFF_DROPPER off and the
            # pool difficulty above the network's, a hash that meets
            # the network difficulty but not the pool's is refused as
            # low difficulty and the block it solves is never
            # submitted — the Bitcoin family's process_share() judges
            # the block on its own for exactly this case.
            is_accepted = hash_meets_difficulty(pow_hash, job["pool_difficulty"])
            is_block = is_accepted and hash_meets_difficulty(pow_hash, job["network_difficulty"])

            if is_accepted:
                self.shares_accepted += 1
            else:
                self.shares_rejected += 1

            display.cn_share_result_panel(
                is_accepted=is_accepted,
                is_block=is_block,
                job_id=job_id,
                height=job["height"],
                worker=client.worker_name or client.client_ip,
                pow_hash=pow_hash.hex(),
                pool_difficulty=job["pool_difficulty"],
                network_difficulty=job["network_difficulty"],
            )

            if is_block:
                self._start_block_submission(job, nonce)

            return is_accepted, (None if is_accepted else errors.ERROR_LOW_DIFFICULTY)

        except Exception as e:
            self.shares_rejected += 1
            print(f"[ERROR] Share processing failed: {e}")
            import traceback
            traceback.print_exc()
            return False, errors.ERROR_INVALID_SHARE

        finally:
            self._print_stats()






    ############################################################
    # _start_block_submission
    ############################################################
    #
    # Launches the submission of a solved block as a background
    # task, with the same one-submission-per-parent sibling
    # guard as the Bitcoin family (see its server.py for the
    # full rationale), keyed by the job's prev_hash and
    # remembering the last MAX_SUBMITTED_PARENTS parents.
    # Returns whether a submission was launched — nothing
    # reads that at the moment, process_share() ignores it.
    #
    # Used by:
    #   - families/cryptonote/server.py — process_share()
    ############################################################

    def _start_block_submission(self, job: Dict, nonce: str) -> bool:
        parent = job["prev_hash"]

        if parent in self.submitted_parents:
            print("[SUBMIT] ⏭️  Sibling block NOT submitted: a block on this parent was "
                  "already sent to the node. Share stays accepted.")
            return False

        self.submitted_parents[parent] = True
        while len(self.submitted_parents) > MAX_SUBMITTED_PARENTS:
            del self.submitted_parents[next(iter(self.submitted_parents))]

        self._spawn(self._submit_block_task(job, nonce))
        return True






    ############################################################
    # _submit_block_task
    ############################################################
    #
    # The background half: submit, and on acceptance count the
    # block and immediately cut the next job (submitblock only
    # returns after the daemon connected the block, so the
    # next template already builds on it). On failure unmark
    # the parent so a later solve may try again.
    #
    # Used by:
    #   - families/cryptonote/server.py — _start_block_submission()
    ############################################################

    async def _submit_block_task(self, job: Dict, nonce: str) -> None:
        if await self._submit_block(job, nonce):
            self.blocks_found += 1
            self._print_stats()
            await self.create_job()
        else:
            self.submitted_parents.pop(job["prev_hash"], None)






    ############################################################
    # _submit_block
    ############################################################
    #
    # Assembles the full block: the job's template blob (which
    # already carries this client's extranonce) with the
    # winning nonce written into the header. The daemon
    # accepts with a status of OK; any other answer, or an
    # in-band error (raised by MoneroRPC.call), is logged and
    # counts as a rejection.
    #
    # Used by:
    #   - families/cryptonote/server.py — _submit_block_task()
    ############################################################

    async def _submit_block(self, job: Dict, nonce: str) -> bool:
        try:
            block_blob = with_nonce(job["template_blob"], bytes.fromhex(nonce),
                                    job["nonce_offset"])

            print(f"[SUBMIT] Submitting block at height {job['height']} "
                  f"(id {block_id(block_blob).hex()[:16]}...) to the network...")
            result = await self.rpc.call("submitblock", [block_blob.hex()])

            if result and result.get("status") == "OK":
                print(f"[SUBMIT] ✅ Block at height {job['height']} ACCEPTED by network!")
                return True

            print(f"[SUBMIT] ❌ Block REJECTED: {result}")
            return False

        except Exception as e:
            print(f"[SUBMIT] ❌ Block submission error: {e}")
            import traceback
            traceback.print_exc()
            return False
