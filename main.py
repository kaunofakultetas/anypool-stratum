#!/usr/bin/env python3
"""
AnyPool - Stratum Mining Pool Server
"""

import os
import json
import asyncio
import aiohttp
import hashlib
import struct
import random
from typing import List, Optional, Dict, Any, Tuple
import scrypt
from pyboxen import boxen
from datetime import datetime




# Configuration
RPC_HOST = os.getenv("RPC_HOST", "127.0.0.1")
RPC_PORT = int(os.getenv("RPC_PORT", "19332"))
RPC_USER = os.getenv("RPC_USER", "admin")
RPC_PASS = os.getenv("RPC_PASS", "admin")
REWARD_ADDR = os.getenv("REWARD_ADDR")
STRATUM_PORT = int(os.getenv("STRATUM_PORT", "3333"))
POOL_DIFFICULTY = int(os.getenv("POOL_DIFFICULTY", "2048"))
POLL_DIFF_DROPPER = os.getenv("POLL_DIFF_DROPPER", "false").lower() == "true"
COINBASE_MESSAGE = os.getenv("COINBASE_MESSAGE", "/AnyPool by VU Kaunas faculty/")
DEBUG = os.getenv("DEBUG", "false").lower() == "true"

RPC_URL = f"http://{RPC_HOST}:{RPC_PORT}"





class StratumUtils:


    @staticmethod
    def sha256d(data: bytes) -> bytes:
        """Double SHA256"""
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()



    @staticmethod
    def ltc_pow_hash(header_bytes: bytes) -> str:
        """Calculates the Scrypt hash for a block header."""
        if len(header_bytes) != 80:
            raise ValueError("Header must be 80 bytes for Scrypt hashing.")

        return scrypt.hash(header_bytes, header_bytes, 1024, 1, 1, 32)[::-1].hex()




    @staticmethod
    def calculate_txid(tx_hex: str) -> str:
        """Calculate TXID (without witness data) - little-endian format"""
        tx_bytes = bytes.fromhex(tx_hex)
        txid_bytes = StratumUtils.sha256d(tx_bytes)
        return txid_bytes[::-1].hex()  # Reverse for little-endian display



    @staticmethod
    def reverse_hex(hex_str: str) -> str:
        """
        Reverse hex string in 2-char chunks

        INPUT:
        +---------------------------------------+
        | 01 | 23 | 45 | 67 | 89 | AB | CD | EF |
        +---------------------------------------+
            
        OUTPUT:
        +---------------------------------------+
        | EF | CD | AB | 89 | 67 | 45 | 23 | 01 |
        +---------------------------------------+
        """
        return ''.join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)]))



    @staticmethod
    def reverse_hex_4b_chunks(hex_str: str) -> str:
        """
        Reverse hex string in 4-byte chunks
        
        INPUT:
        +---------------------------------------------------------------------------------------+
        | 01234567 | 89ABCDEF | 76543210 | FEDCBA98 | 0123ABCD | EF012345 | 6789ABCD | FEDCBA98 |
        +---------------------------------------------------------------------------------------+
              |         |          |          |          |          |          |          |
            FLIP      FLIP       FLIP       FLIP       FLIP       FLIP       FLIP       FLIP
              V         |          |          |          |          |          |          |
        OUTPUT:         V          V          V          V          V          V          V
        +---------------------------------------------------------------------------------------+
        | 67452301 | EFCDAB89 | 10325476 | 98BCDCFE | CDAB2301 | 452301EF | CDAB8967 | 98BADCFE |
        +---------------------------------------------------------------------------------------+
        """
        hex_str_final = ""
        for i in range(0, 64, 8):  # Process 4-byte chunks (8 hex chars each)
            chunk = hex_str[i:i+8]
            hex_str_final += StratumUtils.reverse_hex(chunk)
        return hex_str_final







class MerkleTree:

    @staticmethod
    def calculate_merkle_branch(tx_hashes_be: List[str], index_to_prove: int) -> List[str]:
        """
        Calculates the merkle branch for a transaction at a given index.
        Uses proven algorithm with proper endianness handling.
        """
        if not tx_hashes_be:
            return []

        # Start with all txids as raw bytes (NO endianness conversion for hashing)
        level = [bytes.fromhex(txid) for txid in tx_hashes_be]
        branch = []
        idx = index_to_prove

        while len(level) > 1:
            # Pad to even count
            if len(level) % 2 == 1:
                level.append(level[-1])

            # Find sibling using XOR operation
            sibling_idx = idx ^ 1
            if sibling_idx < len(level):
                # Store sibling as hex for branch
                sibling_hex = level[sibling_idx].hex()
                branch.append(sibling_hex)

            # Build next level
            next_level = []
            for i in range(0, len(level), 2):
                combined = level[i] + level[i + 1]
                next_level.append(StratumUtils.sha256d(combined))

            level = next_level
            idx //= 2

        return branch



    @staticmethod
    def calculate_merkle_root_from_branch(leaf_hex: str, branch: List[str], index: int) -> str:
        """
        Correctly calculates a merkle root from a leaf, its branch, and its index.
        Uses proven algorithm with proper endianness handling.
        """
        # Start with leaf as raw bytes (NO endianness conversion for hashing)
        current = bytes.fromhex(leaf_hex)
        
        for sibling_hex in branch:
            sibling = bytes.fromhex(sibling_hex)  # Raw bytes, no conversion
            if index % 2 == 1:
                combined = sibling + current
            else:
                combined = current + sibling
            current = StratumUtils.sha256d(combined)
            index //= 2
        
        # Return as little-endian hex (header format)
        return current.hex()




def validate_share_params(params: List) -> bool:
    """Validate share submission parameters"""
    if len(params) != 5:
        return False
    
    worker_name, job_id, extra_nonce2, ntime, nonce = params
    
    try:
        # Validate hex parameters
        int(extra_nonce2, 16)
        int(ntime, 16)
        int(nonce, 16)
        
        # Validate lengths
        if len(extra_nonce2) != 8:  # 4 bytes
            return False
        if len(ntime) != 8:  # 4 bytes
            return False
        if len(nonce) != 8:  # 4 bytes
            return False
            
        return True
        
    except (ValueError, TypeError):
        return False



class ShareValidator:
    """Validates shares using the proven legacy miner hash method"""
    


    @staticmethod
    def validate_share(job: Dict, extra_nonce1: str, extra_nonce2: str, ntime: str, nonce: str) -> Tuple[str, bytes, str]:
        """Validate miner provided mined share"""
        
        # Step 1: Reconstruct the full coinbase transaction
        coinbase_full = job["coinb1"] + extra_nonce1 + extra_nonce2 + job["coinb2"]
        
        # Calculate coinbase TXID in LE format (raw SHA256 bytes)
        coinbase_txid_le = StratumUtils.sha256d(bytes.fromhex(coinbase_full)).hex()
        coinbase_txid_be = coinbase_txid_le[::-1]  # For display purposes


        if(DEBUG):
            print(
                boxen(
                    "Coinb1: ".ljust(15) + job["coinb1"],
                    "Extra Nonce 1: ".ljust(15) + extra_nonce1,
                    "Extra Nonce 2: ".ljust(15) + extra_nonce2,
                    "Coinb2: ".ljust(15) + job["coinb2"],
                    "",
                    "Coinbase: ".ljust(15) + coinbase_full,
                    "Coinbase TXID: ".ljust(15) + coinbase_txid_be,
                    title="Coinbase Elements as concatenated in validate_share()",
                    color="blue",
                    padding=(0, 3, 0, 3),
                )
            )



        # Step 2: Calculate merkle root using LE format
        merkle_root_le = MerkleTree.calculate_merkle_root_from_branch(
            coinbase_txid_le, job["merkle_branch"], 0
        )
        merkle_root_binary = bytes.fromhex(merkle_root_le)
        

        if(DEBUG):
            print(
                boxen(
                    "Coinbase TXID: ".ljust(25) + coinbase_txid_be,
                    "Merkle Branch: ".ljust(25) + str(job["merkle_branch"]),
                    "",
                    "Calculated Merkle Root: ".ljust(25) + merkle_root_le,
                    title="Merkle Root Elements as passed in calculate_merkle_root_from_branch() in validate_share()",
                    color="blue",
                    padding=(0, 3, 0, 3),
                )
            )



        # Step 3: Build header using simplified mixed endianness method
        version_final = StratumUtils.reverse_hex(job["version"])
        prevhash_final = StratumUtils.reverse_hex_4b_chunks(job["prevhash"])
        merkle_final = merkle_root_binary.hex()
        ntime_final = StratumUtils.reverse_hex(ntime)
        nbits_final = StratumUtils.reverse_hex(job["nbits"])
        nonce_final = StratumUtils.reverse_hex(nonce)
        


        # Step 4: Build header using simple hex concatenation
        header_hex = version_final + prevhash_final + merkle_final + ntime_final + nbits_final + nonce_final
        header_bytes = bytes.fromhex(header_hex)



        # Step 5: Calculate the Scrypt hash
        scrypt_hash_hex = StratumUtils.ltc_pow_hash(header_bytes)

        if(DEBUG):
            print(
                boxen(
                    "Version: ".ljust(15) + version_final,
                    "PrevHash: ".ljust(15) + prevhash_final,
                    "Merkle: ".ljust(15) + merkle_final,
                    "NTime: ".ljust(15) + ntime_final,
                    "NBits: ".ljust(15) + nbits_final,
                    "Nonce: ".ljust(15) + nonce_final,
                    "",
                    "Scrypt Hash: ".ljust(15) + scrypt_hash_hex,
                    title="Header Elements as Concatenated in Validate Share",
                    color="blue",
                    padding=(0, 3, 0, 3),
                )
            )

        return scrypt_hash_hex, header_bytes, coinbase_full
           






class StratumServer:


    def __init__(self):
        self.extranonce1_counter = 0
        self.current_job = None
        self.job_counter = 0
        self.shares_submitted = 0
        self.shares_accepted = 0
        self.shares_rejected = 0
        self.blocks_found = 0

        self.difficulty_1_target = 0x0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

        self.network_difficulty = None
        self.network_target = None
        
        self.pool_difficulty = POOL_DIFFICULTY
        self.pool_target = self.calculate_mining_target(POOL_DIFFICULTY)
        

        self.previous_job = None
        self.connected_clients = set()
        self.last_block_hash = None
        self.job_seq = 0
        self.jobs = {}
        

        print("")
        print(
            boxen(
                "Coin: ".ljust(20) +                "Litecoin (LTC)",
                "RPC: ".ljust(20) +                 RPC_URL,
                "Port: ".ljust(20) +                str(STRATUM_PORT),
                "Reward Address: ".ljust(20) +      REWARD_ADDR,
                "Pool Difficulty: ".ljust(20) +     str(self.pool_difficulty),

                title="AnyPool - Stratum Server ⚙️   ⚙️   ⚙️  ",
                color="green",
                padding=1,
            )
        )



    def calculate_mining_target(self, difficulty: int) -> int:
        """Calculate miner target from difficulty"""
        target = self.difficulty_1_target // difficulty
        return target


    def calculate_mining_difficulty(self, target: int) -> int:
        """Calculate difficulty from target"""
        difficulty = self.difficulty_1_target // target
        return difficulty



    def add_client(self, client):
        """Add client to broadcast list"""
        self.connected_clients.add(client)
        print(f"[CLIENTS] Added client. Total: {len(self.connected_clients)}")
    


    def remove_client(self, client):
        """Remove client from broadcast list"""
        self.connected_clients.discard(client)
        print(f"[CLIENTS] Removed client. Total: {len(self.connected_clients)}")
    


    async def broadcast_new_job(self):
        """Send new job to all connected clients"""
        if not self.current_job or not self.connected_clients:
            return

        # Make a copy to avoid modification during iteration
        clients_to_broadcast = list(self.connected_clients)
        disconnected_clients = set()


        # Step 1: Get current job and construct notification parameters
        job = self.current_job
        notification_params = [
            job["job_id"], job["prevhash"], job["coinb1"], job["coinb2"],
            job["merkle_branch"], job["version"], job["nbits"], job["ntime"], True
        ]


        # Step 2: Send difficulty and job to all clients (sequentially to catch errors)
        for client in clients_to_broadcast:
            try:
                # Send difficulty first
                await client.send_notification("mining.set_difficulty", [self.pool_difficulty])
                # Then send job
                await client.send_notification("mining.notify", notification_params)
            except Exception as e:
                print(f"[BROADCAST] Failed to send to client: {e}")
                disconnected_clients.add(client)


        # Step 3: Remove disconnected clients
        for client in disconnected_clients:
            self.remove_client(client)
        if(len(disconnected_clients) > 0):
            print(f"[BROADCAST] Removed {len(disconnected_clients)} disconnected clients")


        # Step 4: Print broadcasted job details to connected clients
        if self.connected_clients:
            to_print = [""]
            to_print.append(f"JOB ID: {job['job_id'].ljust(20)}")
            to_print.append("")

            for client in self.connected_clients:
                to_print.append(f"Miner:    " +   f"IP Address:    {client.client_ip}".ljust(35) +       f"- Soft: {client.miner_software}".ljust(25) +      f"- Worker: {client.worker_name}".ljust(25)     )
                to_print.append(f"Job:      " +   f"Extra Nonce 1: {client.extra_nonce1}".ljust(35))
                to_print.append("")
            print()
            print(
                boxen(
                    "\n".join(to_print),
                    title=f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Job broadcasted to connected clients",
                    color="green",
                    padding=(0, 3, 0, 3),
                )
            )


    


    async def rpc_call(self, method: str, params: List = None) -> Dict:
        """Make RPC call to Litecoin node"""
        if params is None:
            params = []
            
        payload = {
            "jsonrpc": "1.0",
            "id": "stratum",
            "method": method,
            "params": params
        }
        
        auth = aiohttp.BasicAuth(RPC_USER, RPC_PASS)
        async with aiohttp.ClientSession(auth=auth) as session:
            async with session.post(RPC_URL, json=payload) as resp:
                data = await resp.json()
                if "error" in data and data["error"]:
                    raise Exception(f"RPC Error: {data['error']}")
                return data["result"]



    def _build_segwit_coinbase_parts(self, template):
        """Builds the coinb1 and coinb2 parts for a SegWit coinbase transaction."""
        reward_addr = REWARD_ADDR
        
        def to_varint(i):
            if i < 0xfd:
                return f"{i:02x}"
            elif i <= 0xffff:
                return "fd" + struct.pack('<H', i).hex()
            elif i <= 0xffffffff:
                return "fe" + struct.pack('<I', i).hex()
            else:
                return "ff" + struct.pack('<Q', i).hex()

        def bip34_height_push(height: int) -> bytes:
            b = height.to_bytes(4, 'little').rstrip(b'\x00') or b'\x00'
            return bytes([len(b)]) + b

        def p2wpkh_script_for_address(addr: str) -> str:
            # Your existing bech32 decoding logic
            CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
            CHARKEY = {c: i for i, c in enumerate(CHARSET)}
            
            def bech32_polymod(values):
                GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
                chk = 1
                for v in values:
                    b = (chk >> 25) & 0xff
                    chk = ((chk & 0x1ffffff) << 5) ^ v
                    for i in range(5):
                        if (b >> i) & 1:
                            chk ^= GEN[i]
                return chk

            def bech32_hrp_expand(hrp):
                return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

            def bech32_verify_checksum(hrp, data):
                return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1

            def bech32_decode(addr):
                addr = addr.strip()
                if any(ord(x) < 33 or ord(x) > 126 for x in addr):
                    return None, None
                if addr.lower() != addr and addr.upper() != addr:
                    return None, None
                addr = addr.lower()
                if '1' not in addr:
                    return None, None
                pos = addr.rfind('1')
                hrp, data = addr[:pos], addr[pos+1:]
                if len(data) < 6:
                    return None, None
                try:
                    decoded = [CHARKEY[c] for c in data]
                except KeyError:
                    return None, None
                if not bech32_verify_checksum(hrp, decoded):
                    return None, None
                return hrp, decoded[:-6]

            def convertbits(data, frombits, tobits, pad=True):
                acc = 0
                bits = 0
                ret = []
                maxv = (1 << tobits) - 1
                for value in data:
                    if value < 0 or (value >> frombits):
                        return None
                    acc = (acc << frombits) | value
                    bits += frombits
                    while bits >= tobits:
                        bits -= tobits
                        ret.append((acc >> bits) & maxv)
                if pad and bits:
                    ret.append((acc << (tobits - bits)) & maxv)
                elif not pad and (bits >= frombits or ((acc << (tobits - bits)) & maxv)):
                    return None
                return ret

            hrp, data = bech32_decode(addr)
            if hrp not in ("ltc", "tltc") or data is None:
                raise ValueError("Invalid bech32 address for Litecoin network")
            witver = data[0]
            prog5 = data[1:]
            prog = bytes(convertbits(prog5, 5, 8, False))
            if witver != 0 or len(prog) != 20:
                raise ValueError("Only v0 P2WPKH supported")
            return "0014" + prog.hex()

        # Build coinbase components
        height = int(template["height"])
        coinbase_value = int(template["coinbasevalue"])
        message_bytes = COINBASE_MESSAGE.encode('utf-8')

        witness_commitment_hex = template.get("default_witness_commitment")
        has_witness = witness_commitment_hex is not None


        # Common parts
        version_le = "01000000"
        input_count = "01"
        prevout_hash = "00" * 32
        prevout_index = "ffffffff"
        sequence = "ffffffff"
        locktime = "00000000"

        # Build scriptSig
        height_push = bip34_height_push(height)
        scriptsig_len = len(height_push) + 4 + 4 + len(message_bytes)
        scriptsig_len_vi = to_varint(scriptsig_len)

        # Build outputs
        outputs = []
        
        # Output 0 (Payout)
        payout_script = p2wpkh_script_for_address(reward_addr)
        payout_output = (
            struct.pack('<Q', coinbase_value).hex() +
            to_varint(len(bytes.fromhex(payout_script))) +
            payout_script
        )
        outputs.append(payout_output)

        # Output 1 (Witness Commitment) - always include if template provides it
        if witness_commitment_hex:
            witness_output = (
                "0000000000000000" +
                to_varint(len(bytes.fromhex(witness_commitment_hex))) +
                witness_commitment_hex  # Use as-is from template
            )
            outputs.append(witness_output)

        output_count_vi = to_varint(len(outputs))

        # Build TXID version (always without witness)
        coinb1_txid = version_le + input_count + prevout_hash + prevout_index + scriptsig_len_vi + height_push.hex()
        coinb2_txid = (
            message_bytes.hex() +
            sequence +
            output_count_vi +
            "".join(outputs) +
            locktime
        )
        
        # Build full version (with witness only if needed)
        if has_witness:
            # SegWit version with witness data
            coinb1_full = version_le + "00" + "01" + input_count + prevout_hash + prevout_index + scriptsig_len_vi + height_push.hex()
            coinb2_full = (
                message_bytes.hex() +
                sequence +
                output_count_vi +
                "".join(outputs) +
                "01200000000000000000000000000000000000000000000000000000000000000000" +  # witness stack
                locktime
            )
        else:
            # Non-SegWit version (same as TXID)
            coinb1_full = coinb1_txid
            coinb2_full = coinb2_txid
        


        if(DEBUG):
            print(
                boxen(
                    "Height:".ljust(25) +                   str(height),
                    "Coinbase value:".ljust(25) +           str(coinbase_value),
                    "Message bytes:".ljust(25) +            str(message_bytes),
                    "Witness commitment hex:".ljust(25) +   str(witness_commitment_hex),
                    "Has witness:".ljust(25) +              str(has_witness),
                    title="Coinbase components",
                    color="blue",
                    padding=(0, 3, 0, 3),
                )
            )

        # Return both versions
        return {
            "coinb1_txid": coinb1_txid,
            "coinb2_txid": coinb2_txid,
            "coinb1_full": coinb1_full,
            "coinb2_full": coinb2_full
        }



    async def create_job(self) -> Dict:
        """
        Creates a new mining job from a getblocktemplate call.
        This function is the heart of the stratum server, responsible for
        assembling all the necessary components for a miner to start hashing.
        """

        # Ensure job storage is initialized
        if not hasattr(self, "jobs"):
            self.jobs = {}
        if not hasattr(self, "job_seq"):
            self.job_seq = 0

        try:
            template = await self.rpc_call("getblocktemplate", [{"rules": ["segwit", "mweb"]}])
            if not template or "previousblockhash" not in template:
                print(f"[ERROR] Invalid block template: {template}")
                return None

            # Step 1: CRITICAL: Prepare data in the exact format needed for validation
            # Previous hash: getblocktemplate returns big-endian, we need little-endian for header
            prevhash_be = template["previousblockhash"]
            prevhash_le = StratumUtils.reverse_hex(prevhash_be)
            prevhash_final = StratumUtils.reverse_hex_4b_chunks(prevhash_le)

            version_be = f"{template['version']:08x}"
            nbits_be = f"{int(template["bits"], 16):08x}"
            ntime_be = f"{template['curtime']:08x}"



            
            # Step 2: Check if the proposed block from full node has the same data as the current job
            #         We need to avoid creating a new job if the block hasn't changed
            #         If nothing has changed, we can just return the current job
            if ( self.current_job != None ):
                if(
                        self.current_job.get("prevhash") == prevhash_final
                    and self.current_job.get("template").get("mweb") == template.get("mweb")
                    and self.network_target == int(template["target"], 16)
                ):
                    return self.current_job
            self.prevhash = prevhash_final



            # Step 3: Update network and pool difficulties and targets
            self.network_target = int(template["target"], 16)
            self.network_difficulty = self.calculate_mining_difficulty(int(template["target"], 16))
            self.pool_target = self.calculate_mining_target(POOL_DIFFICULTY)
            self.pool_difficulty = POOL_DIFFICULTY

            # If network diff drops below pool difficulty, use network diff for pool
            if(POLL_DIFF_DROPPER):
                if(self.network_difficulty < POOL_DIFFICULTY): 
                    self.pool_difficulty = self.network_difficulty
                    self.pool_target = self.network_target

            print()
            print(
                boxen(
                    "Height: ".ljust(10) +  str(template["height"] - 1),
                    "SHA256: ".ljust(10) +    template["previousblockhash"],
                    title=f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - New Block Detected  📦  📦  📦 ",
                    color="green",
                    padding=1,
                )
            )

            # Step 4: Include ALL transactions from template (not just MWEB)
            template_txs = template.get("transactions", [])
            template_txids_be = [t["txid"] for t in template_txs]
            template_txids_le = [bytes.fromhex(txid)[::-1].hex() for txid in template_txids_be]
            
            if(DEBUG):
                print(
                    boxen(
                        "Total transactions in template: ".ljust(35) + str(len(template_txs)),
                        title="DEBUG - StratumServer.create_job()",
                        color="blue",
                        padding=(0, 3, 0, 3),
                    )
                )            
            
            # Build coinbase and calculate merkle branch with ALL transactions
            coinbase_parts = self._build_segwit_coinbase_parts(template)
            # Use placeholder for merkle calculation (each client will have unique extranonce1)
            placeholder_extranonce1 = "00000000"  # 8-char placeholder
            placeholder_coinbase_hex = coinbase_parts["coinb1_txid"] + placeholder_extranonce1 + ("00" * 4) + coinbase_parts["coinb2_txid"]
            
            # Calculate coinbase TXID in LE format (raw SHA256 bytes)
            coinbase_txid_le = StratumUtils.sha256d(bytes.fromhex(placeholder_coinbase_hex)).hex()
            coinbase_txid_be = coinbase_txid_le[::-1]  # For display purposes
            
            
            # Use LE format for merkle calculation with ORIGINAL transaction hashes
            all_txids_le = [coinbase_txid_le] + template_txids_le
            if(DEBUG):
                print(f"[DEBUG] [JOB] All txids (LE, original): {all_txids_le}")

            # Always use the proven merkle branch calculation
            merkle_branch_le = MerkleTree.calculate_merkle_branch(all_txids_le, 0)

            if(DEBUG):
                print(
                    boxen(
                        "Coinbase txid (placeholder): ".ljust(35) + coinbase_txid_be,
                        "All txids: ".ljust(35) + str(all_txids_le),
                        "Calculated merkle branch: ".ljust(35) + str(merkle_branch_le),
                        title="DEBUG - StratumServer.create_job()",
                        color="red",
                        padding=(0, 3, 0, 3),
                    )
                )

            self.job_seq += 1
            job_id = f"{self.job_seq:08x}"

            # Change the job storage to use miner format (LE):
            job = {
                "job_id": job_id,
                "prevhash": prevhash_final,
                "coinb1": coinbase_parts["coinb1_txid"],  # For stratum protocol (TXID version)
                "coinb2": coinbase_parts["coinb2_txid"],  # For stratum protocol (TXID version)
                "coinb1_full": coinbase_parts["coinb1_full"],  # For block submission (with witness)
                "coinb2_full": coinbase_parts["coinb2_full"],  # For block submission (with witness)
                "merkle_branch": merkle_branch_le,
                "version": version_be,
                "nbits": nbits_be,
                "ntime": ntime_be,
                "height": template["height"],

                # FOR BLOCK SUBMISSION:
                "template": template,
            }

            # In create_job(), before storing the job:
            if job_id in self.jobs:
                old_merkle = self.jobs[job_id].get('merkle_branch', [])
                print(f"[WARNING] Overwriting existing job {job_id}!")
                print(f"[WARNING] Old merkle: {old_merkle}")
                print(f"[WARNING] New merkle: {merkle_branch_le}")

            self.jobs[job_id] = job
            self.current_job = job

            if self.connected_clients:
                print(f"[BROADCAST] BROADCASTING NEW JOB to {len(self.connected_clients)} clients...")
                asyncio.create_task(self.broadcast_new_job())

            times_easier = int(self.network_difficulty / self.pool_difficulty)
            print()
            print(
                boxen(
                    f"JOB DETAILS:",
                    f"Job ID:".ljust(30) +                      job_id,
                    f"Job prevhash:".ljust(30) +                template["previousblockhash"],
                    f"Job nbits:".ljust(30) +                   f"{int(template["bits"], 16):08x}",
                    f"Job ntime:".ljust(30) +                   f"{template['curtime']:08x}",
                    f"Job merkle branch count:".ljust(30) +     str(len(job.get('merkle_branch', 'MISSING'))),
                    f"",
                    f"DIFFICULTY:",
                    f"Pool Difficulty:".ljust(30) +             f"{self.pool_difficulty:,} {f"(Pool is {times_easier:,}x easier)" if times_easier > 1 else ""}",
                    f"Network Difficulty:".ljust(30) +          f"{self.network_difficulty:,}",
                    f"",
                    f"TARGETS:",
                    f"Pool Target:".ljust(30) +                 f"{self.pool_target:064x}",
                    f"Network Target:".ljust(30) +              f"{self.network_target:064x}",

                    title=f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - New Mining Job Created and Broadcasted to Miners  ⛏️   ⛏️   ⛏️  ",
                    title_alignment="left",
                    text_alignment="left",
                    color="green",
                    padding=(0, 3, 0, 3),
                )
            )

            # Add debugging to track job storage
            if(DEBUG):
                print(f"[DEBUG] [JOB] STORED job {job_id} with merkle_branch: {job['merkle_branch']}")
                print(f"[DEBUG] [JOB] Total jobs in memory: {len(self.jobs)}")
                print(f"[DEBUG] [JOB] Job keys: {list(self.jobs.keys())}")
                print(f"[DEBUG] [JOB] Height: {job['height']}")
                print(f"[DEBUG] [JOB] Transactions: {len(all_txids_le)} + 1 coinbase")

            return job
        except Exception as e:
            print(f"[ERROR] Failed to create job: {e}")
            return None



    async def process_share(self, worker_name: str, job_id: str, extra_nonce1: str, extra_nonce2: str, ntime: str, nonce: str) -> bool:
        """Process submitted share from a miner with proper job matching"""
        self.shares_submitted += 1

        try:
            job = self.jobs.get(job_id)

            if(DEBUG):
                print()
                print(
                    boxen(
                        f"Job ID: ".ljust(25) +             job_id,
                        f"Job prevhash: ".ljust(25) +       job.get('prevhash', 'MISSING'),
                        f"Job nbits: ".ljust(25) +          job.get('nbits', 'MISSING'),
                        f"Job ntime: ".ljust(25) +          job.get('ntime', 'MISSING'),
                        f"Job merkle branch: ".ljust(25) +  str(job.get('merkle_branch', 'MISSING')),
                        f"Miner extra nonce1: ".ljust(25) + extra_nonce1,
                        f"Miner extra nonce2: ".ljust(25) + extra_nonce2,
                        f"Miner ntime: ".ljust(25) +        ntime,
                        f"Miner nonce: ".ljust(25) +        nonce,
                        title="DEBUG - Job and share details comparison",
                        title_alignment="left",
                        color="red",
                        padding=(0, 3, 0, 3),
                    )
                )


            if not job:
                print("[SHARE] Stale/unknown job_id; rejecting")
                return False



            # Step 1: Validate share using the EXACT job the miner worked on
            result_hash, header_bytes, coinbase_hex = ShareValidator.validate_share(
                job, extra_nonce1, extra_nonce2, ntime, nonce
            )
            

            # Step 2: If validation failed, reject share
            if not result_hash:
                self.shares_rejected += 1
                print(f"[SHARE] REJECTED - Validation failed")
                return False


            # Step 3: Check against pool and network targets
            print()
            to_print = []
            is_accepted = False
            is_network_acceptable = False
            if int(result_hash, 16) <= self.pool_target:
                self.shares_accepted += 1
                is_accepted = True
                
                if int(result_hash, 16) <= self.network_target:
                    to_print.append(" --- YOUR MINER HAS FOUND A NEW BLOCK! 🎉🎉🎉🎉 ✅✅✅✅ ---")
                    to_print.append(f"Share Status: 🎉 FOUND A BLOCK! 🎉")
                    is_network_acceptable = True

                else:
                    to_print.append(" --- Your miner found a share, but it's not a block. Keep mining!")
                    to_print.append(f"Share Status: ✅ ACCEPTED (NOT A BLOCK)")
                    
            else:
                self.shares_rejected += 1
                to_print.append(f"Share Status: ❌ REJECTED - Hash too high")

            prevhash_display = StratumUtils.reverse_hex_4b_chunks(StratumUtils.reverse_hex(job['prevhash']))
            to_print.append("")
            to_print.append(f"Job ID:".ljust(25) +                  f"{job_id}")
            to_print.append(f"Mined for Height:".ljust(25) +        f"{job['height']}")
            to_print.append("")
            to_print.append(f"Scrypt Hash:".ljust(25) +             f"{result_hash}")
            to_print.append(f"Pool Target:".ljust(25) +             f"{self.pool_target:064x}")
            to_print.append(f"Network Target:".ljust(25) +          f"{self.network_target:064x}")
            to_print.append("")
            to_print.append(f"Pool Difficulty:".ljust(25) +         f"{self.pool_difficulty:,}")
            to_print.append(f"Network Difficulty:".ljust(25) +      f"{self.network_difficulty:,}")
            to_print.append("")
            to_print.append(f"SHA256 Previous Hash:".ljust(25) +    f"{prevhash_display}")
            to_print.append(f"SHA256 Hash:".ljust(25) +             StratumUtils.sha256d(header_bytes)[::-1].hex())
            to_print.append(f"Proposed block Height:".ljust(25) +   f"{job['height']}")

            print(
                boxen(
                    "\n".join(to_print),
                    title=f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Mined share validation result 👷  👷  👷 ",
                    color="green" if is_accepted else "red",
                    padding=1,
                )
            )


            # Step 4: Submit block to network if it has low enough hash
            if(is_network_acceptable):
                if await self._submit_block(job, extra_nonce1, extra_nonce2, ntime, nonce, coinbase_hex):
                    self.blocks_found += 1
            
            return is_accepted




        except Exception as e:
            self.shares_rejected += 1
            print(f"[ERROR] Share processing failed: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            if self.shares_submitted > 0:
                print(f"[STATS] Shares: {self.shares_accepted}/{self.shares_submitted} ({100*self.shares_accepted/self.shares_submitted:.1f}%) | Blocks: {self.blocks_found}")






    async def _submit_block(self, job: Dict, extra_nonce1: str, extra_nonce2: str, ntime: str, nonce: str, coinbase_hex: str) -> bool:
        """Submit found block to network using exact test file structure"""
        try:
            print("[SUBMIT] Building block for submission...")
            
            # Step 1: Reconstruct the full coinbase transaction WITH witness data
            coinbase_full_hex = job["coinb1_full"] + extra_nonce1 + extra_nonce2 + job["coinb2_full"]

            # For merkle tree verification, calculate TXID (without witness data)
            coinbase_txid_hex = job["coinb1"] + extra_nonce1 + extra_nonce2 + job["coinb2"]
            coinbase_txid_le = StratumUtils.sha256d(bytes.fromhex(coinbase_txid_hex)).hex()
            coinbase_txid_be = coinbase_txid_le[::-1]  # For display purposes
            

            if(DEBUG):
                print(
                    boxen(
                        "Coinb1: ".ljust(15) + job["coinb1"],
                        "Extra Nonce 1: ".ljust(15) + extra_nonce1,
                        "Extra Nonce 2: ".ljust(15) + extra_nonce2,
                        "Coinb2: ".ljust(15) + job["coinb2"],
                        "",
                        "Coinbase: ".ljust(15) + coinbase_full_hex,
                        "Coinbase TXID: ".ljust(15) + coinbase_txid_be,
                        title="Coinbase Elements as concatenated in _submit_block()",
                        color="blue",
                        padding=(0, 3, 0, 3),
                    )
                )

            
            # Step 2: Calculate merkle root using LE format
            merkle_root_le = MerkleTree.calculate_merkle_root_from_branch(
                coinbase_txid_le, job["merkle_branch"], 0
            )
            merkle_root_binary = bytes.fromhex(merkle_root_le)


            if(DEBUG):
                print(
                    boxen(
                        "Coinbase TXID: ".ljust(25) + coinbase_txid_be,
                        "Merkle Branch: ".ljust(25) + str(job["merkle_branch"]),
                        "",
                        "Calculated Merkle Root: ".ljust(25) + merkle_root_le,
                        title="Merkle Root Elements as passed in calculate_merkle_root_from_branch() in _submit_block()",
                        color="blue",
                        padding=(0, 3, 0, 3),
                    )
                )


            # Step 3: Construct the actual header with our calculated merkle root
            # Based on discovered pattern: LE/BE/LE/BE/LE/BE processing per field
            version_final = StratumUtils.reverse_hex(job["version"]) # Version: LE processing (no change needed)

            # PrevHash: BE processing (reverse each 4-byte chunk)
            prevhash_final = StratumUtils.reverse_hex_4b_chunks(job["prevhash"])

            merkle_final = merkle_root_binary.hex()
            ntime_final = StratumUtils.reverse_hex(ntime)
            nbits_final = StratumUtils.reverse_hex(job["nbits"])
            nonce_final = StratumUtils.reverse_hex(nonce)
            

            # Step 4: Build header using simple hex concatenation
            header_hex = version_final + prevhash_final + merkle_final + ntime_final + nbits_final + nonce_final
            header_bytes = bytes.fromhex(header_hex)


            # Step 5: Calculate the Scrypt hash
            scrypt_hash_hex = StratumUtils.ltc_pow_hash(header_bytes)
            

            if(DEBUG):
                print(
                    boxen(
                        "Version: ".ljust(15) + version_final,
                        "PrevHash: ".ljust(15) + prevhash_final,
                        "Merkle: ".ljust(15) + merkle_final,
                        "NTime: ".ljust(15) + ntime_final,
                        "NBits: ".ljust(15) + nbits_final,
                        "Nonce: ".ljust(15) + nonce_final,
                        "",
                        "Scrypt Hash: ".ljust(15) + scrypt_hash_hex,
                        title="Header Elements as Concatenated in _submit_block()",
                        color="blue",
                        padding=(0, 3, 0, 3),
                    )
                )



            # Construct complete block for submission
            all_txs = job["template"].get("transactions", [])
            all_tx_data_hex = ""
            for tx in all_txs:
                all_tx_data_hex += tx["data"]


            tx_count = f"{len(all_txs) + 1:02x}"
            complete_block = header_hex + tx_count + coinbase_full_hex + all_tx_data_hex + "01" + job["template"].get("mweb", "")

            # Validate if its hex
            if(bytes.fromhex(complete_block)):
                pass # Yes, it is hex

            print("[SUBMIT] Submitting to network...")
            
            # Step 6: Submit the block
            result = await self.rpc_call("submitblock", [complete_block])
            
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



class StratumConnection:


    def __init__(self, reader, writer, server):
        self.reader = reader
        self.writer = writer
        self.server = server
        self.authorized = False
        self.worker_name = None
        
        # Generate UNIQUE extranonce1 for this connection
        self.server.extranonce1_counter += 1
        self.extra_nonce1 = f"{self.server.extranonce1_counter:08x}"
        
        self.client_ip = writer.get_extra_info('peername')[0]
    


    async def handle(self):
        """Handle stratum connection"""
        try:
            self.server.add_client(self)            
            while True:
                try:
                    data = await asyncio.wait_for(self.reader.readline(), timeout=1800.0)
                    
                    if not data:
                        # Client closed connection
                        print(f"[CONNECTION] {self.client_ip} closed connection")
                        break
                    
                    try:
                        raw_message = data.decode().strip()
                        if not raw_message:
                            continue
                            
                        # print(f"[RAW] {client_ip} -> {raw_message}")
                        message = json.loads(raw_message)
                        await self.process_message(message)
                        
                    except json.JSONDecodeError as e:
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
            # Ensure client is always removed
            self.server.remove_client(self)
            try:
                if not self.writer.is_closing():
                    self.writer.close()
                    await self.writer.wait_closed()
            except Exception as e:
                print(f"[CLEANUP] Error closing connection: {e}")
                pass
            # print(f"[CONNECTION] Client {self.client_ip or 'unknown'} disconnected and cleaned up")
    


    async def send_response(self, message_id, result=None, error=None):
        """Send JSON-RPC response"""
        response = {"id": message_id, "result": result, "error": error}
        await self.send_message(response)
    


    async def send_notification(self, method, params):
        """Send JSON-RPC notification"""
        notification = {"id": None, "method": method, "params": params}
        await self.send_message(notification)
    


    async def send_message(self, message):
        """Send message to client with error handling"""
        try:
            data = json.dumps(message) + "\n"
            self.writer.write(data.encode())
            await self.writer.drain()
        except Exception as e:
            # Client disconnected or connection error
            print(f"[SEND] Failed to send message to client: {e}")
            raise  # Re-raise to let caller handle cleanup
    


    async def process_message(self, message):
        """Process incoming stratum message"""
        method = message.get("method")
        params = message.get("params", [])
        msg_id = message.get("id")
        
        # print(f"[DEBUG] {self.client_ip} -> {method}: {params}")
        
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
            if "Broken pipe" not in str(e):
                print(f"[PROCESS] {self.client_ip} error processing (Broken pipe) {method}: {e}")
            else:
                print(f"[PROCESS] {self.client_ip} error processing (Unknown) {method}: {e}")
    


    async def handle_subscribe(self, msg_id, params):
        """Handle mining.subscribe"""
        
        # Extract miner software name from params
        self.miner_software = "Unknown"
        if params and len(params) > 0 and params[0]:
            self.miner_software = params[0]
        print(f"[SUBSCRIBE] {self.client_ip} - {self.miner_software} subscribing")
        

        # Generate unique session ID
        self.subscription_id = f"{random.randint(0, 0xffffffff):08x}"
        # Use THIS client's unique extranonce1
        extra_nonce1 = self.extra_nonce1  # Changed from self.server.extra_nonce1
        extra_nonce2_size = 4
        
        # print(f"[SUBSCRIBE] Sending unique extranonce1: {extra_nonce1}")
        
        response = [[["mining.set_difficulty", self.subscription_id], ["mining.notify", self.subscription_id]], extra_nonce1, extra_nonce2_size]
        await self.send_response(msg_id, response)
        
        # Send difficulty
        await self.send_notification("mining.set_difficulty", [self.server.pool_difficulty])
        
        # Send job
        if not self.server.current_job:
            await self.server.create_job()
        
        if self.server.current_job:
            job = self.server.current_job
            # Assemble params for the miner. It expects a different format from our validator.
            # This is based on cpuminer source: it reverses most fields.
            job_params = [
                job["job_id"], 
                job["prevhash"],        # Already LE - don't reverse
                job["coinb1"], 
                job["coinb2"],
                job["merkle_branch"],
                job["version"],
                job["nbits"],   
                job["ntime"],           # Already LE - don't reverse
                True
            ]
            await self.send_notification("mining.notify", job_params)
            # print(f"[SUBSCRIBE] {self.client_ip} sent job: {job['job_id']}")
    


    async def handle_authorize(self, msg_id, params):
        """Handle mining.authorize"""
        if len(params) >= 1:
            self.worker_name = params[0]
            self.authorized = True
            print(f"[AUTHORIZE] {self.client_ip} authorized worker: {self.worker_name}")
            await self.send_response(msg_id, True)
        else:
            # print(f"[AUTHORIZE] {self.client_ip} authorization failed")
            await self.send_response(msg_id, False)



    async def handle_submit(self, msg_id, params):
        """Handle mining.submit with validation"""
        # Auto-authorize if needed
        if not self.authorized and len(params) >= 1:
            self.worker_name = params[0]
            self.authorized = True
            # print(f"[AUTO-AUTH] {self.client_ip} auto-authorized worker: {self.worker_name}")
        
        if not self.authorized:
            # print(f"[SUBMIT] {self.client_ip} not authorized")
            await self.send_response(msg_id, False)
            return
        
        # Validate parameters
        if not validate_share_params(params):
            # print(f"[SUBMIT] {self.client_ip} invalid parameters: {params}")
            await self.send_response(msg_id, False)
            return
        
        worker_name, job_id, extra_nonce2, ntime, nonce = params
        # print(f"[SUBMIT] {worker_name}: job_id={job_id}, nonce={nonce}")
        
        # Process share with error handling
        try:
            accepted = await self.server.process_share(worker_name, job_id, self.extra_nonce1, extra_nonce2, ntime, nonce)
            await self.send_response(msg_id, accepted)
        except Exception as e:
            print(f"[SUBMIT] {self.client_ip} share processing error: {e}")
            await self.send_response(msg_id, False)



async def handle_client(reader, writer, server):
    """Handle new stratum client connection"""
    connection = StratumConnection(reader, writer, server)
    await connection.handle()





async def main():
    """Main server loop"""
    server = StratumServer()
    
    # Create initial job
    initial_job = await server.create_job()
    if initial_job:
        await server.broadcast_new_job()
    
    # Start stratum server
    stratum_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, server),
        "0.0.0.0", 
        STRATUM_PORT
    )
    
    print(f"[SERVER] Ready for connections on port {STRATUM_PORT}")
    
    # Job refresh loop
    async def job_refresh_loop():
        while True:
            await asyncio.sleep(5)  # Check every X seconds
            await server.create_job() 
            

    
    # Run server
    await asyncio.gather(
        stratum_server.serve_forever(),
        job_refresh_loop()
    )







if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")