############################################################
#  [*] Coinbase Transaction Builder
#
#  Builds the coinbase transaction for a block template and
#  splits it into the two halves the stratum protocol needs.
#  A miner rebuilds the whole transaction by joining coinb1,
#  the extranonce1 the pool assigned it, the extranonce2 it
#  picks itself and coinb2, in that order.
#
#  The split point sits inside the scriptSig, right after the
#  BIP34 height push, so every miner connection produces a
#  unique coinbase (and therefore a unique merkle root).
#
#  Two variants of each half are produced:
#
#    *_txid — serialized WITHOUT witness data. Hashing this
#             gives the txid used in the merkle tree, and it
#             is what gets sent to miners.
#    *_full — serialized WITH the segwit marker/flag and the
#             witness reserved value. This goes into the
#             actual block we submit to the node.
#
#  Used by:
#    - families/bitcoin/jobs.py   — build_job() calls
#      build_coinbase_parts()
#    - families/bitcoin/blocks.py — to_varint() for the
#      block's transaction count
############################################################


import struct
from typing import Dict

from anypool import coins, config, display








############################################################
# to_varint
############################################################
#
# Bitcoin variable-length integer encoding, as hex. Used for
# script lengths, output counts and the block's tx count.
#
# Used by:
#   - build_coinbase_parts() (below) — script/output lengths
#   - families/bitcoin/blocks.py — transaction count of the
#     full block
############################################################

def to_varint(i: int) -> str:
    if i < 0xfd:
        return f"{i:02x}"
    elif i <= 0xffff:
        return "fd" + struct.pack('<H', i).hex()
    elif i <= 0xffffffff:
        return "fe" + struct.pack('<I', i).hex()
    else:
        return "ff" + struct.pack('<Q', i).hex()








############################################################
# bip34_height_push
############################################################
#
# BIP34 requires the block height as the first push in the
# coinbase scriptSig. Encodes the height with Bitcoin Core's
# CScriptNum rules (minimal little-endian with a sign-bit
# padding byte when the top bit is set) and prefixes the
# push-length byte.
#
# Used by:
#   - build_coinbase_parts() (below)
############################################################

def bip34_height_push(height: int) -> bytes:
    if height == 0:
        return b'\x00'  # Minimal encoding for zero

    neg = height < 0
    absvalue = abs(height)

    b = []
    while absvalue:
        b.append(absvalue & 0xff)
        absvalue >>= 8

    # Handle sign bit: if high bit is set, add padding byte
    if b[-1] & 0x80:
        b.append(0x80 if neg else 0x00)
    elif neg:
        b[-1] |= 0x80

    result = bytes(b)
    return bytes([len(result)]) + result








############################################################
# build_coinbase_parts
############################################################
#
# Assembles the coinbase transaction for a getblocktemplate
# result and returns its stratum halves: coinb1_txid and
# coinb2_txid without witness data, coinb1_full and
# coinb2_full with it.
#
# Layout of the transaction (hex, in order):
#
#   version | [segwit marker+flag] | input count
#   | null prevout | scriptSig len
#   | BIP34 height push  <-- coinb1 ends here
#   | extranonce1+2 (8 bytes, inserted by stratum)
#   | coinbase message   <-- coinb2 starts here
#   | sequence | outputs | [witness stack] | locktime
#
# Outputs: the full block reward to REWARD_ADDR (P2WPKH or
# legacy P2PKH — the coin's address scheme decides), plus
# the witness commitment output when the template provides
# one (segwit blocks).
#
# Used by:
#   - families/bitcoin/jobs.py — build_job()
############################################################

def build_coinbase_parts(template: Dict) -> Dict[str, str]:
    # STEP 1: the inputs — height, reward, the pool's message,
    # and whether the block is segwit (the template then
    # carries a witness commitment)
    # ========================================================
    height = int(template["height"])
    coinbase_value = int(template["coinbasevalue"])
    message_bytes = config.COINBASE_MESSAGE.encode('utf-8')

    witness_commitment_hex = template.get("default_witness_commitment")
    has_witness = witness_commitment_hex is not None


    # STEP 2: fixed fields of a coinbase transaction
    # ==============================================
    version_le = "01000000"
    input_count = "01"
    prevout_hash = "00" * 32     # Coinbase spends nothing
    prevout_index = "ffffffff"
    sequence = "ffffffff"
    locktime = "00000000"


    # STEP 3: the scriptSig — height push, room for extranonce1
    # and extranonce2 (4 bytes each), then the message
    # =========================================================
    height_push = bip34_height_push(height)
    scriptsig_len = len(height_push) + 4 + 4 + len(message_bytes)
    scriptsig_len_vi = to_varint(scriptsig_len)


    # STEP 4: output 0 — the full block reward to the pool's
    # payout address. The script format (P2WPKH vs legacy
    # P2PKH) is decided by the active coin's address scheme.
    # ======================================================
    outputs = []
    payout_script = coins.active().address_scheme.payout_script(config.REWARD_ADDR, config.COIN_NETWORK)
    payout_output = (
        struct.pack('<Q', coinbase_value).hex() +
        to_varint(len(bytes.fromhex(payout_script))) +
        payout_script
    )
    outputs.append(payout_output)


    # STEP 5: output 1 — the witness commitment (zero value),
    # required for segwit blocks
    # =======================================================
    if witness_commitment_hex:
        witness_output = (
            "0000000000000000" +
            to_varint(len(bytes.fromhex(witness_commitment_hex))) +
            witness_commitment_hex  # Use as-is from template
        )
        outputs.append(witness_output)

    output_count_vi = to_varint(len(outputs))


    # STEP 6: TXID serialization (always without witness data)
    # — this is what miners hash and what goes into the merkle
    # tree.
    # ========================================================
    coinb1_txid = version_le + input_count + prevout_hash + prevout_index + scriptsig_len_vi + height_push.hex()
    coinb2_txid = (
        message_bytes.hex() +
        sequence +
        output_count_vi +
        "".join(outputs) +
        locktime
    )


    # STEP 7: full serialization — identical unless the block
    # is segwit, in which case the marker/flag bytes ("00"
    # "01") and the witness reserved value are added for block
    # submission.
    # ========================================================
    if has_witness:
        coinb1_full = version_le + "00" + "01" + input_count + prevout_hash + prevout_index + scriptsig_len_vi + height_push.hex()
        coinb2_full = (
            message_bytes.hex() +
            sequence +
            output_count_vi +
            "".join(outputs) +
            "01200000000000000000000000000000000000000000000000000000000000000000" +  # witness stack: one 32-byte reserved value
            locktime
        )
    else:
        coinb1_full = coinb1_txid
        coinb2_full = coinb2_txid


    display.debug_box("Coinbase components", [
        "Height:".ljust(25) +                 str(height),
        "Coinbase value:".ljust(25) +         str(coinbase_value),
        "Message bytes:".ljust(25) +          str(message_bytes),
        "Witness commitment hex:".ljust(25) + str(witness_commitment_hex),
        "Has witness:".ljust(25) +            str(has_witness),
    ])


    return {
        "coinb1_txid": coinb1_txid,
        "coinb2_txid": coinb2_txid,
        "coinb1_full": coinb1_full,
        "coinb2_full": coinb2_full,
    }
