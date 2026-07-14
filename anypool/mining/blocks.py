# -----------------------------------------------------------
#  [*] Block Assembly
#
#  Turns a solved share into the full serialized block that
#  gets handed to the node via submitblock:
#
#    header (80 bytes)
#    | tx count (varint)
#    | coinbase tx (FULL serialization, with witness)
#    | every template transaction, verbatim ("data" field)
#    | MWEB extension block, when the template carries one
#
#  Note the coinbase difference from share validation: the
#  merkle tree was computed over the witness-less txid form,
#  but the block body must contain the full segwit form —
#  that is why jobs carry both coinb1/coinb2 variants.
#
#  Used by:
#    - stratum/server.py — _submit_block()
# -----------------------------------------------------------

from typing import Dict

from anypool.mining.coinbase import to_varint




# -----------------------------------------------------------
# assemble_block
# -----------------------------------------------------------
#
# Concatenates the final block hex for submission. The
# header must come from shares.build_header() for the same
# extranonce/ntime/nonce values, so header and body are
# guaranteed to describe the same coinbase.
#
# The transaction count uses a proper varint (the previous
# implementation used a single byte, which would have
# produced corrupt blocks with more than 252 transactions).
#
# The MWEB tail (marker byte + optional extension data) is
# Litecoin-family serialization and is only appended when the
# coin declares has_mweb — on a plain Bitcoin Core fork like
# Dogecoin that extra byte would make every block malformed.
#
# Used by:
#   - stratum/server.py — _submit_block()
# -----------------------------------------------------------
def assemble_block(job: Dict, extra_nonce1: str, extra_nonce2: str, header_hex: str,
                   has_mweb: bool) -> str:

    # Coinbase in FULL (witness) serialization for the block body
    coinbase_full_hex = job["coinb1_full"] + extra_nonce1 + extra_nonce2 + job["coinb2_full"]


    # All template transactions, exactly as the node gave them to us
    all_txs = job["template"].get("transactions", [])
    all_tx_data_hex = ""
    for tx in all_txs:
        all_tx_data_hex += tx["data"]


    # Coinbase + template transactions
    tx_count = to_varint(len(all_txs) + 1)


    # MWEB tail (Litecoin-family only): marker byte, then the
    # extension data when the template carries any
    if has_mweb:
        mweb_part = "01" + job["template"].get("mweb", "")
    else:
        mweb_part = ""


    complete_block = header_hex + tx_count + coinbase_full_hex + all_tx_data_hex + mweb_part


    # A malformed hex string would make submitblock fail cryptically —
    # fail loudly here instead.
    bytes.fromhex(complete_block)

    return complete_block
