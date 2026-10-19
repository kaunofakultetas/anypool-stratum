############################################################
#  [*] Block Assembly
#
#  Turns a solved share into the full serialized block that
#  gets handed to the node via submitblock:
#
#    header (80 bytes)
#    | tx count (varint)
#    | coinbase tx (FULL serialization, with witness)
#    | every template transaction, verbatim ("data" field)
#    | MWEB section, when the template carries one
#
#  Note the coinbase difference from share validation: the
#  merkle tree was computed over the witness-less txid form,
#  but the block body must contain the full segwit form —
#  that is why jobs carry both coinb1/coinb2 variants.
#
#  Used by:
#    - families/bitcoin/server.py — _submit_block()
############################################################


from typing import Dict

from anypool.families.bitcoin.coinbase import to_varint








############################################################
# assemble_block
############################################################
#
# Concatenates the final block hex for submission. The
# header must come from shares.build_header() for the same
# extranonce/ntime/nonce values, so header and body are
# guaranteed to describe the same coinbase.
#
# The transaction count MUST be a real varint, not a single
# byte — one byte only encodes counts up to 252 and would
# produce a corrupt block the first time a template carries
# more transactions than that.
#
# The MWEB section follows the node's own serialization: a
# Litecoin-family node reads it only after a block whose last
# transaction is the HogEx, as a 0x01 marker and then the
# extension block — and the template carries "mweb" data
# exactly for such blocks, the HogEx being its last
# transaction. So the section is written exactly when the
# template has MWEB data, on any chain and from whatever
# height MWEB activates there; before activation, and on
# coins without MWEB, the block ends after its transactions.
# MWEB data without a single template transaction to be its
# HogEx is a template no node would accept a block for, and
# is refused here instead.
#
# Used by:
#   - families/bitcoin/server.py — _submit_block()
############################################################

def assemble_block(job: Dict, extra_nonce1: str, extra_nonce2: str, header_hex: str) -> str:

    # Coinbase in FULL (witness) serialization for the block body
    coinbase_full_hex = job["coinb1_full"] + extra_nonce1 + extra_nonce2 + job["coinb2_full"]


    # All template transactions, exactly as the node gave them to us
    all_txs = job["template"].get("transactions", [])
    all_tx_data_hex = ""
    for tx in all_txs:
        all_tx_data_hex += tx["data"]


    # Coinbase + template transactions
    tx_count = to_varint(len(all_txs) + 1)


    # MWEB section: marker byte, then the extension block — only
    # behind the HogEx the template ends with
    mweb_hex = job["template"].get("mweb")
    if mweb_hex:
        if not all_txs:
            raise ValueError("block template carries MWEB data but no HogEx transaction")
        mweb_part = "01" + mweb_hex
    else:
        mweb_part = ""


    complete_block = header_hex + tx_count + coinbase_full_hex + all_tx_data_hex + mweb_part


    # A malformed hex string would make submitblock fail cryptically —
    # fail loudly here instead.
    bytes.fromhex(complete_block)

    return complete_block
