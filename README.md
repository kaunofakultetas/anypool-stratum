# AnyPool - Stratum Mining Pool Server

A Stratum protocol to Full Node RPC adapter for mining Bitcoin-family coins (SHA256d and Scrypt).

![Coins](https://img.shields.io/badge/Coins-BTC_|_LTC_|_DOGE_|_KNF-green.svg)


<img height="500" alt="Screenshot 2025-08-28 at 12 17 18" src="https://github.com/user-attachments/assets/11074d46-6a85-4043-a016-092d1daac4be" /> <img height="500" alt="Screenshot 2025-08-28 at 12 19 23" src="https://github.com/user-attachments/assets/6ab2d8f1-f436-400d-a9e4-f6ead9e69dee" />
<br/>



### ⚠️ Test before using in production ⚠️

<br/>

## Supported coins

| Coin | Networks | Algorithm | Addresses | Notes |
|------|----------|-----------|-----------|-------|
| `BTC` (Bitcoin) | mainnet, testnet3, testnet4 | SHA256d | bech32 (native segwit) | SegWit, BIP310 version rolling (AsicBoost), validated on testnet3/testnet4 2026-07-14 |
| `LTC` (Litecoin) | mainnet, testnet | Scrypt | bech32 (native segwit) | SegWit + MWEB |
| `KNF` (KnfCoin)  | mainnet, testnet | Scrypt | bech32 (native segwit) | SegWit + MWEB |
| `DOGE` (Dogecoin) | mainnet, testnet | Scrypt | base58 (legacy P2PKH) | solo mining (no AuxPoW), validated on testnet 2026-07-14 |

**Difficulty units differ per algorithm.** `POOL_DIFFICULTY` is interpreted
against the coin's difficulty-1 target: for Scrypt coins one diff-1 share
is ~65k hashes, for SHA256d it is ~4.3G hashes (Bitcoin's classic bdiff).
A scrypt ASIC works well around 5&nbsp;000–100&nbsp;000; a SHA256 ASIC on
testnet is fine with 1&nbsp;000–65&nbsp;000, and a CPU miner wants single digits.

Both modern (segwit/MWEB) and older pre-segwit Bitcoin Core forks are
supported — the differences (address format, block serialization, template
rules) live entirely in the per-coin definition.

Adding a new coin is one small file — see [Adding a new coin](#adding-a-new-coin) below.

<br/>

## Quick Start
Follow steps below to quickly start the stratum server with LTC testnet node and cpu miner:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/kaunofakultetas/anypool-stratum.git
   ```

2. **Copy sample docker-compose.yml and stack startup script:**
   ```
   cp ./anypool-stratum/docker-compose.yml.sample docker-compose.yml
   cp ./anypool-stratum/runUpdateThisStack.sh.sample runUpdateThisStack.sh
   ```

3. **Configure docker-compose.yml environment variables:**
   ```bash
   nano docker-compose.yml
   ```

4. **Run the server:**
   ```bash
   ./runUpdateThisStack.sh
   ```

5. **Check the logs:**
   ```bash
   sudo docker-compose logs -f
   ```

<br/>

## Environment Variables for *anypool-stratum* service

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `COIN` | Coin to mine (`BTC`, `LTC`, `DOGE`, `KNF`) | LTC | ❌ |
| `COIN_NETWORK` | Network (`mainnet`, `testnet`; for BTC: `mainnet`, `testnet3`, `testnet4`) | testnet | ❌ |
| `RPC_HOST` | Full Node RPC host | 127.0.0.1 | ❌ |
| `RPC_PORT` | Full Node RPC port | 19332 | ❌ |
| `RPC_USER` | RPC username | admin | ❌ |
| `RPC_PASS` | RPC password | admin | ❌ |
| `REWARD_ADDR` | Your cryptocurrency address for mining rewards (native segwit / bech32) |  | ✅ |
| `COINBASE_MESSAGE` | Custom message embedded in mined blocks | "/AnyPool by VU Kaunas faculty/" | ❌ |
| `STRATUM_PORT` | Port for the stratum server | 3333 | ❌ |
| `POOL_DIFFICULTY` | Mining difficulty | 2048 | ❌ |
| `POLL_DIFF_DROPPER`| Drop difficulty for miners if network difficulty suddenly drops even lower then pool's fixed difficulty | false | ❌ |
| `DEBUG` | Print verbose debug panels for every job and share | false | ❌ |

<br/>

## Project Structure

```
anypool-stratum/
├── main.py              # Entry point: config validation + the three loops
│                        #   (TCP listener, 5s template poll, longpoll)
├── anypool/
│   ├── config.py        # Environment variables + startup validation
│   ├── display.py       # All console output panels
│   ├── coins/           # Per-coin definitions (PoW, prefixes, GBT rules)
│   ├── crypto/          # Pure primitives: hashing, merkle tree, bech32
│   ├── mining/          # Coinbase builder, jobs, share validation, blocks
│   ├── node/            # JSON-RPC client to the full node
│   └── stratum/         # Miner-facing network layer (server, connections)
├── tests/               # Unit tests with known-good mainnet block vectors
├── requirements.txt
└── Dockerfile
```

Dependency direction (top depends on bottom):

```
main.py -> stratum/ -> mining/ -> crypto/
            (node/)    (coins/)   (config.py, display.py)
```

<br/>

## Running the Tests

The test suite verifies the full mining pipeline against a real
network-accepted block (KNF mainnet block 1777): coinbase construction,
merkle tree math, header assembly and the Scrypt proof-of-work hash are
all checked byte for byte.

Run inside the container (it has all dependencies installed):

```bash
sudo docker exec <stratum-container-name> python -m unittest discover -s tests -v
```

<br/>

## Adding a New Coin

1. Create `anypool/coins/<symbol>.py` with one `CoinDefinition`
   (see `anypool/coins/base.py` for the fields, `knf.py` for a modern
   segwit coin and `doge.py` for an older pre-segwit fork):

```python
from anypool.coins.address import Base58P2PKH, Bech32P2WPKH
from anypool.coins.base import CoinDefinition
from anypool.crypto.hashing import scrypt_pow_hash

# Modern Litecoin-family coin (segwit + MWEB, bech32 addresses):
NEWCOIN = CoinDefinition(
    name="NEW",
    algo="SCRYPT",
    pow_hash=scrypt_pow_hash,
    difficulty_1_target=0x0000FFFF...,
    gbt_rules=["segwit", "mweb"],
    address_scheme=Bech32P2WPKH({"mainnet": "new", "testnet": "tnew"}),
    has_mweb=True,
)

# Older Bitcoin Core fork (no segwit, legacy addresses):
OLDCOIN = CoinDefinition(
    name="OLD",
    algo="SCRYPT",
    pow_hash=scrypt_pow_hash,
    difficulty_1_target=0x0000FFFF...,
    gbt_rules=[],                 # old daemons predate the rules param
    address_scheme=Base58P2PKH({"mainnet": 0x1e, "testnet": 0x71}),
    has_mweb=False,
)
```

2. Register it in `anypool/coins/__init__.py` (`REGISTRY` dict).
3. Set `COIN=<SYMBOL>` in the environment. No other code changes needed.

For a coin with a different PoW algorithm, add the hash function to
`anypool/crypto/hashing.py` and point the definition's `pow_hash` at it.
Before trusting a new coin on mainnet, mine one testnet block and freeze
its log values into `tests/` as vectors (like `tests/vectors.py` does
for KNF block 1777).

<br/>

## How It Works

1. **Job creation** — the pool polls `getblocktemplate` every 5 seconds and
   also keeps a **longpoll** request hanging at the node, so a new chain tip
   cuts a fresh job within milliseconds. Identical templates never trigger
   a job restart.
2. **Work distribution** — every miner connection gets a unique extranonce1,
   making every miner's coinbase (and merkle root) distinct.
3. **Share validation** — each submitted share is rebuilt into the exact
   80-byte header the miner hashed and checked against the pool target.
   Stale jobs, duplicate shares and out-of-range timestamps are rejected
   with standard stratum error codes the miner can display.
4. **Block submission** — a share that also meets the network target is
   assembled into a complete block (same header, witness coinbase, all
   template transactions, MWEB extension) and submitted via `submitblock`.

<br/>

## Stratum Protocol Support

Beyond the core `subscribe` / `authorize` / `submit` flow, the pool
answers every optional method miners and proxies commonly send —
an unanswered request makes many ASICs and rental services
(e.g. MiningRigRentals) stall or drop the pool:

| Method | Behavior |
|--------|----------|
| `mining.configure` (BIP310) | version-rolling granted on BTC (mask `1fffe000`), declined on coins whose version bits carry meaning |
| `mining.extranonce.subscribe` | acknowledged (extranonce1 never changes mid-connection) |
| `mining.suggest_difficulty` | acknowledged; the pool keeps its configured difficulty |
| anything else | answered with a proper "method not supported" error |

`mining.submit` accepts both the 5-parameter form and the 6-parameter
form with version-rolling bits (bits must stay inside the negotiated mask).

<br/>

## SegWit and MWEB Support

The stratum server automatically detects and supports:


### SegWit (Segregated Witness)
- **Witness Commitments**: Automatically includes witness commitments in coinbase transactions when present
- **SegWit Transactions**: Properly handles SegWit transaction data from block templates
- **Address Support**: Native segwit (bech32) reward addresses

### MWEB (MimbleWimble Extension Blocks)
- **MWEB Detection**: Automatically detects MWEB data in block templates
- **Extension Blocks**: Properly constructs and submits blocks with MWEB extension data
- **Privacy Transactions**: Supports mining blocks containing confidential MWEB transactions

<br/>

## Security Notes

- Worker authorization accepts any name/password — fine for a private or
  teaching pool, do NOT expose to untrusted miners as-is
- Duplicate shares, stale jobs and rolled timestamps are rejected
- Always test on testnet first

<br/>

## Troubleshooting

1. **RPC Connection Errors**: Check your node is running and RPC credentials are correct
2. **Invalid Address**: Make sure REWARD_ADDR is a valid bech32 address for the selected COIN + COIN_NETWORK (the pool refuses to start otherwise)
3. **Port Conflicts**: Change STRATUM_PORT if 3333 is in use
4. **Low Hash Rate**: Adjust POOL_DIFFICULTY for your mining hardware
5. **Share rejections**: The miner's own log now shows the reason (stale job, duplicate, low difficulty, ntime out of range)
