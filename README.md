# AnyPool - Stratum Mining Pool Server

A Stratum protocol to Full Node RPC adapter for mining.

![Coin](https://img.shields.io/badge/Coin-Litecoin_Testnet-green.svg)


<img height="500" alt="Screenshot 2025-08-28 at 12 17 18" src="https://github.com/user-attachments/assets/11074d46-6a85-4043-a016-092d1daac4be" /> <img height="500" alt="Screenshot 2025-08-28 at 12 19 23" src="https://github.com/user-attachments/assets/6ab2d8f1-f436-400d-a9e4-f6ead9e69dee" />
<br/>



# ❌ DO NOT USE IN PRODUCTION! ❌ <br/> ❌ DEVELOPMENT IN PROGRESS! ❌

<br/>

## Supported coins
For now, only Litecoin testnet is supported.

<br/>

## Quick Start

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

<br/>

## Environment Variables for *anypool-stratum* service

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `RPC_HOST` | Full Node RPC host | 127.0.0.1 | ❌ |
| `RPC_PORT` | Full Node RPC port | 19332 | ❌ |
| `RPC_USER` | RPC username | admin | ❌ |
| `RPC_PASS` | RPC password | admin | ❌ |
| `REWARD_ADDR` | Your cryptocurrency address for mining rewards |  | ✅ |
| `COINBASE_MESSAGE` | Custom message embedded in mined blocks | "/AnyPool by VU Kaunas faculty/" | ❌ |
| `STRATUM_PORT` | Port for the stratum server | 3333 | ❌ |
| `POOL_DIFFICULTY` | Mining difficulty | 2048 | ❌ |
| `POLL_DIFF_DROPPER`| Drop difficulty for miners if network difficulty suddenly drops even lower then pool's fixed difficulty | false | ❌ |

<br/>

## Mining

By default, docker-compose.yml file contains a cpuminer container that can be used to mine.

If you want to mine with your external miner, comment this section out.



<br/>

## SegWit and MWEB Support

The stratum server automatically detects and supports:


### SegWit (Segregated Witness)
- **Witness Commitments**: Automatically includes witness commitments in coinbase transactions when present
- **SegWit Transactions**: Properly handles SegWit transaction data from block templates
- **Address Support**: Compatible with both legacy and SegWit address formats

### MWEB (MimbleWimble Extension Blocks)
- **MWEB Detection**: Automatically detects MWEB data in block templates
- **Extension Blocks**: Properly constructs and submits blocks with MWEB extension data
- **Privacy Transactions**: Supports mining blocks containing confidential MWEB transactions

<br/>

## Security Notes

- This implementation includes simplified address decoding
- For production use, implement proper base58check decoding
- Consider adding authentication and rate limiting
- Always test on testnet first

<br/>

## Troubleshooting

1. **RPC Connection Errors**: Check your Litecoin node is running and RPC credentials are correct
2. **Invalid Address**: Make sure REWARD_ADDR is a valid Litecoin testnet address
3. **Port Conflicts**: Change STRATUM_PORT if 3333 is in use
4. **Low Hash Rate**: Adjust POOL_DIFFICULTY for your mining hardware
