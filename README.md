# AnyPool - Stratum Mining Pool Server

A Stratum protocol to Full Node RPC adapter for mining.

![Coin](https://img.shields.io/badge/Coin-Litecoin_Testnet-green.svg)

<img height="400" alt="Screenshot 2025-08-28 at 11 11 10" src="https://github.com/user-attachments/assets/40e3d601-2dbf-4205-92d5-7e8698100142" /> <img height="400" alt="Screenshot 2025-08-28 at 11 10 48" src="https://github.com/user-attachments/assets/10b26542-ee7e-43ce-a596-e80da10aebfd" />
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

## Configuration

- `RPC_HOST`: Full Node RPC host (default: 127.0.0.1)
- `RPC_PORT`: Full Node RPC port (default: 19332 for testnet)
- `RPC_USER`: RPC username (default: admin)
- `RPC_PASS`: RPC password (default: admin)
- `REWARD_ADDR`: Your cryptocurrency address for mining rewards
- `COINBASE_MESSAGE`: Custom message embedded in mined blocks (default: "/AnyPool by VU Kaunas faculty/")
- `STRATUM_PORT`: Port for the stratum server (default: 3333)
- `POOL_DIFFICULTY`: Mining difficulty (default: 2048)
- `POLL_DIFF_DROPPER`: Drop difficulty if network difficulty is lower then pool's difficulty (default: false)

<br/>

## Mining

Connect your ASIC or GPU miner to:
- Host: Your server IP (this is the IP of the server running the stratum server)
- Port: 3333 (or your configured STRATUM_PORT)
- Algorithm: Scrypt (Litecoin's algorithm)

Example with cpuminer:
```bash
minerd -a scrypt -o stratum+tcp://<server_ip>:3333 -u worker1 -p x
```

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
4. **Low Hash Rate**: Adjust FIXED_DIFF for your mining hardware
