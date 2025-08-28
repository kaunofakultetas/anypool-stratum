#!/usr/bin/env python3
"""
Test RPC connection separately to isolate issues

This is a focused diagnostic tool that tests ONLY the RPC connectivity between
the stratum pool and the Litecoin node. Used for troubleshooting when the full
mining pool setup fails.

Purpose:
- Isolate RPC communication problems from other pool issues
- Quick verification that the Litecoin node is reachable and responding
- Test basic authentication and JSON-RPC protocol communication
- First-step debugging tool for new environment setups

What it tests:
- HTTP connectivity to Litecoin node
- RPC authentication (username/password)
- JSON-RPC protocol communication
- Basic node responsiveness via getblockchaininfo call

When to use:
- 🔧 Debugging: When RPC calls are failing in the main pool
- 🔍 Isolation: To separate RPC issues from mining job construction problems  
- ⚡ Quick check: Fast verification before running comprehensive tests
- 🛠️ Setup: First validation step when configuring new environments

This is essentially a "ping test" for RPC - the simplest possible check before
testing more complex mining pool functionality.
"""




import asyncio
import aiohttp
import json
import base64
import os

# Config from environment
RPC_HOST = os.getenv("RPC_HOST", "ltc-testnet4-litecoind")
RPC_PORT = int(os.getenv("RPC_PORT", "19332"))
RPC_USER = os.getenv("RPC_USER", "litecoinrpc")
RPC_PASS = os.getenv("RPC_PASS", "litecoinrpc")

RPC_URL = f"http://{RPC_HOST}:{RPC_PORT}"

async def simple_rpc_call(method, params=None):
    """Simplified RPC call for testing"""
    if params is None:
        params = []
    
    payload = json.dumps({"method": method, "params": params, "id": 1})
    auth = base64.b64encode(f"{RPC_USER}:{RPC_PASS}".encode()).decode()
    headers = {
        "Authorization": f"Basic {auth}",
        "Content-Type": "application/json"
    }
    
    print(f"Calling RPC: {method}")
    print(f"URL: {RPC_URL}")
    print(f"Payload: {payload}")
    
    try:
        timeout_obj = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout_obj) as session:
            async with session.post(RPC_URL, data=payload, headers=headers) as resp:
                print(f"Response status: {resp.status}")
                if resp.status != 200:
                    text = await resp.text()
                    print(f"Error response: {text}")
                    return {"error": f"HTTP {resp.status}: {text}"}
                
                result = await resp.json()
                print(f"Success: {result}")
                return result
                
    except Exception as e:
        print(f"Exception occurred: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return {"error": str(e)}

async def main():
    print("=== RPC Test ===")
    print(f"Testing connection to {RPC_URL}")
    
    result = await simple_rpc_call("getblockchaininfo")
    
    if "error" in result:
        print(f"RPC Error: {result['error']}")
    else:
        print("RPC Success!")
        if "result" in result:
            chain = result["result"].get("chain", "unknown")
            blocks = result["result"].get("blocks", 0)
            print(f"Chain: {chain}, Blocks: {blocks}")

if __name__ == "__main__":
    asyncio.run(main())
