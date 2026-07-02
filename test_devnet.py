#!/usr/bin/env python3
"""Test a deployed Solana program on devnet or local validator."""
import urllib.request
import json
import sys

DEVNET_RPC = "https://api.devnet.solana.com"
LOCAL_RPC = "http://127.0.0.1:8899"

def rpc_call(url, method, params=None):
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e)}

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 test_devnet.py <PROGRAM_ID> [devnet|local]")
        sys.exit(1)
    
    program_id = sys.argv[1]
    network = sys.argv[2] if len(sys.argv) > 2 else "devnet"
    rpc_url = DEVNET_RPC if network == "devnet" else LOCAL_RPC
    
    print("=" * 60)
    print(f"Program ID: {program_id}")
    print(f"Network: {network}")
    print(f"RPC: {rpc_url}")
    print("=" * 60)
    
    # Health check
    print("\n[1/3] Checking cluster...")
    result = rpc_call(rpc_url, "getHealth")
    if result.get("result") == "ok":
        print("  ✅ Cluster healthy")
    else:
        print(f"  ❌ Cluster issue: {result}")
        sys.exit(1)
    
    # Program check
    print("\n[2/3] Checking program...")
    result = rpc_call(rpc_url, "getAccountInfo", [program_id, {"encoding": "jsonParsed"}])
    value = result.get("result", {}).get("value")
    if not value:
        print("  ❌ Program not found")
        sys.exit(1)
    
    print(f"  ✅ Program found")
    print(f"     Executable: {value.get('executable')}")
    print(f"     Lamports: {value.get('lamports', 0):,}")
    print(f"     Owner: {value.get('owner')}")
    print(f"     Data size: {len(value.get('data', [''])[0]) if isinstance(value.get('data'), list) else 0} bytes")
    
    if not value.get("executable"):
        print("  ❌ Not a program!")
        sys.exit(1)
    
    # Slot
    print("\n[3/3] Checking slot...")
    result = rpc_call(rpc_url, "getSlot")
    if "result" in result:
        print(f"  Current slot: {result['result']:,}")
    
    print("\n" + "=" * 60)
    print("✅ ALL CHECKS PASSED")
    print("=" * 60)

if __name__ == "__main__":
    main()
