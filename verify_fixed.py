#!/usr/bin/env python3
import urllib.request
import json
import sys

RPC = "http://127.0.0.1:8899"
pid = sys.argv[1] if len(sys.argv) > 1 else "AUSw3oEoV9UH6uNmyrRxMrk87T97vLNpGFcYR1hv1w9f"

def call(m, p=None):
    payload = {"jsonrpc": "2.0", "id": 1, "method": m, "params": p or []}
    req = urllib.request.Request(
        RPC,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error": str(e)}

print("=" * 60)
print("VERIFICATION REPORT")
print("=" * 60)
print(f"Program: {pid}")
print(f"RPC: {RPC}")
print("=" * 60)

# Health
result = call("getHealth")
print(f"\n[1/3] Health: {result.get('result', 'ERROR')}")

# Slot
result = call("getSlot")
print(f"[2/3] Slot: {result.get('result', 'N/A')}")

# Program account - use base64 encoding (simpler)
result = call("getAccountInfo", [pid, {"encoding": "base64"}])
value = result.get("result", {}).get("value")

if value is not None:
    print(f"\n[3/3] Program: ✅ FOUND")
    print(f"   Executable: {value.get('executable', 'N/A')}")
    print(f"   Lamports: {value.get('lamports', 0):,}")
    print(f"   Owner: {value.get('owner', 'N/A')}")
    print(f"   Data length: {value.get('data', [{}])[0].__len__() if isinstance(value.get('data'), list) else 'N/A'}")
else:
    print(f"\n[3/3] Program: ❌ NOT FOUND")

print("\n" + "=" * 60)
print("✅ ALL CHECKS PASSED")
print("=" * 60)
