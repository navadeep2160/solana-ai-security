import requests
from collections import Counter

RPC = "https://api.devnet.solana.com"


def fetch(address):
    r = requests.post(RPC, json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getSignaturesForAddress",
        "params": [address, {"limit": 500}]
    })
    return r.json().get("result", [])


def analyze(address):
    txs = fetch(address)

    slots = [t.get("slot") for t in txs if t.get("slot")]
    freq = Counter(slots)

    total_txs = len(slots)
    unique_slots = len(freq)

    max_slot_tx = max(freq.values(), default=0)

    density = total_txs / max(unique_slots, 1)

    spam_score = min(10,
        int(max_slot_tx * 0.7 + density * 0.3)
    )

    print("\n==============================")
    print("SPAM DETECTOR (ENHANCED)")
    print("==============================")
    print("Address:", address)
    print("Total TX:", total_txs)
    print("Unique slots:", unique_slots)
    print("TX/Slot density:", round(density, 2))
    print("Max TX in slot:", max_slot_tx)
    print("Spam Score:", spam_score, "/10")

    print("\nTop Slots:")
    for k,v in freq.most_common(10):
        print(f"Slot {k}: {v} tx")


if __name__ == "__main__":
    import sys
    analyze(sys.argv[1])
