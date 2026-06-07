"""
Clean TX Analyzer API (FIXED)
Used by network_v2 pipeline
"""

import requests

RPC_TESTNET = "https://api.testnet.solana.com"


def rpc_call(method, params=None, rpc_url=RPC_TESTNET):
    r = requests.post(rpc_url, json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params or []
    })

    data = r.json()
    return data.get("result", None)


def fetch_address_txs(address: str, limit: int = 10):
    return rpc_call(
        "getSignaturesForAddress",
        [address, {"limit": limit}]
    )


def fetch_tx(signature: str):
    return rpc_call(
        "getTransaction",
        [signature, {
            "encoding": "json",
            "maxSupportedTransactionVersion": 0
        }]
    )
