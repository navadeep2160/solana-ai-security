import requests

def rpc(url, method, params=None):
    r = requests.post(url, json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params or []
    }, timeout=20)

    data = r.json()
    if "error" in data:
        return None
    return data.get("result")


def get_tx(url, sig):
    return rpc(url, "getTransaction", [sig, {
        "encoding": "json",
        "maxSupportedTransactionVersion": 0
    }])


def get_signatures(url, address, limit=20):
    return rpc(url, "getSignaturesForAddress", [address, {"limit": limit}])
