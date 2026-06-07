import requests

RPC = "https://api.devnet.solana.com"

def rpc(method, params):
    r = requests.post(
        RPC,
        json={
            "jsonrpc":"2.0",
            "id":1,
            "method":method,
            "params":params
        }
    )
    return r.json()["result"]

def analyze(signature):

    tx = rpc(
        "getTransaction",
        [
            signature,
            {
                "encoding":"json",
                "maxSupportedTransactionVersion":0
            }
        ]
    )

    fee = tx["meta"]["fee"]

    score = 0

    if fee > 100000:
        score += 5

    if fee > 1000000:
        score += 5

    return {
        "type":"fee_anomaly",
        "score":score,
        "fee":fee
    }

