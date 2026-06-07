import requests

RPC="https://api.devnet.solana.com"

def rpc(method, params=[]):

    r=requests.post(
        RPC,
        json={
            "jsonrpc":"2.0",
            "id":1,
            "method":method,
            "params":params
        }
    )

    return r.json()["result"]

def analyze():

    perf=rpc(
        "getRecentPerformanceSamples",
        [5]
    )

    avg=sum(
        p["numTransactions"]/p["samplePeriodSecs"]
        for p in perf
    )/len(perf)

    score=0

    if avg>3000:
        score+=5

    if avg>5000:
        score+=5

    return {
        "type":"tpu_congestion",
        "score":score,
        "avg_tps":avg
    }

if __name__=="__main__":
    print(analyze())

