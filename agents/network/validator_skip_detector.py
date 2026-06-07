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
        },
        timeout=15
    )

    data=r.json()

    if "error" in data:
        return None

    return data.get("result")

def analyze():

    vote=rpc("getVoteAccounts")

    if not vote:
        return {
            "type":"validator_skip",
            "score":0,
            "error":"No vote account data"
        }

    current=vote.get("current",[])
    delinquent=vote.get("delinquent",[])

    active=len(current)
    delinquent_count=len(delinquent)

    score=0

    if delinquent_count>0:
        score+=3

    if delinquent_count>10:
        score+=3

    if delinquent_count>50:
        score+=4

    top_delinquent=[]

    for v in sorted(
        delinquent,
        key=lambda x:x.get("activatedStake",0),
        reverse=True
    )[:5]:

        top_delinquent.append({
            "stake_sol":round(
                v.get("activatedStake",0)/1e9,
                2
            ),
            "last_vote":v.get("lastVote",0)
        })

    return {
        "type":"validator_skip",
        "score":score,
        "active_validators":active,
        "delinquent_validators":delinquent_count,
        "top_delinquent":top_delinquent
    }

if __name__=="__main__":
    print(analyze())
