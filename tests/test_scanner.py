from agents.scanner.scanner_agent import scan_contract
import json
from pathlib import Path

CONTRACT_PATH = (
    "contracts/vulnerable_bank/"
    "programs/vulnerable_bank/src/lib.rs"
)

with open(CONTRACT_PATH, "r") as f:
    contract = f.read()

result = scan_contract(contract)
print(json.dumps(result, indent=2))