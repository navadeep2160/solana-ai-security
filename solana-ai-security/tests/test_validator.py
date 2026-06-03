from agents.validator.validator_agent import validate_contract
from pathlib import Path

CONTRACT_PATH = (
    "contracts/vulnerable_bank/"
    "programs/vulnerable_bank/src/lib.rs"
)

with open(CONTRACT_PATH, "r") as f:
    contract = f.read()

result = validate_contract(contract)
print("Success:", result["success"])
print("STDERR:", result["stderr"][-800:])