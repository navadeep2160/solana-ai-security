from agents.patcher.patch_agent import patch_contract
from pathlib import Path

CONTRACT_PATH = (
    "contracts/vulnerable_bank/"
    "programs/vulnerable_bank/src/lib.rs"
)

with open(CONTRACT_PATH, "r") as f:
    contract = f.read()

patched = patch_contract(contract, errors="")
print("\n--- PATCHED OUTPUT ---\n")
print(patched[:1500])