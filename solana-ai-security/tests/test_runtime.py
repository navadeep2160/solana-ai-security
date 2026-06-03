import sys
sys.path.insert(0, ".")

from runtime_validator.checker import run_runtime_validation
from pathlib import Path

print("Testing runtime validator...\n")

contract = Path(
    "contracts/vulnerable_bank/programs/vulnerable_bank/src/lib.rs"
).read_text()

result = run_runtime_validation(contract)

print("\n--- RUNTIME RESULT ---")
for k, v in result.items():
    if k != "test_output":
        print(f"  {k}: {v}")
