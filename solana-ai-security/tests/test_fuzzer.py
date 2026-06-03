import sys
sys.path.insert(0, ".")

from fuzzing.fuzzer import run_fuzzing
from pathlib import Path

contract = Path(
    "contracts/vulnerable_bank/programs/vulnerable_bank/src/lib.rs"
).read_text()

print("Running fuzz tests...\n")
result = run_fuzzing(contract)

print(f"\n--- FUZZ RESULTS ---")
print(f"Total cases:  {result['total_cases']}")
print(f"Passed:       {result['passed']}")
print(f"Failed:       {result['failed']}")
print(f"Findings:     {len(result['findings'])}")
for f in result["findings"]:
    print(f"  [{f['severity'].upper()}] {f['type']}: {f['description']}")
