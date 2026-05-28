import sys
sys.path.insert(0, ".")

from analysis.ast_parser.cfg_builder import analyze_cfg
from pathlib import Path

contract = Path(
    "contracts/vulnerable_bank/programs/vulnerable_bank/src/lib_original.rs"
).read_text()

print("Running CFG analysis on vulnerable contract...\n")
result = analyze_cfg(contract)
print(result["summary"])
