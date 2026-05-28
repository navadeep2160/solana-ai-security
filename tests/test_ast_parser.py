import sys
sys.path.insert(0, ".")

from analysis.ast_parser.rust_ast_parser import parse_rust_ast, format_ast_findings
from pathlib import Path

contract = Path(
    "contracts/vulnerable_bank/programs/vulnerable_bank/src/lib_original.rs"
).read_text()

print("Running AST parser on vulnerable contract...\n")
result = parse_rust_ast(contract)
print(format_ast_findings(result))
