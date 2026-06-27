"""
Solana CLI Path Helper
======================
Ensures solana-test-validator is found by subprocess calls.
"""
import os
import shutil
from pathlib import Path

SOLANA_BIN = Path.home() / ".local/share/solana/install/active_release/bin"

def ensure_solana_in_path():
    """Add Solana CLI to PATH if not already present."""
    solana_path = str(SOLANA_BIN)
    current_path = os.environ.get("PATH", "")
    
    if solana_path not in current_path and SOLANA_BIN.exists():
        os.environ["PATH"] = f"{solana_path}:{current_path}"
        return True
    return False

def get_validator_path():
    """Get absolute path to solana-test-validator."""
    # Check if already in PATH
    validator = shutil.which("solana-test-validator")
    if validator:
        return validator
    
    # Try default install location
    default = SOLANA_BIN / "solana-test-validator"
    if default.exists():
        ensure_solana_in_path()
        return str(default)
    
    return "solana-test-validator"  # Fallback, will fail if not found

def get_solana_path():
    """Get absolute path to solana CLI."""
    solana = shutil.which("solana")
    if solana:
        return solana
    
    default = SOLANA_BIN / "solana"
    if default.exists():
        ensure_solana_in_path()
        return str(default)
    
    return "solana"
