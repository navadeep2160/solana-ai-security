"""Validator agent - checks if generated Rust code compiles."""

import json
import os
import subprocess
from pathlib import Path
from datetime import datetime

CARGO_TOML = """[package]
name = "vulnerable_bank"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "lib"]

[dependencies]
anchor-lang = "0.30.1"
"""

def validate_contract(rust_code: str) -> dict:
    """Validate generated Rust code by running cargo check."""
    
    # Set persistent cargo target dir to cache dependencies
    os.environ.setdefault("CARGO_TARGET_DIR", "/tmp/solana_cargo_cache")
    
    print("[VALIDATOR] Writing Cargo.toml...")
    
    # Use a directory outside any workspace
    program_dir = Path("/tmp/solana_validator/programs/vulnerable_bank")
    src_dir = program_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    
    # Write Cargo.toml
    (program_dir / "Cargo.toml").write_text(CARGO_TOML, encoding="utf-8")
    
    # Write lib.rs
    print("[VALIDATOR] Writing contract to disk...")
    (src_dir / "lib.rs").write_text(rust_code, encoding="utf-8")
    
    # Run cargo check
    print("[VALIDATOR] Running cargo check...")
    result = subprocess.run(
        ["cargo", "check"],
        cwd=program_dir,
        capture_output=True,
        text=True,
        timeout=300
    )
    
    success = result.returncode == 0
    
    output = {
        "success": success,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }
    
    # Save log
    log_dir = Path("outputs/logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_path = log_dir / f"validator_{timestamp}.json"
    with open(log_path, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"[VALIDATOR] Log saved → {log_path}")
    
    if success:
        print("[VALIDATOR] ✅ cargo check passed")
    else:
        print("[VALIDATOR] ❌ cargo check failed")
    
    return output
