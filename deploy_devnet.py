#!/usr/bin/env python3
"""
One-shot devnet deployment script.
Run this from ~/project/solana-ai-security
"""

import subprocess
import os
import sys
import re

def run(cmd, shell=False, capture=True, check=True):
    if isinstance(cmd, str):
        cmd = cmd.split()
    result = subprocess.run(cmd, capture_output=capture, text=True, shell=shell)
    if check and result.returncode != 0:
        print(f"  ❌ Command failed")
        if result.stderr:
            print(f"     {result.stderr.strip()}")
        sys.exit(1)
    return result

def main():
    print("=" * 60)
    print("Solana Devnet Deployment - One Shot")
    print("=" * 60)
    
    lib_rs_path = "/tmp/solana_validator/programs/vulnerable_bank/src/lib.rs"
    program_keypair = "/tmp/program-keypair.json"
    
    # Step 1: Verify generated code
    print("\n[1/6] Checking generated code...")
    if not os.path.exists(lib_rs_path):
        print(f"  ❌ Generated code not found")
        print("  Run: python -m analysis.bytecode_analyzer.test_batch --test download")
        sys.exit(1)
    print(f"  ✅ Generated code found")
    
    # Step 2: Get program ID
    print("\n[2/6] Setting up program keypair...")
    if not os.path.exists(program_keypair):
        run(["solana-keygen", "new", "-o", program_keypair, "--no-passphrase"])
    
    result = run(["solana-keygen", "pubkey", program_keypair])
    program_id = result.stdout.strip()
    print(f"  Program ID: {program_id}")
    
    # Step 3: Fix declare_id! with Python regex
    print("\n[3/6] Updating declare_id!...")
    with open(lib_rs_path, 'r') as f:
        content = f.read()
    
    new_content = re.sub(
        r'declare_id!\("[^"]+"\);',
        f'declare_id!("{program_id}");',
        content
    )
    
    with open(lib_rs_path, 'w') as f:
        f.write(new_content)
    
    with open(lib_rs_path, 'r') as f:
        verify = f.read()
    if program_id in verify:
        print(f"  ✅ declare_id! updated")
    else:
        print(f"  ❌ Failed to update declare_id!")
        sys.exit(1)
    
    # Step 4: Build
    print("\n[4/6] Building with cargo build-sbf...")
    os.chdir("/tmp/solana_validator/programs/vulnerable_bank")
    result = run("cargo build-sbf", shell=True, capture=False, check=False)
    if result.returncode != 0:
        print("  ❌ Build failed")
        sys.exit(1)
    print("  ✅ Build successful")
    
    # Step 5: Check .so
    so_path = "/tmp/solana_validator/programs/vulnerable_bank/target/deploy/vulnerable_bank.so"
    if not os.path.exists(so_path):
        alt_path = "/tmp/solana_validator/programs/vulnerable_bank/target/sbf-solana-solana/release/vulnerable_bank.so"
        if os.path.exists(alt_path):
            so_path = alt_path
        else:
            print(f"  ❌ .so file not found")
            sys.exit(1)
    
    size = os.path.getsize(so_path)
    print(f"  ✅ .so file: {size:,} bytes")
    
    # Step 6: Deploy
    print("\n[5/6] Deploying to devnet...")
    result = run([
        "solana", "program", "deploy",
        "--program-id", program_keypair,
        so_path
    ], capture=False, check=False)
    
    if result.returncode != 0:
        print("  ❌ Deployment failed")
        sys.exit(1)
    print("  ✅ Deployment successful")
    
    # Step 7: Verify
    print("\n[6/6] Verifying on devnet...")
    result = run(["solana", "program", "show", program_id], check=False)
    if result.returncode == 0:
        print("  ✅ Program verified")
    
    print("\n" + "=" * 60)
    print("DEPLOYMENT COMPLETE")
    print("=" * 60)
    print(f"\nProgram ID: {program_id}")
    print(f"Explorer:   https://explorer.solana.com/address/{program_id}?cluster=devnet")
    print(f"\nTest: python3 test_devnet.py {program_id} devnet")
    print("=" * 60)

if __name__ == "__main__":
    main()
